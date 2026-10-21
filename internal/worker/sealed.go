package worker

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// In a Pod the standard output of the work container is its log, which the
// node's log collection and anyone with access to the log can read, and which
// outlives the Pod. The program there therefore does not print the result
// block; it seals the result's tar for the main process and prints only the
// sealed frame:
//
//	KESTRELYNX-SEALED <version> <job id> <length>\n
//	<the sealed bytes in standard base64, 76 characters per line>\n
//	KESTRELYNX-SEALED-END\n
//
// The sealed bytes are the encapsulated key (32 bytes) followed by the
// ciphertext. The suite is fixed: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
// ChaCha20-Poly1305. The main process makes a new key pair for every attempt
// (every Pod it creates) and sends the public key in the Pod's input; the
// private key stays in its memory. The context information and the associated
// data both name the attempt (instance, session, job, attempt number and the
// UID of the Pod), so a result of another attempt, another start of the main
// process or another Pod does not open. The seal gives confidentiality and
// integrity and ties the result to the attempt; it does not prove who made it,
// since the public key is in the Pod. Outside the frame only status lines may
// appear:
//
//	KESTRELYNX-STATUS <stage> <code>\n
//
// where the stage and the code are words from a fixed set, never text.
const (
	SealedStart  = "KESTRELYNX-SEALED"
	SealedEnd    = "KESTRELYNX-SEALED-END"
	StatusPrefix = "KESTRELYNX-STATUS"

	// SealedVersion is the version of the frame and of the binding.
	SealedVersion = 1
	// SealFile is the input file (in /work) that carries the attempt's public
	// key and binding.
	SealFile = "/work/seal.json"
	// SealInputName is SealFile relative to /work, as an input file.
	SealInputName = "seal.json"

	sealedKEMEncBytes  = 32 // an X25519 encapsulated key
	sealedTagBytes     = 16 // the Poly1305 tag
	sealedLineWidth    = resultLineWidth
	maxSealFileBytes   = 4096
	maxStatusLines     = 8
	maxStatusLineBytes = 64
)

// SealBinding names the attempt a result belongs to.
type SealBinding struct {
	Instance string
	Session  string
	Job      string
	Attempt  uint32
	PodUID   string
}

var (
	sealWord   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	sealUIDRE  = regexp.MustCompile(`^[0-9a-f-]{8,64}$`)
	statusWord = regexp.MustCompile(`^[a-z][a-z0-9_]{0,23}$`)
)

// Valid reports whether every part of the binding has the shape it is allowed.
func (b SealBinding) Valid() error {
	for name, v := range map[string]string{"instance": b.Instance, "session": b.Session, "job": b.Job} {
		if !sealWord.MatchString(v) {
			return fmt.Errorf("the %s of the seal binding is malformed", name)
		}
	}
	if b.Attempt == 0 {
		return errors.New("the attempt of the seal binding is zero")
	}
	if !sealUIDRE.MatchString(b.PodUID) {
		return errors.New("the pod UID of the seal binding is malformed")
	}
	return nil
}

// canonical is the length-prefixed encoding of the binding under a label, so
// that the context information and the associated data differ.
func (b SealBinding) canonical(label string) []byte {
	var out []byte
	put := func(s string) {
		out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
		out = append(out, s...)
	}
	put("kestrelynx/" + label)
	out = binary.BigEndian.AppendUint32(out, SealedVersion)
	put(b.Instance)
	put(b.Session)
	put(b.Job)
	out = binary.BigEndian.AppendUint32(out, b.Attempt)
	put(b.PodUID)
	return out
}

func (b SealBinding) info() []byte { return b.canonical("info") }
func (b SealBinding) aad() []byte  { return b.canonical("aad") }

func sealSuite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305()
}

// SealKey is the private half of an attempt's key pair, kept in the memory of
// the main process.
type SealKey struct {
	priv hpke.PrivateKey
	pub  []byte
}

// NewSealKey makes a key pair for one attempt.
func NewSealKey() (*SealKey, error) {
	kem, _, _ := sealSuite()
	priv, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &SealKey{priv: priv, pub: priv.PublicKey().Bytes()}, nil
}

// PublicKey is the public key to send into the Pod.
func (k *SealKey) PublicKey() []byte { return append([]byte(nil), k.pub...) }

// SealFileContent is the content of seal.json for an attempt.
type SealFileContent struct {
	Version   int    `json:"v"`
	PublicKey string `json:"public_key"` // standard base64
	Instance  string `json:"instance"`
	Session   string `json:"session"`
	Job       string `json:"job"`
	Attempt   uint32 `json:"attempt"`
	PodUID    string `json:"pod_uid"`
}

// SealFileBytes encodes seal.json.
func SealFileBytes(pub []byte, b SealBinding) ([]byte, error) {
	if err := b.Valid(); err != nil {
		return nil, err
	}
	return json.Marshal(SealFileContent{
		Version: SealedVersion, PublicKey: base64.StdEncoding.EncodeToString(pub),
		Instance: b.Instance, Session: b.Session, Job: b.Job, Attempt: b.Attempt, PodUID: b.PodUID,
	})
}

// ParseSealFile strictly decodes seal.json into the public key and binding.
func ParseSealFile(data []byte) (hpke.PublicKey, SealBinding, error) {
	if len(data) == 0 || len(data) > maxSealFileBytes {
		return nil, SealBinding{}, errors.New("the seal file has a bad size")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c SealFileContent
	if err := dec.Decode(&c); err != nil {
		return nil, SealBinding{}, fmt.Errorf("the seal file is malformed: %w", err)
	}
	if dec.More() {
		return nil, SealBinding{}, errors.New("the seal file has trailing data")
	}
	if c.Version != SealedVersion {
		return nil, SealBinding{}, errors.New("the seal file has an unknown version")
	}
	b := SealBinding{Instance: c.Instance, Session: c.Session, Job: c.Job, Attempt: c.Attempt, PodUID: c.PodUID}
	if err := b.Valid(); err != nil {
		return nil, SealBinding{}, err
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(c.PublicKey)
	if err != nil || len(raw) != sealedKEMEncBytes {
		return nil, SealBinding{}, errors.New("the seal file's public key is malformed")
	}
	kem, _, _ := sealSuite()
	pub, err := kem.NewPublicKey(raw)
	if err != nil {
		return nil, SealBinding{}, errors.New("the seal file's public key is not usable")
	}
	return pub, b, nil
}

// SealFrame seals the result tar to the public key and returns the whole frame
// to print, with the status lines (each a stage and a code from the fixed
// word shapes) before it.
func SealFrame(pub hpke.PublicKey, b SealBinding, tarBytes []byte, status ...[2]string) ([]byte, error) {
	if err := b.Valid(); err != nil {
		return nil, err
	}
	_, kdf, aead := sealSuite()
	enc, sender, err := hpke.NewSender(pub, kdf, aead, b.info())
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	ct, err := sender.Seal(b.aad(), tarBytes)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	sealed := append(append([]byte(nil), enc...), ct...)
	var out bytes.Buffer
	for _, s := range status {
		line, err := StatusLine(s[0], s[1])
		if err != nil {
			return nil, err
		}
		out.WriteString(line)
	}
	fmt.Fprintf(&out, "%s %d %s %d\n", SealedStart, SealedVersion, b.Job, len(sealed))
	b64 := base64.StdEncoding.EncodeToString(sealed)
	for len(b64) > 0 {
		n := min(sealedLineWidth, len(b64))
		out.WriteString(b64[:n])
		out.WriteByte('\n')
		b64 = b64[n:]
	}
	out.WriteString(SealedEnd + "\n")
	return out.Bytes(), nil
}

// StatusLine formats a status line from a stage and a code, both words of the
// fixed shape.
func StatusLine(stage, code string) (string, error) {
	if !statusWord.MatchString(stage) || !statusWord.MatchString(code) {
		return "", errors.New("a status line takes only short lower-case words")
	}
	line := StatusPrefix + " " + stage + " " + code + "\n"
	if len(line) > maxStatusLineBytes {
		return "", errors.New("a status line is too long")
	}
	return line, nil
}

// SealedLogLimit is the most bytes a sealed log may hold: the frame of the
// largest result tar, the status lines and a margin. A log longer than this is
// refused whatever it holds, so a frame hidden past the limit is never read.
func SealedLogLimit(maxTarBytes int64) int64 {
	sealed := maxTarBytes + sealedKEMEncBytes + sealedTagBytes
	b64 := (sealed + 2) / 3 * 4
	lines := (b64 + sealedLineWidth - 1) / sealedLineWidth
	header := int64(len(SealedStart) + 1 + 3 + 1 + 64 + 1 + 20 + 1)
	return b64 + lines + header + int64(len(SealedEnd)+1) + maxStatusLines*maxStatusLineBytes
}

// criLinePrefixBytes is what the container runtime adds to the front of every
// line of a container log before it stores it: a UTC timestamp with
// nanoseconds (30 bytes), the stream name "stdout" (6), the partial/full tag
// (1) and the three spaces between them.
const criLinePrefixBytes = 30 + 1 + 6 + 1 + 1 + 1

// SealedLogNodeBytes is the room the node's container log needs for the
// largest sealed log: SealedLogLimit is what the API serves, while the node
// stores every line with its CRI prefix, and the kubelet rotates the log
// (dropping its beginning) when it grows past containerLogMaxSize. For the
// largest result it is about 1.5 times SealedLogLimit.
func SealedLogNodeBytes(maxTarBytes int64) int64 {
	sealed := maxTarBytes + sealedKEMEncBytes + sealedTagBytes
	b64 := (sealed + 2) / 3 * 4
	bodyLines := (b64 + sealedLineWidth - 1) / sealedLineWidth
	lines := bodyLines + 2 + maxStatusLines // frame start and end, status lines
	return SealedLogLimit(maxTarBytes) + lines*criLinePrefixBytes
}

// OpenSealed reads a log that is untrusted and returns the result tar. The log
// must hold exactly one frame, with only status lines around it, be no longer
// than limit, name the expected job, have the length it announces and open with
// the key under the binding. Anything else, a log that lost its beginning to
// rotation included, is an error.
func OpenSealed(log []byte, limit int64, key *SealKey, b SealBinding, maxTarBytes int64) ([]byte, error) {
	if int64(len(log)) > limit {
		return nil, ErrSealedLogTooLong
	}
	if err := b.Valid(); err != nil {
		return nil, err
	}
	if len(log) == 0 || log[len(log)-1] != '\n' {
		return nil, errors.New("the log has no complete last line")
	}
	lines := strings.Split(string(log[:len(log)-1]), "\n")
	var (
		startAt = -1
		endAt   = -1
		status  int
	)
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, SealedStart+" "):
			if startAt >= 0 {
				return nil, errors.New("the log holds more than one frame")
			}
			startAt = i
		case l == SealedEnd:
			if endAt >= 0 {
				return nil, errors.New("the log holds more than one frame end")
			}
			endAt = i
		case strings.HasPrefix(l, StatusPrefix+" "):
			f := strings.Split(l, " ")
			if len(f) != 3 || !statusWord.MatchString(f[1]) || !statusWord.MatchString(f[2]) || len(l)+1 > maxStatusLineBytes {
				return nil, errors.New("the log holds a malformed status line")
			}
			status++
			if status > maxStatusLines {
				return nil, errors.New("the log holds too many status lines")
			}
		case startAt >= 0 && endAt < 0:
			// a line of the body, checked below
		default:
			return nil, errors.New("the log holds a line outside the frame that is not a status line")
		}
	}
	if startAt < 0 {
		return nil, errors.New("the log has no frame start")
	}
	if endAt < 0 || endAt < startAt {
		return nil, errors.New("the log has no frame end")
	}
	f := strings.Split(lines[startAt], " ")
	if len(f) != 4 || f[0] != SealedStart || f[1] != strconv.Itoa(SealedVersion) || f[2] != b.Job {
		return nil, errors.New("the frame start does not name this job")
	}
	n, err := strconv.ParseInt(f[3], 10, 64)
	if err != nil || strconv.FormatInt(n, 10) != f[3] || n < sealedKEMEncBytes+sealedTagBytes || n > maxTarBytes+sealedKEMEncBytes+sealedTagBytes {
		return nil, errors.New("the frame length is invalid or over the limit")
	}
	body := lines[startAt+1 : endAt]
	wantB64 := (n + 2) / 3 * 4
	wantLines := (wantB64 + sealedLineWidth - 1) / sealedLineWidth
	if int64(len(body)) != wantLines {
		return nil, errors.New("the frame has the wrong number of lines")
	}
	var b64 strings.Builder
	for i, l := range body {
		if i < len(body)-1 && len(l) != sealedLineWidth || len(l) == 0 || len(l) > sealedLineWidth {
			return nil, errors.New("a frame line has the wrong width")
		}
		b64.WriteString(l)
	}
	if int64(b64.Len()) != wantB64 {
		return nil, errors.New("the frame body has the wrong size")
	}
	sealed, err := base64.StdEncoding.Strict().DecodeString(b64.String())
	if err != nil || int64(len(sealed)) != n {
		return nil, errors.New("the frame body is not valid base64 of the announced length")
	}
	_, kdf, aead := sealSuite()
	r, err := hpke.NewRecipient(sealed[:sealedKEMEncBytes], key.priv, kdf, aead, b.info())
	if err != nil {
		return nil, errors.New("the result does not open")
	}
	tarBytes, err := r.Open(b.aad(), sealed[sealedKEMEncBytes:])
	if err != nil {
		return nil, errors.New("the result does not open")
	}
	return tarBytes, nil
}

// ErrSealedLogTooLong reports a log over the limit.
var ErrSealedLogTooLong = errors.New("the log is longer than the largest sealed result")

// ResultBlockOfTar renders a result tar as the plain result block that
// DecodeResult reads, so that what is opened from a sealed frame goes through
// the same checks as a result read from a Docker container's output.
func ResultBlockOfTar(tarBytes []byte) []byte {
	sum := sha256.Sum256(tarBytes)
	b64 := base64.StdEncoding.EncodeToString(tarBytes)
	var out bytes.Buffer
	fmt.Fprintf(&out, "%s %d %d %s\n", ResultBlockStart, ProtocolVersion, len(tarBytes), hex.EncodeToString(sum[:]))
	for len(b64) > 0 {
		n := min(resultLineWidth, len(b64))
		out.WriteString(b64[:n])
		out.WriteByte('\n')
		b64 = b64[n:]
	}
	out.WriteString(ResultBlockEnd + "\n")
	return out.Bytes()
}
