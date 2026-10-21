package worker

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

var testBinding = SealBinding{Instance: "inst1", Session: "sess1", Job: "job1", Attempt: 1, PodUID: "0f0f0f0f-1111-2222-3333-444444444444"}

const testMaxTar = 1 << 20

func sealTestFrame(t *testing.T, key *SealKey, b SealBinding, tarBytes []byte, status ...[2]string) []byte {
	t.Helper()
	file, err := SealFileBytes(key.PublicKey(), b)
	if err != nil {
		t.Fatal(err)
	}
	pub, got, err := ParseSealFile(file)
	if err != nil || got != b {
		t.Fatalf("seal file: %v %+v", err, got)
	}
	frame, err := SealFrame(pub, b, tarBytes, status...)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func openTest(log []byte, key *SealKey, b SealBinding) ([]byte, error) {
	return OpenSealed(log, SealedLogLimit(testMaxTar), key, b, testMaxTar)
}

func TestSealedRoundTrip(t *testing.T) {
	key, err := NewSealKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte("result bytes "), 5000)
	frame := sealTestFrame(t, key, testBinding, plain, [2]string{"job", "completed"})
	got, err := openTest(frame, key, testBinding)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %v (%d bytes)", err, len(got))
	}
	if strings.Contains(string(frame), "result bytes") {
		t.Error("the frame holds the plain text")
	}
	for _, l := range strings.Split(strings.TrimSuffix(string(frame), "\n"), "\n") {
		if len(l) > 76 && !strings.HasPrefix(l, SealedStart) {
			t.Errorf("a line of %d characters", len(l))
		}
	}
}

func TestSealedIsBoundToTheAttempt(t *testing.T) {
	key, _ := NewSealKey()
	other, _ := NewSealKey()
	frame := sealTestFrame(t, key, testBinding, []byte("tar"))
	for name, mutate := range map[string]func(b *SealBinding){
		"instance": func(b *SealBinding) { b.Instance = "inst2" },
		"session":  func(b *SealBinding) { b.Session = "sess2" },
		"job":      func(b *SealBinding) { b.Job = "job2" },
		"attempt":  func(b *SealBinding) { b.Attempt = 2 },
		"pod uid":  func(b *SealBinding) { b.PodUID = "aaaaaaaa-1111-2222-3333-444444444444" },
	} {
		b := testBinding
		mutate(&b)
		if _, err := openTest(frame, key, b); err == nil {
			t.Errorf("a frame of another %s opened", name)
		}
	}
	if _, err := openTest(frame, other, testBinding); err == nil {
		t.Error("a frame opened with another key")
	}
	// A result sealed for an earlier attempt (same job, same Pod name, another
	// attempt's key) is not taken.
	oldKey, _ := NewSealKey()
	old := testBinding
	old.Attempt = 1
	oldFrame := sealTestFrame(t, oldKey, old, []byte("old tar"))
	next := testBinding
	next.Attempt = 2
	if _, err := openTest(oldFrame, key, next); err == nil {
		t.Error("the result of an earlier attempt opened")
	}
}

func TestSealedFramingRefusals(t *testing.T) {
	key, _ := NewSealKey()
	frame := sealTestFrame(t, key, testBinding, bytes.Repeat([]byte("x"), 400))
	lines := strings.Split(strings.TrimSuffix(string(frame), "\n"), "\n")
	join := func(ls ...string) []byte { return []byte(strings.Join(ls, "\n") + "\n") }
	cases := map[string][]byte{
		"empty":                  nil,
		"plain result block":     ResultBlockOfTar([]byte("tar")),
		"no last newline":        bytes.TrimSuffix(frame, []byte("\n")),
		"start lost to rotation": join(lines[1:]...),
		"end missing":            join(lines[:len(lines)-1]...),
		"two frames":             append(append([]byte{}, frame...), frame...),
		"line outside the frame": join(append([]string{"hello"}, lines...)...),
		"line after the frame":   join(append(append([]string{}, lines...), "trailing")...),
		"body line too long":     join(append([]string{lines[0], lines[1] + "AAAA"}, lines[2:]...)...),
		"body line removed":      join(append(append([]string{}, lines[:2]...), lines[3:]...)...),
		"wrong job in the start": []byte(strings.Replace(string(frame), "job1", "job2", 1)),
		"wrong length":           []byte(strings.Replace(string(frame), lines[0], strings.TrimSuffix(lines[0], lines[0][strings.LastIndex(lines[0], " ")+1:])+"999", 1)),
		"unknown version":        []byte(strings.Replace(string(frame), SealedStart+" 1", SealedStart+" 2", 1)),
		"malformed status":       append([]byte(StatusPrefix+" Bad CODE\n"), frame...),
		"status with free text":  append([]byte(StatusPrefix+" job x y\n"), frame...),
		"tampered ciphertext":    tamper(frame),
		"only the end line":      []byte(SealedEnd + "\n"),
		"frame end before start": join(SealedEnd, lines[0]),
	}
	for name, log := range cases {
		if _, err := openTest(log, key, testBinding); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	// The status lines around the frame are fine, up to a number.
	ok := append([]byte(StatusPrefix+" start ok\n"), frame...)
	ok = append(ok, []byte(StatusPrefix+" end ok\n")...)
	if _, err := openTest(ok, key, testBinding); err != nil {
		t.Errorf("status lines around the frame: %v", err)
	}
	var many []byte
	for i := 0; i < maxStatusLines+1; i++ {
		many = append(many, []byte(StatusPrefix+" job ok\n")...)
	}
	if _, err := openTest(append(many, frame...), key, testBinding); err == nil {
		t.Error("too many status lines opened")
	}
}

func tamper(frame []byte) []byte {
	out := append([]byte{}, frame...)
	nl := bytes.IndexByte(out, '\n')
	// Flip a base64 character of the first body line (a legal, other character).
	if out[nl+5] == 'A' {
		out[nl+5] = 'B'
	} else {
		out[nl+5] = 'A'
	}
	return out
}

// The limit is the largest frame there is; a log over it is refused whatever
// it holds, so a second frame hidden past a legal one is never read.
func TestSealedLogLimit(t *testing.T) {
	key, _ := NewSealKey()
	limit := SealedLogLimit(testMaxTar)
	// The largest legal result fits.
	frame := sealTestFrame(t, key, testBinding, bytes.Repeat([]byte{0xAB}, testMaxTar), [2]string{"job", "completed"})
	if int64(len(frame)) > limit {
		t.Fatalf("the frame of the largest result (%d bytes) is over the limit %d", len(frame), limit)
	}
	if _, err := openTest(frame, key, testBinding); err != nil {
		t.Fatalf("the largest result: %v", err)
	}
	// One byte more than the limit is refused, even when what is added is a
	// legal status line after a good frame.
	small := sealTestFrame(t, key, testBinding, []byte("tar"))
	pad := bytes.Repeat([]byte(StatusPrefix+" job ok\n"), 1)
	hidden := append(append([]byte{}, small...), bytes.Repeat([]byte("x"), int(limit))...)
	if _, err := OpenSealed(hidden, limit, key, testBinding, testMaxTar); !errors.Is(err, ErrSealedLogTooLong) {
		t.Errorf("a log over the limit: %v", err)
	}
	_ = pad
	// A result tar over the limit cannot be announced.
	big := strings.Replace(string(small), " 1 job1 ", " 1 job1 99", 1)
	if _, err := openTest([]byte(big), key, testBinding); err == nil {
		t.Error("an over-long announced length opened")
	}
}

func TestSealFileIsStrict(t *testing.T) {
	key, _ := NewSealKey()
	good, _ := SealFileBytes(key.PublicKey(), testBinding)
	if _, _, err := ParseSealFile(good); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"empty":         nil,
		"unknown field": bytes.Replace(good, []byte(`"v":1`), []byte(`"v":1,"x":2`), 1),
		"trailing":      append(append([]byte{}, good...), []byte("{}")...),
		"bad key":       bytes.Replace(good, []byte(`"public_key":"`), []byte(`"public_key":"AA`), 1),
		"bad version":   bytes.Replace(good, []byte(`"v":1`), []byte(`"v":2`), 1),
		"zero attempt":  bytes.Replace(good, []byte(`"attempt":1`), []byte(`"attempt":0`), 1),
		"bad uid":       bytes.Replace(good, []byte(testBinding.PodUID[:8]), []byte("Z!"), 1),
	} {
		if _, _, err := ParseSealFile(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestResultBlockOfTarIsWhatDecodeResultReads(t *testing.T) {
	tarBytes, err := EncodeResultTar(map[string][]byte{"result.json": []byte("{}\n"), "final/a": []byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	files, err := DecodeResult(ResultBlockOfTar(tarBytes), DefaultResultLimits())
	if err != nil || string(files["final/a"]) != "a" {
		t.Fatalf("decode: %v %v", err, files)
	}
	plain, _ := EncodeResult(map[string][]byte{"result.json": []byte("{}\n"), "final/a": []byte("a")})
	if !bytes.Equal(plain, ResultBlockOfTar(tarBytes)) {
		t.Error("the plain block changed")
	}
}

func TestSealedLogSizesForTheLargestResult(t *testing.T) {
	max := DefaultResultLimits().MaxTarBytes
	api, node := SealedLogLimit(max), SealedLogNodeBytes(max)
	// The API serves about 94.56 MiB, and the node stores the same lines with a
	// 40-byte prefix each, about 143.69 MiB.
	if api < 94<<20 || api > 95<<20 {
		t.Errorf("API limit = %d", api)
	}
	if node < 143<<20 || node > 144<<20 {
		t.Errorf("node bytes = %d", node)
	}
	// A log of that many lines, each with the prefix, is what the node holds.
	lines := (api-int64(0))/77 + 1
	if node-api < lines*30 {
		t.Errorf("the node's prefix bytes %d are too few for about %d lines", node-api, lines)
	}
	if criLinePrefixBytes != 40 {
		t.Errorf("CRI line prefix = %d", criLinePrefixBytes)
	}
}
