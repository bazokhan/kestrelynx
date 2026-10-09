package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// analysisBase identifies the scan settings KestreLynx itself fixes: an image
// scan with Trivy's default scanners and package types, no unfixed filtering
// and the full package list requested. A change to the scan arguments that
// alters what is reported must change this value. analysisID extends it with
// the inputs Trivy reads from its environment and working directory.
const analysisBase = "image;scanners=default;pkg-types=default;ignore-unfixed=false;list-all-pkgs=true"

// configFiles are the files Trivy reads from its working directory that
// change what it reports.
var configFiles = []string{"trivy.yaml", ".trivyignore", ".trivyignore.yaml"}

// maxVersionOutput bounds how much of `trivy version` output is read.
const maxVersionOutput = 1 << 20

// DBInfo identifies one vulnerability database. Version is the schema
// version and does not by itself identify the content; UpdatedAt, the time
// the database was built, does.
type DBInfo struct {
	Version   int
	UpdatedAt time.Time
}

// Known reports whether d carries an actual database identity.
func (d DBInfo) Known() bool { return d.Version != 0 && !d.UpdatedAt.IsZero() }

func (d DBInfo) equal(o DBInfo) bool {
	return d.Version == o.Version && d.UpdatedAt.Equal(o.UpdatedAt)
}

// ScanConditions identifies the conditions that decide what a scan reports,
// so two scans can be compared only when these match. It deliberately holds
// nothing about the scan run itself (times, target, how the image was
// fetched).
type ScanConditions struct {
	TrivyVersion    string
	VulnerabilityDB DBInfo
	JavaDB          DBInfo
	// Severities is sorted, upper-case and free of duplicates.
	Severities []string
	// AnalysisSettings identifies the effective scan settings other than the
	// databases and severities: KestreLynx's own flags, a digest of the TRIVY_*
	// environment (names and values are hashed, never kept) and the content of
	// the config and ignore files in the directory Trivy runs in.
	AnalysisSettings string
	// Content hashes (hex SHA-256) of the two database files in the cache in
	// use and of the Trivy executable. The database metadata alone does not
	// identify content, so these are what makes two conditions the same.
	VulnerabilityDBSHA string
	JavaDBSHA          string
	TrivySHA           string
}

// Known reports whether every field is set; conditions that are not known
// never compare as equal to anything.
func (c ScanConditions) Known() bool {
	return c.TrivyVersion != "" && c.VulnerabilityDB.Known() && c.JavaDB.Known() &&
		len(c.Severities) > 0 && c.AnalysisSettings != "" &&
		c.VulnerabilityDBSHA != "" && c.JavaDBSHA != "" && c.TrivySHA != ""
}

// Equal reports whether c and o describe the same scan conditions. Unknown
// conditions are never equal.
func (c ScanConditions) Equal(o ScanConditions) bool {
	if !c.Known() || !o.Known() {
		return false
	}
	if c.TrivyVersion != o.TrivyVersion || c.AnalysisSettings != o.AnalysisSettings ||
		c.VulnerabilityDBSHA != o.VulnerabilityDBSHA || c.JavaDBSHA != o.JavaDBSHA || c.TrivySHA != o.TrivySHA ||
		!c.VulnerabilityDB.equal(o.VulnerabilityDB) || !c.JavaDB.equal(o.JavaDB) ||
		len(c.Severities) != len(o.Severities) {
		return false
	}
	for i := range c.Severities {
		if c.Severities[i] != o.Severities[i] {
			return false
		}
	}
	return true
}

// normalizeSeverities upper-cases, trims, de-duplicates and sorts severities,
// splitting comma-joined entries as --severity accepts them.
func normalizeSeverities(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range in {
		for _, s := range strings.Split(e, ",") {
			s = strings.ToUpper(strings.TrimSpace(s))
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// versionReport is the subset of `trivy version --format json` in use.
type versionReport struct {
	Version         string `json:"Version"`
	VulnerabilityDB *struct {
		Version   int       `json:"Version"`
		UpdatedAt time.Time `json:"UpdatedAt"`
	} `json:"VulnerabilityDB"`
	JavaDB *struct {
		Version   int       `json:"Version"`
		UpdatedAt time.Time `json:"UpdatedAt"`
	} `json:"JavaDB"`
}

// parseVersionReport converts `trivy version --format json` output into the
// conditions it determines (version and database identities). A missing
// database stays the zero DBInfo.
func parseVersionReport(data []byte) (ScanConditions, error) {
	var r versionReport
	if err := json.Unmarshal(data, &r); err != nil {
		return ScanConditions{}, fmt.Errorf("parse trivy version: %w", err)
	}
	c := ScanConditions{TrivyVersion: r.Version}
	if r.VulnerabilityDB != nil {
		c.VulnerabilityDB = DBInfo{Version: r.VulnerabilityDB.Version, UpdatedAt: r.VulnerabilityDB.UpdatedAt}
	}
	if r.JavaDB != nil {
		c.JavaDB = DBInfo{Version: r.JavaDB.Version, UpdatedAt: r.JavaDB.UpdatedAt}
	}
	return c, nil
}

// run executes trivy with args and returns its stdout.
func (t Trivy) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, t.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: maxVersionOutput}
	cmd.Stderr = &limitedWriter{w: &stderr, n: 64 << 10}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// limitedWriter discards writes beyond n bytes while reporting them written,
// so a chatty child cannot grow the buffer without bound or block on a pipe.
type limitedWriter struct {
	w *bytes.Buffer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if room := l.n - l.w.Len(); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		l.w.Write(p[:room])
	}
	return len(p), nil
}

func (t Trivy) cacheArgs() []string {
	if t.CacheDir == "" {
		return nil
	}
	return []string{"--cache-dir", t.CacheDir}
}

// currentVersion reads `trivy version --format json`.
func (t Trivy) currentVersion(ctx context.Context) (ScanConditions, error) {
	args := append([]string{"version", "--format", "json"}, t.cacheArgs()...)
	out, err := t.run(ctx, args...)
	if err != nil {
		return ScanConditions{}, err
	}
	return parseVersionReport(out)
}

// resolved returns a copy of t with BinPath and CacheDir made absolute, for
// use by every operation that runs trivy away from the process's working
// directory. The cache directory follows Trivy's own order: CacheDir, then
// TRIVY_CACHE_DIR, then the user cache directory's "trivy". BinPath is
// looked up on PATH when it has no separator, and is otherwise taken
// relative to the current directory.
func (t Trivy) resolved() (Trivy, error) {
	cache := t.CacheDir
	if cache == "" {
		cache = os.Getenv("TRIVY_CACHE_DIR")
	}
	if cache == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return Trivy{}, fmt.Errorf("locate trivy cache: %w", err)
		}
		cache = filepath.Join(base, "trivy")
	}
	cache, err := filepath.Abs(cache)
	if err != nil {
		return Trivy{}, fmt.Errorf("resolve cache dir: %w", err)
	}
	bin := t.bin()
	if !strings.ContainsRune(bin, filepath.Separator) {
		if bin, err = exec.LookPath(bin); err != nil {
			return Trivy{}, fmt.Errorf("locate trivy: %w", err)
		}
	}
	if bin, err = filepath.Abs(bin); err != nil {
		return Trivy{}, fmt.Errorf("resolve trivy path: %w", err)
	}
	t.CacheDir, t.BinPath = cache, bin
	return t, nil
}

// withoutTrivyEnv returns env minus every TRIVY_* variable.
func withoutTrivyEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, "TRIVY_") {
			out = append(out, e)
		}
	}
	return out
}

// hashFile returns the hex SHA-256 of a file, streaming it so multi-gigabyte
// databases are never held in memory.
func hashFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := f.Read(buf)
		h.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// analysisID builds ScanConditions.AnalysisSettings for the way t runs Trivy.
// When SkipDBUpdate is set scans run in an empty private directory with every
// TRIVY_* variable removed from the environment, so no config, ignore or VEX
// setting from outside can apply; otherwise the TRIVY_* environment and the
// config files in the current directory are hashed.
func (t Trivy) analysisID() (string, error) {
	if t.SkipDBUpdate {
		return analysisBase + ";env=sanitized;workdir=isolated", nil
	}
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "TRIVY_") {
			env = append(env, e)
		}
	}
	sort.Strings(env)
	envSum := sha256.Sum256([]byte(strings.Join(env, "\x00")))

	var parts []string
	for _, name := range configFiles {
		data, err := os.ReadFile(name)
		switch {
		case errors.Is(err, os.ErrNotExist):
			parts = append(parts, name+"=absent")
		case err != nil:
			return "", fmt.Errorf("read %s: %w", name, err)
		default:
			sum := sha256.Sum256(data)
			parts = append(parts, name+"="+hex.EncodeToString(sum[:]))
		}
	}
	return fmt.Sprintf("%s;env=%s;workdir=cwd:%s", analysisBase, hex.EncodeToString(envSum[:]), strings.Join(parts, ",")), nil
}

// fillIdentity completes c with the content identities and analysis settings
// as they are now.
//
// t must already be resolved.
func (t Trivy) fillIdentity(ctx context.Context, c *ScanConditions) error {
	root := t.CacheDir
	var err error
	if c.VulnerabilityDBSHA, err = hashFile(ctx, filepath.Join(root, "db", "trivy.db")); err != nil {
		return fmt.Errorf("hash vulnerability db: %w", err)
	}
	if c.JavaDBSHA, err = hashFile(ctx, filepath.Join(root, "java-db", "trivy-java.db")); err != nil {
		return fmt.Errorf("hash java db: %w", err)
	}
	if c.TrivySHA, err = hashFile(ctx, t.BinPath); err != nil {
		return fmt.Errorf("hash trivy executable: %w", err)
	}
	if c.AnalysisSettings, err = t.analysisID(); err != nil {
		return err
	}
	return nil
}

// current reads the Trivy version and database identities and hashes the
// database files, the executable and the analysis inputs. Severities are left
// empty.
// t must already be resolved.
func (t Trivy) current(ctx context.Context) (ScanConditions, error) {
	c, err := t.currentVersion(ctx)
	if err != nil {
		return ScanConditions{}, err
	}
	if err := t.fillIdentity(ctx, &c); err != nil {
		return ScanConditions{}, err
	}
	return c, nil
}

// PrepareDB downloads the vulnerability and Java databases into the cache
// without scanning, then records which Trivy and which database content are
// now current. The returned conditions carry the version, database
// identities and content hashes, this Trivy's severities and the analysis
// settings. It fails when either database is missing afterwards, since scans
// that skip updates need both.
func (t Trivy) PrepareDB(ctx context.Context) (ScanConditions, error) {
	t, err := t.resolved()
	if err != nil {
		return ScanConditions{}, err
	}
	cache := t.cacheArgs()
	for _, flag := range []string{"--download-db-only", "--download-java-db-only"} {
		args := append([]string{"image", "--quiet", flag}, cache...)
		if _, err := t.run(ctx, args...); err != nil {
			return ScanConditions{}, err
		}
	}
	c, err := t.current(ctx)
	if err != nil {
		return ScanConditions{}, err
	}
	if !c.VulnerabilityDB.Known() || !c.JavaDB.Known() || c.TrivyVersion == "" {
		return ScanConditions{}, fmt.Errorf("trivy version reports no complete database identity after download")
	}
	c.Severities = normalizeSeverities(strings.Split(t.severity(), ","))
	return c, nil
}

// VerifyDB re-reads everything PrepareDB recorded (version, database
// identities and file contents, the executable, the analysis inputs) and
// reports whether it still equals base, i.e. nothing changed since
// PrepareDB. An error means the check could not be made.
func (t Trivy) VerifyDB(ctx context.Context, base ScanConditions) (bool, error) {
	t, err := t.resolved()
	if err != nil {
		return false, err
	}
	now, err := t.current(ctx)
	if err != nil {
		return false, err
	}
	now.Severities = base.Severities
	return now.Equal(base), nil
}
