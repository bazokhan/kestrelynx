package toolfetch

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	indexName     = "index.json"
	indexVersion  = 1
	maxIndexBytes = 4 << 20
	staleTmp      = time.Hour
)

// part is one file in the cache. Its content is stored under its SHA-256.
type part struct {
	Name      string `json:"name"` // the package or file
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	SHA512    string `json:"sha512"`
	Integrity string `json:"integrity"` // the registry digest it was checked against, "<algo>-<hex>"
}

// entry is what the cache knows of one tool version for a platform: the
// files and what the registry said about them when they were fetched.
type entry struct {
	Manager     Manager   `json:"manager"`
	Version     string    `json:"version"`
	Platform    string    `json:"platform"`
	Main        part      `json:"main"`
	Wrapper     *part     `json:"wrapper,omitempty"`
	PublishedAt time.Time `json:"published_at"` // the latest of the files'
	Engines     []string  `json:"engines,omitempty"`
	LastUsed    time.Time `json:"last_used"`
}

type indexFile struct {
	Version int               `json:"version"`
	Entries map[string]*entry `json:"entries"`
}

// cache is the content-addressed store under <storage_dir>/tools.
type cache struct {
	dir string
	max int64
	now func() time.Time

	mu      sync.Mutex
	idx     indexFile
	holds   map[string]time.Time // blob SHA-256 -> when the hold ends
	holdTTL time.Duration
}

func openCache(dir string, max int64, now func() time.Time, holdTTL time.Duration) (*cache, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	c := &cache{dir: abs, max: max, now: now, holds: map[string]time.Time{}, holdTTL: holdTTL}
	for _, d := range []string{c.dir, c.blobDir(), c.tmpDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return nil, err
		}
	}
	// Nothing else uses the directory when it is opened, so a download that
	// was cut short has left only debris.
	if ents, err := os.ReadDir(c.tmpDir()); err == nil {
		for _, e := range ents {
			os.Remove(filepath.Join(c.tmpDir(), e.Name()))
		}
	}
	c.idx = c.readIndex()
	return c, nil
}

func (c *cache) blobDir() string { return filepath.Join(c.dir, "blobs") }
func (c *cache) tmpDir() string  { return filepath.Join(c.dir, "tmp") }

func (c *cache) blobPath(sha string) string { return filepath.Join(c.blobDir(), sha) }

// readIndex reads the index; one that is missing, too large or unreadable is
// an empty one, and the blobs it no longer names are cleared when room is
// needed.
func (c *cache) readIndex() indexFile {
	empty := indexFile{Version: indexVersion, Entries: map[string]*entry{}}
	f, err := os.Open(filepath.Join(c.dir, indexName))
	if err != nil {
		return empty
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxIndexBytes+1))
	if err != nil || len(data) > maxIndexBytes {
		return empty
	}
	var idx indexFile
	if json.Unmarshal(data, &idx) != nil || idx.Version != indexVersion || idx.Entries == nil {
		return empty
	}
	for k, e := range idx.Entries {
		if e == nil || !validPart(e.Main) || (e.Wrapper != nil && !validPart(*e.Wrapper)) {
			delete(idx.Entries, k)
		}
	}
	return idx
}

func validPart(p part) bool {
	return isHex(p.SHA256, 64) && isHex(p.SHA512, 128) && p.Size >= 0
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// saveIndex writes the index by replacing the file. mu is held.
func (c *cache) saveIndex() error {
	data, err := json.Marshal(c.idx)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.tmpDir(), "index-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(c.dir, indexName)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// usage is the bytes of every file under the cache directory: blobs the
// index names, blobs it does not, temporary files and the index itself.
func (c *cache) usage() int64 {
	var total int64
	filepath.WalkDir(c.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// lookup returns a copy of the entry for key.
func (c *cache) lookup(key string) (entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.idx.Entries[key]
	if !ok {
		return entry{}, false
	}
	return *e, true
}

// drop forgets the entry for key. The blobs it named stay until room is
// needed.
func (c *cache) drop(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.idx.Entries[key]; ok {
		delete(c.idx.Entries, key)
		c.saveIndex()
	}
}

// store records the entry and writes the index.
func (c *cache) store(key string, e entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.LastUsed = c.now()
	c.idx.Entries[key] = &e
	return c.saveIndex()
}

// touch marks the entry used now and holds its main blob.
func (c *cache) touch(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.idx.Entries[key]; ok {
		e.LastUsed = c.now()
		c.saveIndex()
	}
}

// hold keeps a blob from being evicted for the hold period.
func (c *cache) hold(sha string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.holds[sha] = c.now().Add(c.holdTTL)
}

// release ends the hold on a blob.
func (c *cache) release(sha string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.holds, sha)
}

func (c *cache) heldLocked(sha string) bool {
	until, ok := c.holds[sha]
	if !ok {
		return false
	}
	if !c.now().Before(until) {
		delete(c.holds, sha)
		return false
	}
	return true
}

// makeRoom evicts until need more bytes fit within the capacity. Orphaned
// blobs and stale temporary files go first, then entries, least recently
// used first; a blob in use, or one in keep, is never evicted. It reports
// whether the room exists.
func (c *cache) makeRoom(need int64, keep map[string]bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if need > c.max {
		return false
	}
	used := c.usage()
	if used+need <= c.max {
		return true
	}
	referenced := map[string]bool{}
	for _, e := range c.idx.Entries {
		referenced[e.Main.SHA256] = true
		if e.Wrapper != nil {
			referenced[e.Wrapper.SHA256] = true
		}
	}
	remove := func(p string) {
		if info, err := os.Lstat(p); err == nil && os.Remove(p) == nil {
			used -= info.Size()
		}
	}
	// Orphaned blobs.
	if ents, err := os.ReadDir(c.blobDir()); err == nil {
		for _, de := range ents {
			if !referenced[de.Name()] && !keep[de.Name()] && !c.heldLocked(de.Name()) {
				remove(filepath.Join(c.blobDir(), de.Name()))
			}
		}
	}
	// Temporary files that a finished or abandoned download left.
	if ents, err := os.ReadDir(c.tmpDir()); err == nil {
		for _, de := range ents {
			if info, err := de.Info(); err == nil && c.now().Sub(info.ModTime()) > staleTmp {
				remove(filepath.Join(c.tmpDir(), de.Name()))
			}
		}
	}
	if used+need <= c.max {
		return true
	}
	keys := make([]string, 0, len(c.idx.Entries))
	for k := range c.idx.Entries {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := c.idx.Entries[keys[i]], c.idx.Entries[keys[j]]
		if !a.LastUsed.Equal(b.LastUsed) {
			return a.LastUsed.Before(b.LastUsed)
		}
		return keys[i] < keys[j]
	})
	changed := false
	for _, k := range keys {
		if used+need <= c.max {
			break
		}
		e := c.idx.Entries[k]
		blobs := []string{e.Main.SHA256}
		if e.Wrapper != nil {
			blobs = append(blobs, e.Wrapper.SHA256)
		}
		busy := false
		for _, b := range blobs {
			busy = busy || keep[b] || c.heldLocked(b)
		}
		if busy {
			continue
		}
		delete(c.idx.Entries, k)
		changed = true
		for _, b := range blobs {
			// A blob another entry names stays.
			shared := false
			for _, o := range c.idx.Entries {
				if o.Main.SHA256 == b || (o.Wrapper != nil && o.Wrapper.SHA256 == b) {
					shared = true
				}
			}
			if !shared {
				remove(c.blobPath(b))
			}
		}
	}
	if changed {
		c.saveIndex()
		used = c.usage()
	}
	return used+need <= c.max
}

// verify reads the blob of a part and checks it against what the index
// records. It also hashes under the algorithm of a declared hash when algo
// is given, and returns that digest.
func (c *cache) verify(p part, algo string) (spec string, err error) {
	name := c.blobPath(p.SHA256)
	info, err := os.Lstat(name)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("the cached file is not a regular file")
	}
	if info.Size() != p.Size {
		return "", fmt.Errorf("the cached file has %d bytes, not %d", info.Size(), p.Size)
	}
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h256, h512 := sha256.New(), sha512.New()
	ws := []io.Writer{h256, h512}
	var hs interface {
		io.Writer
		Sum([]byte) []byte
	}
	if algo != "" {
		hs = newHash(algo)
		ws = append(ws, hs)
	}
	if _, err := io.Copy(io.MultiWriter(ws...), f); err != nil {
		return "", err
	}
	if hex.EncodeToString(h256.Sum(nil)) != p.SHA256 || hex.EncodeToString(h512.Sum(nil)) != p.SHA512 {
		return "", errors.New("the cached file does not match its recorded hashes")
	}
	if hs != nil {
		spec = hex.EncodeToString(hs.Sum(nil))
	}
	return spec, nil
}

// place moves a finished download into the blob store.
func (c *cache) place(tmpFile, sha string) error {
	dst := c.blobPath(sha)
	if err := os.Chmod(tmpFile, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpFile, dst)
}

// newTmp reserves a name for a download.
func (c *cache) newTmp() (string, error) {
	f, err := os.CreateTemp(c.tmpDir(), "dl-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	f.Close()
	// The download creates the file itself, exclusively.
	os.Remove(name)
	return name, nil
}
