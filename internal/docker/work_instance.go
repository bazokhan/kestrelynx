package docker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const instanceIDFile = "work-instance-id"

// LoadOrCreateInstanceID returns the persistent instance id stored in dir,
// creating it on first use. The file is created with mode 0600 through a
// temporary file and a hard link, so a concurrent first start cannot
// overwrite an id another process already created.
func LoadOrCreateInstanceID(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create instance id directory: %w", err)
	}
	final := filepath.Join(dir, instanceIDFile)
	if id, err := readInstanceID(final); err == nil {
		return id, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate instance id: %w", err)
	}
	id := hex.EncodeToString(b[:])

	tmp, err := os.CreateTemp(dir, ".work-instance-id-*")
	if err != nil {
		return "", fmt.Errorf("create instance id file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", fmt.Errorf("create instance id file: %w", err)
	}
	if _, err := tmp.WriteString(id + "\n"); err != nil {
		tmp.Close()
		return "", fmt.Errorf("write instance id: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", fmt.Errorf("write instance id: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("write instance id: %w", err)
	}
	if err := os.Link(tmp.Name(), final); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return readInstanceID(final)
		}
		return "", fmt.Errorf("publish instance id: %w", err)
	}
	// Make the new directory entry durable.
	d, err := os.Open(dir)
	if err != nil {
		return "", fmt.Errorf("sync instance id directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return "", fmt.Errorf("sync instance id directory: %w", err)
	}
	return id, nil
}

func readInstanceID(p string) (string, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if !instanceIDRE.MatchString(id) {
		return "", fmt.Errorf("instance id file %s is malformed", p)
	}
	return id, nil
}
