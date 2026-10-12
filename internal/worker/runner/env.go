//go:build unix

package runner

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// npmRegistry is the only registry npm and pnpm use.
const npmRegistry = "https://registry.npmjs.org/"

// Names of the empty files npm and pnpm are told to read as their user and
// global configuration. They must be two different paths: npm refuses to load
// the same file as both.
const (
	npmUserConfig   = "npmrc-user"
	npmGlobalConfig = "npmrc-global"
)

// cacheDir is where the children keep caches, stores and configuration. It is
// under TmpDir, so it lives and dies with the container's tmpfs.
func (c *Config) cacheDir() string { return filepath.Join(c.TmpDir, "kestrelynx-cache") }

// prepareCache creates the cache directory and the empty npm configuration
// files the environment points at.
func (c *Config) prepareCache() error {
	if err := os.MkdirAll(c.cacheDir(), 0o700); err != nil {
		return err
	}
	for _, n := range []string{npmUserConfig, npmGlobalConfig} {
		if err := os.WriteFile(filepath.Join(c.cacheDir(), n), nil, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// childEnv builds the environment of a child process from a fixed list. The
// program's own environment is never copied, so nothing the container was
// started with, and no repository file, can add a variable. Package-manager
// configuration files are pointed at /dev/null so only these values count.
func (c *Config) childEnv(m worker.Manager) []string {
	cache := c.cacheDir()
	env := map[string]string{
		"PATH":            c.Path,
		"HOME":            c.HomeDir,
		"TMPDIR":          c.TmpDir,
		"LANG":            "C.UTF-8",
		"TERM":            "dumb",
		"NO_COLOR":        "1",
		"XDG_CACHE_HOME":  filepath.Join(cache, "xdg-cache"),
		"XDG_DATA_HOME":   filepath.Join(cache, "xdg-data"),
		"XDG_CONFIG_HOME": filepath.Join(cache, "xdg-config"),
		"XDG_STATE_HOME":  filepath.Join(cache, "xdg-state"),
	}
	switch m {
	case worker.ManagerNpm, worker.ManagerPnpm:
		env["npm_config_userconfig"] = filepath.Join(cache, npmUserConfig)
		env["npm_config_globalconfig"] = filepath.Join(cache, npmGlobalConfig)
		env["npm_config_registry"] = npmRegistry
		env["npm_config_update_notifier"] = "false"
		env["npm_config_fund"] = "false"
		env["npm_config_audit"] = "false"
		env["npm_config_ignore_scripts"] = "true"
		env["npm_config_progress"] = "false"
		env["COREPACK_ENABLE_NETWORK"] = "0"
		env["COREPACK_ENABLE_AUTO_PIN"] = "0"
		env["COREPACK_ENABLE_DOWNLOAD_PROMPT"] = "0"
		env["COREPACK_ENABLE_STRICT"] = "0"
		if m == worker.ManagerNpm {
			env["npm_config_cache"] = filepath.Join(cache, "npm")
			env["npm_config_prefix"] = filepath.Join(cache, "npm-prefix")
		} else {
			// pnpm reads its own settings from pnpm_config_* variables; the
			// npm_config_* names above only matter for the shared files. The
			// settings that stop pnpm from fetching another version of itself
			// are not set here: pnpm 10 does not read them from the
			// environment, so they are arguments of the command line (see
			// worker.PnpmFixedConfig).
			env["pnpm_config_registry"] = npmRegistry
			env["pnpm_config_store_dir"] = filepath.Join(cache, "pnpm-store")
			env["pnpm_config_cache_dir"] = filepath.Join(cache, "pnpm-cache")
			env["pnpm_config_update_notifier"] = "false"
			env["PNPM_HOME"] = filepath.Join(cache, "pnpm-home")
		}
	case worker.ManagerUv:
		env["UV_NO_CONFIG"] = "1"
		env["UV_PYTHON_DOWNLOADS"] = "never"
		env["UV_PYTHON_PREFERENCE"] = "only-system"
		env["UV_CACHE_DIR"] = filepath.Join(cache, "uv")
		env["UV_NO_PROGRESS"] = "1"
	case worker.ManagerPip:
		env["PIP_CONFIG_FILE"] = "/dev/null"
		env["PIP_CACHE_DIR"] = filepath.Join(cache, "pip")
		env["PIP_NO_INPUT"] = "1"
		env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
		env["PYTHONDONTWRITEBYTECODE"] = "1"
		env["PYTHONNOUSERSITE"] = "1"
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}
