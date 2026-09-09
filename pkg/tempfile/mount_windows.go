//go:build windows

// This file adds an experimental, opt-in Windows implementation of the
// pkg/tempfile mount/unmount hooks, using WinFsp (https://winfsp.dev) to
// back the gopass-edit temp directory with an in-memory filesystem instead
// of a plain %TEMP% directory on disk. This closes, on Windows, the same
// gap that mount_linux.go (/dev/shm) and mount_darwin.go (hdid ramdisk)
// already close on their platforms: the plaintext secret never touches
// persistent storage while it is being edited.
//
// This is a feature flag / proof-of-concept, disabled by default (mode
// "off"), and deliberately self-contained within pkg/tempfile:
//   - it does not import internal/config, so it cannot read gopass's real,
//     versioned configuration (edit.* et al.). Instead it reads a single
//     environment variable and, as a fallback, a small dotfile-style file
//     of its own. See winFspMode() below.
//   - it does not touch pkg/ctxutil, internal/editor, or any other
//     package, other than the one-line addition to docs/config.md
//     documenting the environment variable (gopass's own tests require
//     every environment variable used in the code to be documented
//     there).
//
// If this feature is ever promoted to a first-class gopass capability,
// mode resolution here should be replaced by a proper internal/config
// option (threaded through pkg/ctxutil like other per-request settings,
// the same way edit.editor already is for internal/editor), and
// winFspModeFromFile below should be deleted in favor of gopass's own
// config-directory resolution (internal/config/location.go), which this
// file intentionally does not depend on or attempt to replicate.
//
// Known limitation, not yet addressed here: the in-memory filesystem
// (github.com/winfsp/go-winfsp/memfs) stores file contents in regular Go
// process memory, not in a kernel-backed facility like Linux's /dev/shm.
// Under memory pressure the OS can still page these bytes out to
// pagefile.sys. This is the same class of residual risk /dev/shm already
// has when swap is enabled on Linux; it is not a regression, but it is
// not swap-proof either. Locking the backing buffer with VirtualLock
// would close this gap but is deferred: memfs's buffer can reallocate on
// growth (plain Go slice append), which would silently invalidate a
// naive VirtualLock call.
//
// Known limitation, not yet validated on real hardware: WinFsp is mounted
// directly onto the already-created temp directory (t.dir), the same way
// mount_darwin.go mounts its ramdisk onto t.dir instead of allocating a
// drive letter. This keeps the path returned by File.Name() unchanged
// (still inside %TEMP%), which is required for editor.Invoke to keep
// working unmodified. WinFsp is documented to support mounting onto an
// empty directory, not just onto a drive letter, but this specific
// combination (directory mountpoint + go-winfsp) has not been exercised
// on a real Windows machine as part of this change; treat it as
// unverified until confirmed in practice.

package tempfile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/pkg/debug"
	"github.com/winfsp/go-winfsp"
	"github.com/winfsp/go-winfsp/gofs"
	"github.com/winfsp/go-winfsp/memfs"
)

var shmDir = ""

// tempdirBase returns a temporary directory suitable for sensitive data. On
// Windows we always return the empty string, exactly like the pre-existing
// "unsupported platform" fallback (see mount_others.go): the actual
// directory is chosen by os.MkdirTemp against the OS default (%TEMP%), and
// -- when the winfsp feature flag is enabled and available -- mount()
// below remounts that same directory as an in-memory filesystem in place.
func tempdirBase() string {
	return ""
}

// winFspModeEnvVar names the feature-flag environment variable for this
// experimental capability. Kept in sync manually with the literal string
// used in the os.Getenv call in winFspMode below, which must stay a
// literal for gopass's own docs/env tests (internal/config/docs_test.go)
// to recognize it as documented in docs/config.md.
const winFspModeEnvVar = "GOPASS_WINFSP_MODE"

// winFspHint is shown whenever WinFsp was requested (mode "auto" or
// "require") but could not be loaded or used.
const winFspHint = "Hint: Install WinFsp from https://winfsp.dev/rel/ (or: winget install -e --id WinFsp.WinFsp)"

// isValidWinFspMode reports whether v is one of the recognized mode
// values.
func isValidWinFspMode(v string) bool {
	switch v {
	case "off", "auto", "require":
		return true
	default:
		return false
	}
}

// stripQuotes removes one matching pair of surrounding double or single
// quotes from v (e.g. `"require"` becomes `require`). Needed because
// cmd.exe's `set NAME=value` does not strip quotes the way POSIX shells
// do, so a quoted mode value reaches us with the quotes still attached.
func stripQuotes(v string) string {
	if len(v) < 2 {
		return v
	}

	first, last := v[0], v[len(v)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		return v[1 : len(v)-1]
	}

	return v
}

// winFspModeFromFile is a self-contained, feature-flag-scoped discovery
// helper for a dotfile-style override, for users who prefer to keep this
// setting in a file rather than an environment variable (e.g. dotfile
// management tools). It deliberately does NOT reuse or replicate gopass's
// real configuration-directory resolution (internal/config/location.go),
// to avoid silently drifting out of sync with it if that logic changes.
// Instead it uses a dedicated directory of its own, next to (not inside)
// gopass's real config directory, resolved via the Go standard library
// (%AppData% on Windows).
//
// Path: %AppData%\gopass-winfsp\mode
//
// If this feature is ever promoted to a first-class gopass capability,
// this function should be deleted in favor of gopass's real config
// system.
func winFspModeFromFile() string {
	base, err := os.UserConfigDir()
	if err != nil {
		debug.Log("tempfile: winfsp: could not resolve user config dir: %s", err)

		return ""
	}

	fn := filepath.Join(base, "gopass-winfsp", "mode")

	data, err := os.ReadFile(fn)
	if err != nil {
		// Absence of the file is the expected common case, not an error.
		return ""
	}

	return strings.ToLower(strings.TrimSpace(stripQuotes(strings.TrimSpace(string(data)))))
}

// winFspMode resolves the effective mode for this run, in order of
// precedence: the GOPASS_WINFSP_MODE environment variable, then the
// dotfile read by winFspModeFromFile, then the "off" default. An
// unrecognized value from either source is logged and skipped, falling
// through to the next source, exactly as if it had been unset.
func winFspMode() string {
	if v := strings.ToLower(strings.TrimSpace(stripQuotes(strings.TrimSpace(os.Getenv("GOPASS_WINFSP_MODE"))))); v != "" {
		if isValidWinFspMode(v) {
			return v
		}

		debug.Log("tempfile: winfsp: ignoring unrecognized %s=%q", winFspModeEnvVar, v)
	}

	if v := winFspModeFromFile(); v != "" {
		if isValidWinFspMode(v) {
			return v
		}

		debug.Log("tempfile: winfsp: ignoring unrecognized mode %q from config file", v)
	}

	return "off"
}

func (t *File) mount(ctx context.Context) error {
	_ = t.dev // to trick megacheck

	mode := winFspMode()
	if mode == "off" {
		return nil
	}

	if err := winfsp.LoadWinFSP(); err != nil {
		if mode == "require" {
			out.Errorf(ctx, "winfsp not found or failed to load: %s", err)
			out.Printf(ctx, winFspHint)

			return fmt.Errorf("%s=require but winfsp is unavailable: %w", winFspModeEnvVar, err)
		}

		out.Warningf(ctx, "winfsp not found, falling back to the default temp directory")
		out.Printf(ctx, winFspHint)

		return nil
	}

	fs := gofs.New(memfs.New(memfs.WithCaseInsensitive(true)))

	// Unlike mount_darwin.go's "diskutil mount -mountpoint t.dir" (which
	// follows the POSIX convention of mounting onto an already-existing,
	// empty directory, same as Linux), WinFsp's directory-mountpoint mode
	// does the opposite: it creates the mountpoint itself as an NTFS
	// reparse point ("mountpoint junction") at t.dir, and NTFS refuses to
	// create that reparse point if a filesystem object already occupies
	// the path. See https://winfsp.dev/doc/Frequently-Asked-Questions/
	// ("Inability to mount over a non-empty directory on Windows ... NTFS
	// disallows the creation of (mountpoint) reparse points on non-empty
	// directories"); rclone hit the identical "Cannot create a file when
	// that file already exists" failure for the same reason when its
	// destination path was pre-created.
	//
	// t.dir was already created (empty) by os.MkdirTemp in tempfile.New
	// (pkg/tempfile/file.go) before mount() is ever invoked, so we must
	// remove that placeholder directory here and let winfsp.Mount recreate
	// the path as its reparse point. This opens a small, unavoidable
	// TOCTOU window between os.Remove and winfsp.Mount; given the random
	// suffix os.MkdirTemp already put in the path, the practical collision
	// risk on a single-user workstation is negligible, and is the same
	// class of risk WinFsp's own directory-mount design already accepts
	// (it cannot guarantee mountpoint cleanup on a crash either, which is
	// why it relies on FILE_FLAG_DELETE_ON_CLOSE instead of a persistent
	// on-disk directory).
	if err := os.Remove(t.dir); err != nil && !os.IsNotExist(err) {
		if mode == "require" {
			return fmt.Errorf("%s=require but failed to prepare mountpoint %s: %w", winFspModeEnvVar, t.dir, err)
		}

		out.Warningf(ctx, "failed to prepare winfsp mountpoint %s, falling back to the default temp directory: %s", t.dir, err)
		out.Printf(ctx, winFspHint)

		return nil
	}

	fspFS, err := winfsp.Mount(fs, t.dir)
	if err != nil {
		if mode == "require" {
			return fmt.Errorf("%s=require but failed to mount winfsp at %s: %w", winFspModeEnvVar, t.dir, err)
		}

		out.Warningf(ctx, "failed to mount winfsp at %s, falling back to the default temp directory: %s", t.dir, err)
		out.Printf(ctx, winFspHint)

		return nil
	}

	t.mnt = fspFS

	out.Printf(ctx, "gopass: using a WinFsp-backed secure temp directory (experimental, %s=%s)", winFspModeEnvVar, mode)

	return nil
}

func (t *File) unmount(context.Context) error {
	if t.mnt != nil {
		t.mnt.Unmount()
		t.mnt = nil
	}

	return nil
}
