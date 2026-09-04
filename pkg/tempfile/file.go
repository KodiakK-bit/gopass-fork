// Package tempfile is a wrapper around os.MkdirTemp, providing an OO pattern
// as well as secure placement on a temporary ramdisk.
package tempfile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotInit is returned when the file is not initialized.
var ErrNotInit = fmt.Errorf("not initialized")

// globalPrefix is prefixed to all temporary dirs.
var globalPrefix string

// mountHandle is implemented by platform-specific mount handles that need
// to be released when the tempfile is removed. Currently only used on
// Windows (see mount_windows.go), where it is satisfied by
// *winfsp.FileSystem. It is declared here, without any platform build tag,
// so that File itself stays platform-independent and pkg/tempfile does not
// need a Windows-only variant of the File type.
type mountHandle interface {
	Unmount()
}

// File is a temporary file that is stored on a ramdisk if possible.
type File struct {
	dir string
	dev string
	fh  *os.File
	mnt mountHandle // only ever set on Windows; nil on all other platforms.
}

// New returns a new tempfile wrapper.
// It will create a temporary directory and a file inside it.
// If possible, it will mount a ramdisk to the temporary directory.
func New(ctx context.Context, prefix string) (*File, error) {
	td, err := os.MkdirTemp(tempdirBase(), globalPrefix+prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to create tempdir: %w", err)
	}

	tf := &File{
		dir: td,
	}

	if err := tf.mount(ctx); err != nil {
		_ = os.RemoveAll(tf.dir)

		return nil, fmt.Errorf("failed to mount %s: %w", tf.dir, err)
	}

	fn := filepath.Join(tf.dir, "secret")

	fh, err := os.OpenFile(fn, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", fn, err)
	}

	tf.fh = fh

	return tf, nil
}

// Name returns the name of the tempfile.
func (t *File) Name() string {
	if t.fh == nil {
		return ""
	}

	return t.fh.Name()
}

// Write implements io.Writer.
func (t *File) Write(p []byte) (int, error) {
	if t.fh == nil {
		return 0, ErrNotInit
	}

	return t.fh.Write(p) //nolint:wrapcheck
}

// Close implements io.WriteCloser.
func (t *File) Close() error {
	if t.fh == nil {
		return nil
	}

	return t.fh.Close() //nolint:wrapcheck
}

// Remove attempts to remove the tempfile.
func (t *File) Remove(ctx context.Context) error {
	_ = t.Close()

	if err := t.unmount(ctx); err != nil {
		return fmt.Errorf("failed to unmount %s from %s: %w", t.dev, t.dir, err)
	}

	if t.dir == "" {
		return nil
	}

	if err := os.RemoveAll(t.dir); err != nil {
		return fmt.Errorf("failed to remove %s: %w", t.dir, err)
	}

	return nil
}
