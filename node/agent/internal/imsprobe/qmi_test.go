package imsprobe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCacheRejectsSymlinkAndWritableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registration")
	if err := os.WriteFile(path, []byte("IMS registration:\n Status: 'registered'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err == nil {
		if _, err := readCache(link, time.Now()); err == nil {
			t.Fatal("symlink cache accepted")
		}
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readCache(path, time.Now()); err == nil {
		t.Fatal("writable cache accepted")
	}
}

func TestCacheRequiresTrustedOwnershipAndFreshness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registration")
	if err := os.WriteFile(path, []byte("IMS registration:\n Status: 'registered'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = readCache(path, time.Now())
	if rootOwned(info) {
		if err != nil {
			t.Fatal(err)
		}
	} else if err == nil {
		t.Fatal("non-root cache accepted")
	}
	if _, err := readCache(path, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("stale cache accepted")
	}
}
