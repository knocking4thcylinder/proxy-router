package service

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifySudoersTargetRequiresInstallation(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "proxy-router")
	definition := filepath.Join(dir, "proxy-router.service")
	if err := os.WriteFile(binary, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifySudoersTarget(binary, definition, binary, binary); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing service definition: got %v", err)
	}
}

func TestVerifySudoersTargetRequiresRunningBuild(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "proxy-router")
	definition := filepath.Join(dir, "proxy-router.service")
	running := filepath.Join(dir, "running-build")
	different := filepath.Join(dir, "different-build")
	for _, path := range []string{binary, definition, running} {
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(different, []byte("other build"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifySudoersTarget(binary, definition, binary, running); err != nil {
		t.Errorf("matching build: %v", err)
	}
	if err := verifySudoersTarget(binary, definition, binary, different); err == nil {
		t.Error("accepted an installed binary that differs from the running build")
	}
	alias := filepath.Join(dir, "alias")
	if err := verifySudoersTarget(alias, definition, binary, running); err == nil {
		t.Error("accepted a rule path that resolves to a different location")
	}
}
