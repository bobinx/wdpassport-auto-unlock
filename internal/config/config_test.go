package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigLoadAndSave(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "test.conf")

	cfg := &Config{
		Password:   "secret123",
		Device:     "/dev/sdb",
		UUID:       "88E2-42DF",
		MountPoint: "/media/WD",
		Timeout:    45,
	}

	if err := Save(confPath, cfg); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	info, err := os.Stat(confPath)
	if err != nil {
		t.Fatalf("failed to stat config: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected mode 0600, got %04o", info.Mode().Perm())
	}

	loaded, err := Load(confPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if loaded.Password != "secret123" {
		t.Errorf("expected password 'secret123', got '%s'", loaded.Password)
	}
	if loaded.Device != "/dev/sdb" {
		t.Errorf("expected device '/dev/sdb', got '%s'", loaded.Device)
	}
	if loaded.UUID != "88E2-42DF" {
		t.Errorf("expected UUID '88E2-42DF', got '%s'", loaded.UUID)
	}
	if loaded.MountPoint != "/media/WD" {
		t.Errorf("expected mount_point '/media/WD', got '%s'", loaded.MountPoint)
	}
	if loaded.Timeout != 45 {
		t.Errorf("expected timeout 45, got %d", loaded.Timeout)
	}
}
