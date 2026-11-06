package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const debianBinary = "2.0\n"

func main() {
	arch := "amd64"
	if len(os.Args) > 1 {
		arch = os.Args[1]
	}
	version := "1.0.0"

	goarch := arch
	if arch == "armhf" {
		goarch = "arm"
	}

	distDir := "dist"
	if err := os.MkdirAll(distDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create dist: %v\n", err)
		os.Exit(1)
	}

	tmpDir, err := os.MkdirTemp("", "wd-deb-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	binPath := filepath.Join(tmpDir, "wd-auto-unlock")
	fmt.Printf("Compiling static Go binary for linux/%s...\n", goarch)
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", binPath, "./cmd/wd-auto-unlock")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %s (%v)\n", string(out), err)
		os.Exit(1)
	}

	// 1. Create control.tar.gz
	controlTarPath := filepath.Join(tmpDir, "control.tar.gz")
	controlFile, err := os.Create(controlTarPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create control tar: %v\n", err)
		os.Exit(1)
	}
	gwCtrl := gzip.NewWriter(controlFile)
	twCtrl := tar.NewWriter(gwCtrl)

	controlContent := fmt.Sprintf(`Package: wd-auto-unlock
Version: %s
Section: utils
Priority: optional
Architecture: %s
Maintainer: BobinX <https://github.com/bobinx>
Description: Western Digital My Passport auto-unlock and auto-mount utility
 Automatically unlocks and mounts Western Digital My Passport hardware-encrypted
 drives on Linux with zero third-party dependencies.
`, version, arch)

	addTarString(twCtrl, "control", controlContent, 0644)

	postinstContent := `#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    if [ ! -f /etc/wdpassport.conf ] && [ -f /etc/wdpassport.conf.example ]; then
        cp /etc/wdpassport.conf.example /etc/wdpassport.conf
        chmod 0600 /etc/wdpassport.conf
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || true
    fi
    if command -v udevadm >/dev/null 2>&1; then
        udevadm control --reload-rules || true
    fi
fi
exit 0
`
	addTarString(twCtrl, "postinst", postinstContent, 0755)

	twCtrl.Close()
	gwCtrl.Close()
	controlFile.Close()

	// 2. Create data.tar.gz
	dataTarPath := filepath.Join(tmpDir, "data.tar.gz")
	dataFile, err := os.Create(dataTarPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create data tar: %v\n", err)
		os.Exit(1)
	}
	gwData := gzip.NewWriter(dataFile)
	twData := tar.NewWriter(gwData)

	addTarFile(twData, binPath, "usr/local/bin/wd-auto-unlock", 0755)
	addTarFile(twData, "wd-unlock.service", "etc/systemd/system/wd-unlock.service", 0644)
	addTarFile(twData, "wd-unlock.timer", "etc/systemd/system/wd-unlock.timer", 0644)
	addTarFile(twData, "99-wd-passport.rules", "etc/udev/rules.d/99-wd-passport.rules", 0644)
	addTarFile(twData, "wdpassport.conf.example", "etc/wdpassport.conf.example", 0600)

	twData.Close()
	gwData.Close()
	dataFile.Close()

	// 3. Package as standard GNU ar debian archive
	debPath := filepath.Join(distDir, fmt.Sprintf("wd-auto-unlock_%s_%s.deb", version, arch))
	debFile, err := os.Create(debPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create deb: %v\n", err)
		os.Exit(1)
	}
	defer debFile.Close()

	// Write ar magic
	debFile.WriteString("!<arch>\n")

	// Write debian-binary
	writeArMember(debFile, "debian-binary", []byte(debianBinary))

	// Write control.tar.gz
	ctrlBytes, _ := os.ReadFile(controlTarPath)
	writeArMember(debFile, "control.tar.gz", ctrlBytes)

	// Write data.tar.gz
	dataBytes, _ := os.ReadFile(dataTarPath)
	writeArMember(debFile, "data.tar.gz", dataBytes)

	fmt.Printf("Successfully generated %s (%d bytes)\n", debPath, len(ctrlBytes)+len(dataBytes)+len(debianBinary)+180)
}

func addTarString(tw *tar.Writer, name, content string, mode int64) {
	bytes := []byte(content)
	hdr := &tar.Header{
		Name:     name,
		Mode:     mode,
		Size:     int64(len(bytes)),
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
	}
	_ = tw.WriteHeader(hdr)
	_, _ = tw.Write(bytes)
}

func addTarFile(tw *tar.Writer, srcPath, destPath string, mode int64) {
	f, err := os.Open(srcPath)
	if err != nil {
		return
	}
	defer f.Close()

	stat, _ := f.Stat()
	hdr := &tar.Header{
		Name:     destPath,
		Mode:     mode,
		Size:     stat.Size(),
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
	}
	_ = tw.WriteHeader(hdr)
	_, _ = io.Copy(tw, f)
}

func writeArMember(w io.Writer, name string, data []byte) {
	nameField := fmt.Sprintf("%-16s", name)
	dateField := fmt.Sprintf("%-12d", time.Now().Unix())
	uidField := fmt.Sprintf("%-6d", 0)
	gidField := fmt.Sprintf("%-6d", 0)
	modeField := fmt.Sprintf("%-8o", 0100644)
	sizeField := fmt.Sprintf("%-10d", len(data))
	fmag := "`\n"

	header := nameField + dateField + uidField + gidField + modeField + sizeField + fmag
	w.Write([]byte(header))
	w.Write(data)
	if len(data)%2 != 0 {
		w.Write([]byte("\n"))
	}
}
