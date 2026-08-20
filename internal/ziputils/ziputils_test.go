// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ziputils

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsZipFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{
			name:     "Valid ZIP file",
			filename: "file.zip",
			want:     true,
		},
		{
			name:     "Valid ZIP file with uppercase extension",
			filename: "file.ZIP",
			want:     true,
		},
		{
			name:     "Not a ZIP file",
			filename: "file.json",
			want:     false,
		},
		{
			name:     "File with no extension",
			filename: "file",
			want:     false,
		},
		{
			name:     "File with path",
			filename: "/path/to/file.zip",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsZipFile(tt.filename); got != tt.want {
				t.Errorf("IsZipFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessZipFile(t *testing.T) {
	// Get the absolute path to the test-files directory
	projectRoot := getProjectRoot(t)
	testFilesDir := filepath.Join(projectRoot, "test-files")

	// Test cases
	tests := []struct {
		name        string
		zipFile     string
		wantErr     bool
		errContains string
		fileCount   int
	}{
		{
			name:      "Valid ZIP file with JSON files",
			zipFile:   filepath.Join(testFilesDir, "test_vault_files.zip"),
			wantErr:   false,
			fileCount: 3, // Contains 3 JSON files
		},
		{
			name:      "Another valid ZIP file with JSON files",
			zipFile:   filepath.Join(testFilesDir, "test_shares.zip"),
			wantErr:   false,
			fileCount: 3, // Contains 3 JSON files
		},
		{
			name:        "Non-existent file",
			zipFile:     filepath.Join(testFilesDir, "non_existent.zip"),
			wantErr:     true,
			errContains: "unable to open ZIP file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractedFiles, err := ProcessZipFile(tt.zipFile)

			// Clean up extracted files after test
			if len(extractedFiles) > 0 {
				defer os.RemoveAll(filepath.Dir(extractedFiles[0]))
			}

			// Check if error was expected
			if (err != nil) != tt.wantErr {
				t.Errorf("ProcessZipFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// If we expected an error, check that it contains the expected substring
			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ProcessZipFile() error = %v, should contain %v", err, tt.errContains)
				}
				return
			}

			// Check file count if we expected success
			if !tt.wantErr {
				if len(extractedFiles) != tt.fileCount {
					t.Errorf("ProcessZipFile() extracted %d files, want %d", len(extractedFiles), tt.fileCount)
				}

				// Verify all extracted files exist and are JSON files
				for _, file := range extractedFiles {
					if !fileExists(file) {
						t.Errorf("Extracted file %s does not exist", file)
					}

					if !strings.HasSuffix(strings.ToLower(file), ".json") {
						t.Errorf("Extracted file %s is not a JSON file", file)
					}

					// Check that the file starts with '{'
					content, err := os.ReadFile(file)
					if err != nil {
						t.Errorf("Failed to read extracted file %s: %v", file, err)
					}
					if len(content) == 0 || content[0] != '{' {
						t.Errorf("Extracted file %s does not start with '{' character", file)
					}
				}
			}
		})
	}
}

func TestProcessZipFileWithInvalidContent(t *testing.T) {
	// Create a temporary ZIP file with invalid content
	tempZipPath := filepath.Join(os.TempDir(), "test_invalid.zip")
	defer os.Remove(tempZipPath)

	// Create test cases with invalid ZIP contents
	testCases := []struct {
		name        string
		createZip   func(zipPath string) error
		errContains string
	}{
		{
			name: "ZIP with non-JSON files",
			createZip: func(zipPath string) error {
				return createZipWithNonJsonFiles(zipPath)
			},
			errContains: "contains non-JSON files",
		},
		{
			name: "ZIP with empty JSON file",
			createZip: func(zipPath string) error {
				return createZipWithEmptyJsonFile(zipPath)
			},
			errContains: "⚠ invalid file format in ZIP archive, expecting JSON files",
		},
		{
			name: "ZIP with invalid JSON content",
			createZip: func(zipPath string) error {
				return createZipWithInvalidJsonContent(zipPath)
			},
			errContains: "⚠ invalid file format in ZIP archive, expecting JSON files",
		},
		{
			name: "Empty ZIP file",
			createZip: func(zipPath string) error {
				return createEmptyZip(zipPath)
			},
			errContains: "does not contain any JSON files",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create the test ZIP file
			err := tc.createZip(tempZipPath)
			if err != nil {
				t.Fatalf("Failed to create test ZIP file: %v", err)
			}

			// Process the ZIP file
			extractedFiles, err := ProcessZipFile(tempZipPath)

			// Clean up any extracted files
			if len(extractedFiles) > 0 {
				defer os.RemoveAll(filepath.Dir(extractedFiles[0]))
			}

			// We expect an error for all these test cases
			if err == nil {
				t.Errorf("ProcessZipFile() expected error but got nil")
				return
			}

			// Check if the error contains the expected substring
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Errorf("ProcessZipFile() error = %v, should contain %v", err, tc.errContains)
			}
		})
	}
}

// Helper functions to create test ZIP files

func createZipWithNonJsonFiles(zipPath string) error {
	// Create a new ZIP file
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	// Create a ZIP writer
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Add a non-JSON file
	fileWriter, err := zipWriter.Create("file.txt")
	if err != nil {
		return err
	}

	// Write some content
	_, err = fileWriter.Write([]byte("This is a text file"))
	return err
}

func createZipWithEmptyJsonFile(zipPath string) error {
	// Create a new ZIP file
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	// Create a ZIP writer
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Add an empty JSON file
	fileWriter, err := zipWriter.Create("empty.json")
	if err != nil {
		return err
	}

	// Write empty content
	_, err = fileWriter.Write([]byte{})
	return err
}

func createZipWithInvalidJsonContent(zipPath string) error {
	// Create a new ZIP file
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	// Create a ZIP writer
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Add a JSON file with invalid content (not starting with '{')
	fileWriter, err := zipWriter.Create("invalid.json")
	if err != nil {
		return err
	}

	// Write invalid JSON content
	_, err = fileWriter.Write([]byte("Not a valid JSON"))
	return err
}

func createEmptyZip(zipPath string) error {
	// Create a new ZIP file
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	// Create a ZIP writer and close it without adding any files
	zipWriter := zip.NewWriter(zipFile)
	return zipWriter.Close()
}

// TestProcessZipFile_WithDRFile verifies that a flat ZIP mixing a Virtual Signer .dr file (JSON,
// per the current on-disk envelope format) alongside a .json file is accepted and both are
// extracted, since .dr is now a supported extension inside a ZIP.
func TestProcessZipFile_WithDRFile(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "with_dr.zip")

	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create test ZIP file: %v", err)
	}
	zipWriter := zip.NewWriter(zipFile)

	jsonWriter, err := zipWriter.Create("share.json")
	if err != nil {
		t.Fatalf("failed to add json entry: %v", err)
	}
	if _, err := jsonWriter.Write([]byte(`{"key": "value"}`)); err != nil {
		t.Fatalf("failed to write json entry: %v", err)
	}

	drWriter, err := zipWriter.Create("req0.ecdsa.secp256k1.dr")
	if err != nil {
		t.Fatalf("failed to add .dr entry: %v", err)
	}
	if _, err := drWriter.Write([]byte(`{"vaultId":"v1","requestId":"req0","reshareNonce":1,"algo":"ECDSA","curve":"secp256k1","dataB64":"AAAA"}`)); err != nil {
		t.Fatalf("failed to write .dr entry: %v", err)
	}

	if err := zipWriter.Close(); err != nil {
		t.Fatalf("failed to close ZIP writer: %v", err)
	}
	if err := zipFile.Close(); err != nil {
		t.Fatalf("failed to close ZIP file: %v", err)
	}

	extractedFiles, err := ProcessZipFile(zipPath)
	if err != nil {
		t.Fatalf("ProcessZipFile() unexpected error: %v", err)
	}
	if len(extractedFiles) > 0 {
		defer os.RemoveAll(filepath.Dir(extractedFiles[0]))
	}
	if len(extractedFiles) != 2 {
		t.Fatalf("ProcessZipFile() extracted %d files, want 2", len(extractedFiles))
	}

	var sawJSON, sawDR bool
	for _, f := range extractedFiles {
		switch strings.ToLower(filepath.Ext(f)) {
		case ".json":
			sawJSON = true
		case ".dr":
			sawDR = true
		}
	}
	if !sawJSON || !sawDR {
		t.Fatalf("expected both a .json and a .dr file among extracted files, got %v", extractedFiles)
	}
}

// TestProcessZipFile_NestedDirsAndMacOSXMetadata verifies that a ZIP whose payload files sit in
// nested directories, and which carries macOS Finder metadata (a "__MACOSX/" folder of AppleDouble
// "._" files and a ".DS_Store"), is accepted: payload files are extracted flat by basename and the
// OS metadata entries are ignored. This mirrors ZIPs produced by macOS Archive Utility.
func TestProcessZipFile_NestedDirsAndMacOSXMetadata(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "macos_style.zip")

	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create test ZIP file: %v", err)
	}
	zipWriter := zip.NewWriter(zipFile)

	entries := map[string]string{
		"backup/share.json":              `{"key":"value"}`,
		"backup/req0.ecdsa.secp256k1.dr": `{"vaultId":"v1"}`,
		"__MACOSX/backup/._share.json":   "AppleDouble junk",
		"__MACOSX/._backup":              "AppleDouble junk",
		".DS_Store":                      "Finder metadata",
	}
	for name, content := range entries {
		w, err := zipWriter.Create(name)
		if err != nil {
			t.Fatalf("failed to add entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write entry %s: %v", name, err)
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatalf("failed to close ZIP writer: %v", err)
	}
	if err := zipFile.Close(); err != nil {
		t.Fatalf("failed to close ZIP file: %v", err)
	}

	extractedFiles, err := ProcessZipFile(zipPath)
	if err != nil {
		t.Fatalf("ProcessZipFile() unexpected error: %v", err)
	}
	if len(extractedFiles) > 0 {
		defer os.RemoveAll(filepath.Dir(extractedFiles[0]))
	}
	if len(extractedFiles) != 2 {
		t.Fatalf("ProcessZipFile() extracted %d files, want 2 (only the payload files)", len(extractedFiles))
	}
	for _, f := range extractedFiles {
		base := filepath.Base(f)
		if base != "share.json" && base != "req0.ecdsa.secp256k1.dr" {
			t.Fatalf("unexpected extracted file %q; metadata should have been skipped", base)
		}
	}
}

// TestProcessZipFile_BasenameCollision verifies that two payload files sharing a basename across
// different directories are rejected rather than silently overwriting each other when flattened.
func TestProcessZipFile_BasenameCollision(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "collision.zip")

	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create test ZIP file: %v", err)
	}
	zipWriter := zip.NewWriter(zipFile)

	for _, name := range []string{"a/share.json", "b/share.json"} {
		w, err := zipWriter.Create(name)
		if err != nil {
			t.Fatalf("failed to add entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(`{"key":"value"}`)); err != nil {
			t.Fatalf("failed to write entry %s: %v", name, err)
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatalf("failed to close ZIP writer: %v", err)
	}
	if err := zipFile.Close(); err != nil {
		t.Fatalf("failed to close ZIP file: %v", err)
	}

	extractedFiles, err := ProcessZipFile(zipPath)
	if len(extractedFiles) > 0 {
		defer os.RemoveAll(filepath.Dir(extractedFiles[0]))
	}
	if err == nil {
		t.Fatalf("ProcessZipFile() expected an error for basename collision, got nil")
	}
	if !strings.Contains(err.Error(), "multiple files named") {
		t.Fatalf("ProcessZipFile() error = %v, should mention basename collision", err)
	}
}

// TestProcessZipFile_BasenameCollisionCaseInsensitive verifies that basenames differing only by
// case (e.g. "share.json" vs "SHARE.JSON") are also rejected as a collision, since they resolve
// to the same file on common case-insensitive filesystems and would otherwise let one entry
// silently overwrite the other on extraction.
func TestProcessZipFile_BasenameCollisionCaseInsensitive(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "collision-case.zip")

	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create test ZIP file: %v", err)
	}
	zipWriter := zip.NewWriter(zipFile)

	for _, name := range []string{"a/share.json", "b/SHARE.JSON"} {
		w, err := zipWriter.Create(name)
		if err != nil {
			t.Fatalf("failed to add entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(`{"key":"value"}`)); err != nil {
			t.Fatalf("failed to write entry %s: %v", name, err)
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatalf("failed to close ZIP writer: %v", err)
	}
	if err := zipFile.Close(); err != nil {
		t.Fatalf("failed to close ZIP file: %v", err)
	}

	extractedFiles, err := ProcessZipFile(zipPath)
	if len(extractedFiles) > 0 {
		defer os.RemoveAll(filepath.Dir(extractedFiles[0]))
	}
	if err == nil {
		t.Fatalf("ProcessZipFile() expected an error for case-insensitive basename collision, got nil")
	}
	if !strings.Contains(err.Error(), "multiple files named") {
		t.Fatalf("ProcessZipFile() error = %v, should mention basename collision", err)
	}
}

// Helper function to check if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestIsBundleZip(t *testing.T) {
	tests := []struct {
		name    string
		entries map[string]string // nil means no zip file is created
		want    bool
	}{
		{
			name:    "root manifest.json",
			entries: map[string]string{"manifest.json": `{"formatVersion":2}`, "dr/a.dr": `{}`},
			want:    true,
		},
		{
			name:    "corrupt root manifest.json still true",
			entries: map[string]string{"manifest.json": `not-json`, "a.dr": `{}`},
			want:    true,
		},
		{
			name:    "manifest not at root",
			entries: map[string]string{"sub/manifest.json": `{"formatVersion":2}`, "a.dr": `{}`},
			want:    false,
		},
		{
			name:    "uppercase Manifest.JSON",
			entries: map[string]string{"Manifest.JSON": `{"formatVersion":2}`},
			want:    false,
		},
		{
			name:    "no manifest",
			entries: map[string]string{"a.dr": `{}`, "b.json": `{}`},
			want:    false,
		},
		{
			name:    "empty zip",
			entries: map[string]string{},
			want:    false,
		},
		{
			name:    "unreadable path",
			entries: nil,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var zipPath string
			if tt.entries == nil {
				zipPath = filepath.Join(t.TempDir(), "missing.zip")
			} else {
				zipPath = filepath.Join(t.TempDir(), "test.zip")
				if err := writeTestZip(zipPath, tt.entries); err != nil {
					t.Fatalf("writeTestZip: %v", err)
				}
			}
			if got := IsBundleZip(zipPath); got != tt.want {
				t.Errorf("IsBundleZip() = %v, want %v", got, tt.want)
			}
		})
	}
}

func writeTestZip(zipPath string, entries map[string]string) error {
	f, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := zip.NewWriter(f)
	for name, body := range entries {
		fw, err := w.Create(name)
		if err != nil {
			_ = w.Close()
			return err
		}
		if _, err := fw.Write([]byte(body)); err != nil {
			_ = w.Close()
			return err
		}
	}
	return w.Close()
}

// Helper function to get the project root directory
func getProjectRoot(t *testing.T) string {
	// Start with the current working directory
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	// Go up until we find the go.mod file
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("Could not find project root (go.mod file)")
			return ""
		}
		dir = parent
	}
}
