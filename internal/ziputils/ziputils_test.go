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
			name: "ZIP with nested directories",
			createZip: func(zipPath string) error {
				return createZipWithNestedDirs(zipPath)
			},
			errContains: "contains nested directories",
		},
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

func createZipWithNestedDirs(zipPath string) error {
	// Create a new ZIP file
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	// Create a ZIP writer
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Add a JSON file in a nested directory
	fileWriter, err := zipWriter.Create("nested/dir/file.json")
	if err != nil {
		return err
	}

	// Write valid JSON content
	_, err = fileWriter.Write([]byte(`{"key": "value"}`))
	return err
}

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

// Helper function to check if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
