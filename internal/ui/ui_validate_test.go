package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlainText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Valid with space", "test file.json", "test file.json"},
		{"Valid with different symbols", "test_file-with$?!@#%&*()_=+;¿?.$,~{}¡!'/symbols.json", "test_file-with$?!@#%&*()_=+;¿?.$,~{}¡!'/symbols.json"},
		{"Valid with windows path", "windows\\path\\test.file.json", "windows\\path\\test.file.json"},
		{"Valid with unix path", "unix/path/test.file.json", "unix/path/test.file.json"},
		{"Valid with variations", "filèñçü.file.json", "filèñçü.file.json"},
		{"Valid with icons", "🤷🏼‍♀️.file.json", "🤷🏼‍♀️.file.json"},
		// Cases with ANSI escape codes
		{"Invalid ANSI escape code", "scape\x1B.json", "scape.json"},
		{"Invalid ASCII control character", "control\x00.json", "control.json"},
		{"Invalid ASCII delete character", "delete\x1f.json", "delete.json"},
		{"Invalid ANSI escape code + extra other code (clear terminal code)", "clear-terminal\x1b[3J.json", "clear-terminal[3J.json"},
		{"Invalid ASCII form feed character", "\x0cform-feed", "form-feed"},
		{"Invalid ASCII line feed character", "\x0aline-feed", "line-feed"},
		{"Invalid ASCII carriage return character", "carriage\x0d-return", "carriage-return"},
		{"Invalid ASCII horizontal tab character", "horizontal\x09-tab", "horizontal-tab"},
		{"Invalid ASCII vertical tab character", "vertical\x0b-tab", "vertical-tab"},
		{"Invalid ASCII null character", "\x00null", "null"},
		{"Invalid ASCII escape character", "\x1bescape", "escape"},
		{"Invalid ANSI code for dark red background", "red" + AnsiCodes["darkRedBG"], "red[41m"},
		{"Invalid ANSI code for dark green background", "darkgreen" + AnsiCodes["darkGreenBG"], "darkgreen[42m"},
		{"Invalid ANSI code for invert on", "inverton" + AnsiCodes["invertOn"], "inverton[7m"},
		{"Invalid ANSI code for reset", "reset" + AnsiCodes["reset"], "reset[0m"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plainText := PlainText(tt.input)
			assert.Equal(t, tt.expected, plainText)
		})
	}
}

func TestValidateExportFilenameForCli(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{"valid simple filename", "wallet.json", false},
		{"valid with hyphens", "my-wallet.json", false},
		{"valid with underscores", "my_wallet.json", false},
		{"valid uppercase extension", "wallet.JSON", false},
		{"valid mixed case extension", "wallet.Json", false},
		{"trimmed whitespace", "  wallet.json  ", false},

		// Note: on Unix, backslash is a valid filename character, not a path separator.
		{"filename with backslashes on unix", "path\\to\\wallet.json", false},

		// Rejections
		{"empty string", "", true},
		{"whitespace only", "   ", true},
		{"null byte", "file\x00name.json", true},
		{"wrong extension txt", "wallet.txt", true},
		{"wrong extension csv", "wallet.csv", true},
		{"no extension", "wallet", true},
		{"hidden file", ".hidden.json", true},
		{"dot only", ".", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExportFilenameForCli(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestScopeExportPath(t *testing.T) {
	baseDir := t.TempDir()
	defer os.Remove(baseDir)

	//File to test that it is not overwritten
	dummyFile := "dummy.json"
	if err := os.WriteFile(filepath.Join(baseDir, dummyFile), []byte("dummy"), 0644); err != nil {
		t.Fatalf("failed to create dummy file: %v", err)
	}

	tests := []struct {
		name        string
		filename    string
		expected    string
		expectError bool
	}{

		{"valid simple filename scoped to base", "wallet.json", "wallet.json", false},
		{"valid with hyphens scoped to base", "my-wallet.json", "my-wallet.json", false},
		{"valid with underscores scoped to base", "my_wallet.json", "my_wallet.json", false},
		{"valid uppercase extension scoped to base", "wallet.JSON", "wallet.JSON", false},
		{"valid mixed case extension scoped to base", "wallet.Json", "wallet.Json", false},
		{"trimmed whitespace scoped to base", "  wallet.json  ", "wallet.json", false},
		// Note: on Unix, backslash is a valid filename character, not a path separator.
		{"filename with backslashes on unix scoped to base", "path\\to\\wallet.json", "path\\to\\wallet.json", false},

		// Rejections
		{"empty string", "", "", true},
		{"whitespace only", "   ", "", true},
		{"null byte", "file\x00name.json", "", true},
		{"wrong extension txt", "wallet.txt", "", true},
		{"wrong extension csv", "wallet.csv", "", true},
		{"no extension", "wallet", "", true},
		{"hidden file", ".hidden.json", "", true},
		{"dot only", ".", "", true},
		{"file with directory components rejected", "../../etc/passwd.json", "", true},
		{"base tmp directory is rejected", baseDir, "", true},

		// Detection of existing file
		{"file already exported cause no conflict", dummyFile, dummyFile, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ScopeExportPathForWeb(tt.filename, baseDir)
			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, filepath.Base(result))

				randomDirPath := filepath.Dir(result)
				assert.Regexp(t, `^req-\d{2,16}$`, filepath.Base(randomDirPath))

				baseTmpDirPath := filepath.Dir(randomDirPath)
				assert.Equal(t, baseDir, baseTmpDirPath)
			}
		})
	}
}
