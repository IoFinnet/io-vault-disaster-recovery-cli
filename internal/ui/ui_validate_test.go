package ui

import (
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

func TestValidateExportFilename(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{"valid simple filename", "wallet.json", "wallet.json", false},
		{"valid with hyphens", "my-wallet.json", "my-wallet.json", false},
		{"valid with underscores", "my_wallet.json", "my_wallet.json", false},
		{"valid uppercase extension", "wallet.JSON", "wallet.JSON", false},
		{"valid mixed case extension", "wallet.Json", "wallet.Json", false},
		{"trimmed whitespace", "  wallet.json  ", "wallet.json", false},

		// Path stripping — directory components removed, bare filename returned
		{"strips directory traversal", "../../etc/passwd.json", "passwd.json", false},
		{"strips absolute path", "/etc/wallet.json", "wallet.json", false},
		{"strips relative path", "path/to/wallet.json", "wallet.json", false},
		// Note: on Unix, backslash is a valid filename character, not a path separator.
		// filepath.Base does not strip backslash-delimited components on Unix.
		// This test verifies the actual platform behavior.
		{"filename with backslashes on unix", "path\\to\\wallet.json", "path\\to\\wallet.json", false},

		// Rejections
		{"empty string", "", "", true},
		{"whitespace only", "   ", "", true},
		{"null byte", "file\x00name.json", "", true},
		{"wrong extension txt", "wallet.txt", "", true},
		{"wrong extension csv", "wallet.csv", "", true},
		{"no extension", "wallet", "", true},
		{"hidden file", ".hidden.json", "", true},
		{"dot only", ".", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateExportFilename(tt.input)
			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestScopeExportPath(t *testing.T) {
	baseDir := filepath.Join("/tmp", "vault-web-test")

	tests := []struct {
		name        string
		filename    string
		expected    string
		expectError bool
	}{
		{"valid filename scoped to base", "wallet.json", filepath.Join(baseDir, "wallet.json"), false},
		{"traversal stripped and scoped", "../../etc/passwd.json", filepath.Join(baseDir, "passwd.json"), false},
		{"absolute path stripped and scoped", "/etc/wallet.json", filepath.Join(baseDir, "wallet.json"), false},
		{"empty filename rejected", "", "", true},
		{"wrong extension rejected", "wallet.txt", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ScopeExportPath(tt.filename, baseDir)
			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
