package ui

import (
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateStringIsSafeForShell(t *testing.T) {
	tests := []struct {
		name                  string
		fileName              string
		expectedMatchedString string
		expectedError         bool
	}{
		{"Valid with space", "test file.json", "", false},
		{"Valid with different symbols", "test_file-with$?!@#%&*()_=+;¿?.$,~{}¡!'/symbols.json", "", false},
		{"Valid with windows path", "windows\\path\\test.file.json", "", false},
		{"Valid with unix path", "unix/path/test.file.json", "", false},
		{"Valid with variations", "filèñçü.file.json", "", false},
		{"Valid with icons", "🤷🏼‍♀️.file.json", "", false},
		//Error cases
		{"Invalid ANSI escape code", "scape\x1B.json", `"\x1b"`, true},
		{"Invalid ASCII control character", "control\x00.json", `"\x00"`, true},
		{"Invalid ASCII delete character", "delete\x1f.json", `"\x1f"`, true},
		{"Invalid ANSI escape code + extra other code (clear terminal code)", "clear-terminal\x1b[3J.json", `"\x1b"`, true},
		{"Invalid ASCII form feed character", "\x0cform-feed", `"\f"`, true},
		{"Invalid ASCII line feed character", "\x0aline-feed", `"\n"`, true},
		{"Invalid ASCII carriage return character", "\x0dcarriage-return", `"\r"`, true},
		{"Invalid ASCII horizontal tab character", "\x09horizontal-tab", `"\t"`, true},
		{"Invalid ASCII vertical tab character", "\x0bvertical-tab", `"\v"`, true},
		{"Invalid ASCII null character", "\x00null", `"\x00"`, true},
		{"Invalid ASCII escape character", "\x1bescape", `"\x1b"`, true},
		{"Invalid ANSI code for dark red background", "red" + AnsiCodes["darkRedBG"], `"\x1b"`, true},
		{"Invalid ANSI code for dark green background", "darkgreen" + AnsiCodes["darkGreenBG"], `"\x1b"`, true},
		{"Invalid ANSI code for invert on", "inverton" + AnsiCodes["invertOn"], `"\x1b"`, true},
		{"Invalid ANSI code for reset", "reset" + AnsiCodes["reset"], `"\x1b"`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err, matchedString := validateStringIsSafeForShell(tt.fileName)
			assert.Equal(t, tt.expectedMatchedString, matchedString)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateUserInputsAreSafe(t *testing.T) {
	nonANSIEscapeCodes := "test_file- èñçü🤷🏼‍♀️\\with$?!@#%&*()_=+;¿?.$,~{}¡!'/symbols.json"

	tests := []struct {
		name          string
		appConfig     *config.AppConfig
		expectedError bool
	}{
		//Valid cases
		{"Valid filenames with non ANSI escape codes", &config.AppConfig{Filenames: []string{nonANSIEscapeCodes}}, false},
		{"Valid ZipExtractedDirs with non ANSI escape codes", &config.AppConfig{ZipExtractedDirs: []string{nonANSIEscapeCodes}}, false},
		{"Valid ExportKSFile with non ANSI escape codes", &config.AppConfig{ExportKSFile: nonANSIEscapeCodes}, false},
		{"Valid PasswordForKS with ANSI escape code", &config.AppConfig{PasswordForKS: "password\x1B"}, false},
		//Error cases
		{"Invalid filename with ANSI escape code", &config.AppConfig{Filenames: []string{"scape\x1B.json"}}, true},
		{"Invalid ZipExtractedDirs with ANSI escape code", &config.AppConfig{ZipExtractedDirs: []string{"zip\x1B.json"}}, true},
		{"Invalid ExportKSFile with ANSI escape code", &config.AppConfig{ExportKSFile: "ansi\x1B.json"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUserInputsAreSafe(tt.appConfig)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
