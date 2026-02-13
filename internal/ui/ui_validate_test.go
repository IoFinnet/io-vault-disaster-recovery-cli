package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlainText(t *testing.T) {
	tests := []struct {
		name                  string
		input                 string
		expected              string
	}{
		{"Valid with space", "test file.json", "test file.json"},
		{"Valid with different symbols", "test_file-with$?!@#%&*()_=+;¿?.$,~{}¡!'/symbols.json", "test_file-with$?!@#%&*()_=+;¿?.$,~{}¡!'/symbols.json"},
		{"Valid with windows path", "windows\\path\\test.file.json", "windows\\path\\test.file.json"},
		{"Valid with unix path", "unix/path/test.file.json", "unix/path/test.file.json"},
		{"Valid with variations", "filèñçü.file.json", "filèñçü.file.json"},
		{"Valid with icons", "🤷🏼‍♀️.file.json", "🤷🏼‍♀️.file.json"},
		//Error cases
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