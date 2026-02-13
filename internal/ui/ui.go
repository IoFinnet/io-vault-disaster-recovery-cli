// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"fmt"
	"regexp"
)

const (
	WORDS = 24
)

var (
	// ANSI escape seqs for colours in the terminal
	AnsiCodes = map[string]string{
		"bold":        "\033[1m",
		"invertOn":    "\033[7m",
		"darkRedBG":   "\033[41m",
		"darkGreenBG": "\033[42m",
		"reset":       "\033[0m",
	}
)

func Banner() string {
	b := "\n"
	b += fmt.Sprintf("%s%s                                     %s\n", AnsiCodes["invertOn"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += fmt.Sprintf("%s%s     io.finnet Key Recovery Tool     %s\n", AnsiCodes["invertOn"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += fmt.Sprintf("%s%s               v6.0.0                %s\n", AnsiCodes["invertOn"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += fmt.Sprintf("%s%s                                     %s\n", AnsiCodes["invertOn"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += "\n"
	return b
}

func ErrorBox(err error) string {
	b := "\n"
	b += fmt.Sprintf("%s%s         %s\n", AnsiCodes["darkRedBG"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += fmt.Sprintf("%s%s  Error  %s  %s.\n", AnsiCodes["darkRedBG"], AnsiCodes["bold"], AnsiCodes["reset"], PlainText(err.Error()))
	b += fmt.Sprintf("%s%s         %s\n", AnsiCodes["darkRedBG"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += "\n"
	return b
}


func SuccessBox() string {
	b := "\n"
	b += fmt.Sprintf("%s%s                %s\n", AnsiCodes["darkGreenBG"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += fmt.Sprintf("%s%s    Success!    %s\n", AnsiCodes["darkGreenBG"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += fmt.Sprintf("%s%s                %s\n", AnsiCodes["darkGreenBG"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += "\n"
	return b
}

func Bold(text string) string {
	return fmt.Sprintf("%s%s%s", AnsiCodes["bold"], NonANSIEscapeCodes(text), AnsiCodes["reset"])
}
func Boldf(format string, a ...any) string {
	return fmt.Sprintf("%s%s%s", AnsiCodes["bold"], NonANSIEscapeCodes(fmt.Sprintf(format, a...)), AnsiCodes["reset"])
}

func PlainText(text string) string {
	return NonANSIEscapeCodes(text)
}

func PlainTextf(format string, a ...any) string {
	return NonANSIEscapeCodes(fmt.Sprintf(format, a...))
}

func NonANSIEscapeCodes(input string) string {
	// See https://pkg.go.dev/unicode#CategoryAliases
	const forbiddenPattern = `\p{Control}`
	replaced := regexp.MustCompile(forbiddenPattern).ReplaceAllString(input, "")
	return replaced
}