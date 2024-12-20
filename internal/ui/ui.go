// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"fmt"
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
	b += fmt.Sprintf("%s%s               v5.2.0                %s\n", AnsiCodes["invertOn"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += fmt.Sprintf("%s%s                                     %s\n", AnsiCodes["invertOn"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += "\n"
	return b
}

func ErrorBox(err error) string {
	b := "\n"
	b += fmt.Sprintf("%s%s         %s\n", AnsiCodes["darkRedBG"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += fmt.Sprintf("%s%s  Error  %s  %s.\n", AnsiCodes["darkRedBG"], AnsiCodes["bold"], AnsiCodes["reset"], err)
	b += fmt.Sprintf("%s%s         %s\n", AnsiCodes["darkRedBG"], AnsiCodes["bold"], AnsiCodes["reset"])
	b += "\n"
	return b
}
