// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	"fmt"
)

func banner() string {
	b := "\n"
	b += fmt.Sprintf("%s%s                                     %s\n", ansiCodes["invertOn"], ansiCodes["bold"], ansiCodes["reset"])
	b += fmt.Sprintf("%s%s     io.finnet Key Recovery Tool     %s\n", ansiCodes["invertOn"], ansiCodes["bold"], ansiCodes["reset"])
	b += fmt.Sprintf("%s%s               v5.0.0                %s\n", ansiCodes["invertOn"], ansiCodes["bold"], ansiCodes["reset"])
	b += fmt.Sprintf("%s%s                                     %s\n", ansiCodes["invertOn"], ansiCodes["bold"], ansiCodes["reset"])
	b += "\n"
	return b
}

func errorBox(err error) string {
	b := "\n"
	b += fmt.Sprintf("%s%s         %s\n", ansiCodes["darkRedBG"], ansiCodes["bold"], ansiCodes["reset"])
	b += fmt.Sprintf("%s%s  Error  %s  %s.\n", ansiCodes["darkRedBG"], ansiCodes["bold"], ansiCodes["reset"], err)
	b += fmt.Sprintf("%s%s         %s\n", ansiCodes["darkRedBG"], ansiCodes["bold"], ansiCodes["reset"])
	b += "\n"
	return b
}
