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

// HDAddressesUsage returns usage information for the HD addresses CSV feature
func HDAddressesUsage() string {
	b := fmt.Sprintf("%sHD Address Recovery:%s\n", AnsiCodes["bold"], AnsiCodes["reset"])
	b += "  The -addresses-csv flag enables recovery of derived HD wallet addresses.\n"
	b += "  The CSV file can be exported through the io.finnet API or, in the future,\n"
	b += "  through the io.vault dashboard interface.\n"
	b += "\n"
	b += fmt.Sprintf("  %sCSV Format:%s\n", AnsiCodes["bold"], AnsiCodes["reset"])
	b += "    address,xpub,path,algorithm,curve,flags\n"
	b += "\n"
	b += fmt.Sprintf("  %sColumns:%s\n", AnsiCodes["bold"], AnsiCodes["reset"])
	b += "    address   - Label/identifier for the address\n"
	b += "    xpub      - Extended public key with chain code\n"
	b += "    path      - BIP32 derivation path (e.g., m/44/60/0/0/0)\n"
	b += "    algorithm - ECDSA, EDDSA, or SCHNORR\n"
	b += "    curve     - secp256k1, P-256, or Edwards25519\n"
	b += "    flags     - Reserved (set to 0)\n"
	b += "\n"
	b += fmt.Sprintf("  %sExample:%s\n", AnsiCodes["bold"], AnsiCodes["reset"])
	b += "    ./recovery-tool -addresses-csv addresses.csv backup1.json backup2.json\n"
	b += "\n"
	b += fmt.Sprintf("  %sOutput:%s\n", AnsiCodes["bold"], AnsiCodes["reset"])
	b += "    Creates addresses_recovered.csv with derived public and private keys.\n"
	return b
}
