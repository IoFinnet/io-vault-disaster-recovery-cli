package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVaultsDataFilesZeroize(t *testing.T) {
	files := VaultsDataFiles{
		{File: "test1.json", Mnemonics: "word1 word2 word3"},
		{File: "test2.json", Mnemonics: "word4 word5 word6"},
	}

	files.Zeroize()

	for _, f := range files {
		assert.Equal(t, "", f.Mnemonics)
	}
}

func TestVaultsDataFilesZeroize_EmptySlice(t *testing.T) {
	files := VaultsDataFiles{}
	files.Zeroize() // should not panic
}

func TestVaultsDataFilesZeroize_EmptyMnemonics(t *testing.T) {
	files := VaultsDataFiles{
		{File: "test.json", Mnemonics: ""},
	}
	files.Zeroize() // should not panic
}
