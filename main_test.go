// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyPathsFlag_Set(t *testing.T) {
	t.Run("repeated flags accumulate", func(t *testing.T) {
		var f keyPathsFlag
		require.NoError(t, f.Set("a.pem"))
		require.NoError(t, f.Set("b.pem"))
		require.Equal(t, []string{"a.pem", "b.pem"}, []string(f))
	})

	t.Run("comma list splits", func(t *testing.T) {
		var f keyPathsFlag
		require.NoError(t, f.Set("a.pem,b.pem,c.pem"))
		require.Equal(t, []string{"a.pem", "b.pem", "c.pem"}, []string(f))
	})

	t.Run("mixed repeated and comma", func(t *testing.T) {
		var f keyPathsFlag
		require.NoError(t, f.Set("a.pem,b.pem"))
		require.NoError(t, f.Set("c.pem"))
		require.Equal(t, []string{"a.pem", "b.pem", "c.pem"}, []string(f))
	})

	t.Run("surrounding whitespace trimmed", func(t *testing.T) {
		var f keyPathsFlag
		require.NoError(t, f.Set(" a.pem , b.pem "))
		require.Equal(t, []string{"a.pem", "b.pem"}, []string(f))
	})

	t.Run("empty token errors", func(t *testing.T) {
		var f keyPathsFlag
		require.Error(t, f.Set(""))

		var f2 keyPathsFlag
		require.Error(t, f2.Set("a.pem,,b.pem"))
	})

	t.Run("duplicate paths collapse, order preserved", func(t *testing.T) {
		var f keyPathsFlag
		require.NoError(t, f.Set("a.pem"))
		require.NoError(t, f.Set("./a.pem"))
		require.NoError(t, f.Set("b.pem"))
		require.Equal(t, []string{"a.pem", "b.pem"}, []string(f))
	})

	t.Run("String on nil receiver does not panic", func(t *testing.T) {
		var f *keyPathsFlag
		require.NotPanics(t, func() {
			_ = f.String()
		})
	})
}

func TestReadPrivateKeys(t *testing.T) {
	dirTmp := t.TempDir()

	t.Run("missing path errors and names the path", func(t *testing.T) {
		missing := filepath.Join(dirTmp, "missing.pem")
		keys, err := readPrivateKeys([]string{missing})
		require.Error(t, err)
		require.Contains(t, err.Error(), missing)
		require.Empty(t, keys)
	})

	t.Run("directory errors", func(t *testing.T) {
		keys, err := readPrivateKeys([]string{dirTmp})
		require.Error(t, err)
		require.Empty(t, keys)
	})

	t.Run("two good paths return two elements in order", func(t *testing.T) {
		path1 := filepath.Join(dirTmp, "key1.pem")
		path2 := filepath.Join(dirTmp, "key2.pem")
		require.NoError(t, os.WriteFile(path1, []byte("key-one"), 0o600))
		require.NoError(t, os.WriteFile(path2, []byte("key-two"), 0o600))

		keys, err := readPrivateKeys([]string{path1, path2})
		require.NoError(t, err)
		require.Equal(t, [][]byte{[]byte("key-one"), []byte("key-two")}, keys)
	})
}
