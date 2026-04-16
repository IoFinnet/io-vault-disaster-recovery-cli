// Copyright (C) 2026 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package fileutils

import (
	"errors"
	"io/fs"
	"path/filepath"
)

func StripPathFromError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return &fs.PathError{
			Op:   pathErr.Op,
			Path: filepath.Base(pathErr.Path),
			Err:  pathErr.Err,
		}
	}
	return err
}
