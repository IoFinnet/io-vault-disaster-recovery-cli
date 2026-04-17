// Copyright (C) 2026 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package fileutils

import (
	"errors"
	errors2 "github.com/pkg/errors"
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

// PermissionOwnerRW is the file mode granting only the owner read/write access.
const PermissionOwnerRW os.FileMode = 0600

func WriteToNewFile(filename string, data []byte, perm os.FileMode) error {
	// O_CREATE will create a new file if one doesn’t exist already
	// O_EXCL means the file must not exist already
	// O_WRONLY means you’re opening the file as write-only
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		if os.IsExist(err) {
			return errors2.Errorf("file already exists: %s", filename)
		} else {
			return errors2.Errorf("failed creating file: %s: %v", filename, err)
		}
	}
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		return errors2.Errorf("failed writing to file: %s: %v", filename, err)
	}
	return nil
}
