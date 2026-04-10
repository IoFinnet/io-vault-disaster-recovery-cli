// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package fileutils

import "os"

// PermissionOwnerRW is the file mode granting only the owner read/write access.
const PermissionOwnerRW os.FileMode = 0600
