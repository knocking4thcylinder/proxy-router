package secpath

import "io/fs"

// Windows has no root to protect; nothing passes the check.
func ownerOf(fs.FileInfo) (int, bool) { return 0, false }
