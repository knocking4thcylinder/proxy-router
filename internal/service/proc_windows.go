package service

// Alive isn't needed on Windows, which has no service support.
func Alive(pid int) bool { return false }
