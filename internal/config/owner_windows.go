package config

type ids struct{ uid, gid int }

func statOwner(path string) (ids, bool) { return ids{}, false }
