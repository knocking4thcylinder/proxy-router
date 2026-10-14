//go:build !darwin && !linux

package service

func DefinitionPath(t Target) string { return "" }
func BinaryPath(t Target) string     { return "" }
func Definition(s Spec) []byte       { return nil }

func Install(s Spec) error           { return ErrUnsupported }
func Stop(t Target) error            { return ErrUnsupported }
func Remove(t Target) error          { return ErrUnsupported }
func Query(t Target) (Status, error) { return Status{}, ErrUnsupported }
