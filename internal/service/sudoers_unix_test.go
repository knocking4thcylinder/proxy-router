//go:build darwin || linux

package service

import "testing"

func TestSudoersPossible(t *testing.T) {
	ok := [][]string{{"--dir", "/home/alice/.config/proxy-router", "--uid", "1000", "start", "--tun"}}
	if !SudoersPossible(ok) {
		t.Error("a plain config path isn't allowed")
	}
	for _, dir := range []string{"/home/alice/My Config", "/home/alice/x*", "/home/alice/x,y"} {
		args := [][]string{{"--dir", dir, "--uid", "1000", "start", "--tun"}}
		if SudoersPossible(args) {
			t.Errorf("%q would be written into a rule", dir)
		}
	}
}
