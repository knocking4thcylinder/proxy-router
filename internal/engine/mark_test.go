package engine

import "testing"

func TestMarkSockets(t *testing.T) {
	xc := map[string]any{"outbounds": []map[string]any{
		{"tag": "proxy", "streamSettings": map[string]any{"sockopt": map[string]any{"interface": "en0", "mark": 1}}},
		{"tag": "direct", "protocol": "freedom"},
	}}
	MarkSockets(xc, 0x7072)
	for _, ob := range xc["outbounds"].([]map[string]any) {
		so := ob["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
		if so["mark"] != 0x7072 {
			t.Fatalf("%s: %v", ob["tag"], so)
		}
	}
	if so := xc["outbounds"].([]map[string]any)[0]["streamSettings"].(map[string]any)["sockopt"].(map[string]any); so["interface"] != "en0" {
		t.Fatalf("lost the interface: %v", so)
	}

	plain := map[string]any{"outbounds": []any{map[string]any{"tag": "direct"}}}
	MarkSockets(plain, 0)
	if _, ok := plain["outbounds"].([]any)[0].(map[string]any)["streamSettings"]; ok {
		t.Fatal("mark 0 changed the config")
	}
	MarkSockets(plain, 5)
	if plain["outbounds"].([]any)[0].(map[string]any)["streamSettings"] == nil {
		t.Fatal("[]any outbounds not marked")
	}
}
