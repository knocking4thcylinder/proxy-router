package engine

// MarkSockets sets SO_MARK (sockopt.mark) on every outbound in an Xray
// config, so a firewall can tell proxy-router's own connections apart: the
// TUN kill switch lets them out of the physical interface. It overrides a
// mark an imported outbound brought along. 0 leaves the config alone.
// Only Linux has socket marks.
func MarkSockets(xc map[string]any, mark int) {
	if mark == 0 {
		return
	}
	var obs []map[string]any
	switch v := xc["outbounds"].(type) {
	case []map[string]any:
		obs = v
	case []any:
		for _, o := range v {
			if m, ok := o.(map[string]any); ok {
				obs = append(obs, m)
			}
		}
	}
	for _, ob := range obs {
		ss, _ := ob["streamSettings"].(map[string]any)
		if ss == nil {
			ss = map[string]any{}
			ob["streamSettings"] = ss
		}
		so, _ := ss["sockopt"].(map[string]any)
		if so == nil {
			so = map[string]any{}
			ss["sockopt"] = so
		}
		so["mark"] = mark
	}
}
