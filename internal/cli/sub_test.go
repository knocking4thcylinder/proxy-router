package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/knocking4thcylinder/proxy-router/internal/config"
)

const hwidPlaceholder = "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&type=tcp&security=none#App%20not%20supported"

// A Remnawave-style panel serves a placeholder until the client sends
// x-hwid. updateSubscription must retry with a stable device ID, remember
// it, and use it on later updates without another round trip.
func TestUpdateSubscriptionRetriesWithHWID(t *testing.T) {
	var (
		mu    sync.Mutex
		hwids []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hwid := r.Header.Get("x-hwid")
		mu.Lock()
		hwids = append(hwids, hwid)
		mu.Unlock()
		if hwid == "" {
			w.Header().Set("x-hwid-not-supported", "true")
			w.Write([]byte(hwidPlaceholder))
			return
		}
		w.Write([]byte("vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls#real"))
	}))
	defer srv.Close()

	cfg, err := config.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := &config.State{}
	sub := &config.Subscription{URL: srv.URL, AllowHTTP: true}
	st.Subscriptions = []*config.Subscription{sub}
	e := &env{cfg: cfg, state: st}

	if err := e.updateSubscription(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]string(nil), hwids...)
	mu.Unlock()
	if len(got) != 2 || got[0] != "" || got[1] == "" {
		t.Fatalf("requests sent x-hwid %q, want an empty first request and an identified retry", got)
	}
	if got[1] != st.HWID {
		t.Errorf("retry used %q, want the state's HWID %q", got[1], st.HWID)
	}
	if !sub.SendHWID {
		t.Error("SendHWID not set; later updates would retry every time")
	}
	if len(sub.Servers) != 1 || sub.Servers[0].Name != "real" {
		t.Errorf("servers = %v, want the real subscription", sub.Servers)
	}

	// The requirement is remembered: one request, already identified.
	mu.Lock()
	hwids = nil
	mu.Unlock()
	if err := e.updateSubscription(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got = append([]string(nil), hwids...)
	mu.Unlock()
	if len(got) != 1 || got[0] != st.HWID {
		t.Fatalf("second update sent x-hwid %q, want [%q]", got, st.HWID)
	}
}

func TestUpdateSubscriptionDeviceLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-hwid-max-devices-reached", "true")
		w.Write([]byte(hwidPlaceholder))
	}))
	defer srv.Close()

	cfg, err := config.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := &config.State{}
	sub := &config.Subscription{URL: srv.URL, AllowHTTP: true, SendHWID: true}
	st.Subscriptions = []*config.Subscription{sub}
	e := &env{cfg: cfg, state: st}

	err = e.updateSubscription(context.Background(), sub)
	if err == nil || !strings.Contains(err.Error(), "device limit") {
		t.Fatalf("err = %v, want a device limit error", err)
	}
}
