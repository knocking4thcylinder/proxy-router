package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/knocking4thcylinder/proxy-router/internal/service"
	"github.com/knocking4thcylinder/proxy-router/internal/update"
)

func TestManualUpdateDowngradeSelection(t *testing.T) {
	if _, _, ok := update.AssetName(runtime.GOOS, runtime.GOARCH); !ok {
		t.Skip("no releases for this platform")
	}
	oldVersion, oldChannel := Version, Channel
	t.Cleanup(func() { Version, Channel = oldVersion, oldChannel })
	Version, Channel = "v0.1.3-nightly.20261118.42.abc1234", update.NightlyChannel

	for _, tt := range []struct {
		name, want, channel, endpoint string
		check, force                  bool
		wantError                     string
	}{
		{name: "stable argument", want: "stable", endpoint: "latest", wantError: "doesn't include"},
		{name: "stable flag", channel: "stable", endpoint: "latest", wantError: "doesn't include"},
		{name: "forced pin", want: "v0.1.2", endpoint: "tags/v0.1.2", force: true, wantError: "doesn't include"},
		{name: "unforced pin", want: "v0.1.2", endpoint: "tags/v0.1.2", wantError: "use --force to downgrade"},
		{name: "check only", want: "stable", endpoint: "latest", check: true, force: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/"+update.Repo+"/releases/"+tt.endpoint {
					http.NotFound(w, r)
					return
				}
				// With no assets, an accepted update reaches installation
				// and fails before touching any executable or service.
				fmt.Fprint(w, `{"tag_name":"v0.1.2"}`)
			}))
			defer srv.Close()
			err := runUpdate(tt.want, tt.channel, tt.check, tt.force, &update.Client{API: srv.URL})
			if tt.wantError == "" && err == nil {
				return
			}
			if tt.wantError == "" || err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("runUpdate error = %v, want %q", err, tt.wantError)
			}
		})
	}
}

func TestServiceUpdateChecksPublishedVersion(t *testing.T) {
	const nightly = "v0.1.3-nightly.5"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/"+update.Repo+"/releases/tags/nightly" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"tag_name":"nightly","name":%q}`, nightly)
	}))
	defer srv.Close()
	client := &update.Client{API: srv.URL}
	if _, err := serviceRelease(t.Context(), client, "nightly", nightly); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"nightly", "/tmp/local-build"} {
		if _, err := serviceRelease(t.Context(), client, tag, "v0.1.3-nightly.4"); err == nil {
			t.Fatalf("accepted %q for the previous nightly", tag)
		}
	}
}

func TestApplyManualServiceUpdate(t *testing.T) {
	const stable = "v0.1.2"
	const nightly = "v0.1.3-nightly.20261118.42.abc1234"
	errCopy, errRestart := errors.New("copy failed"), errors.New("restart failed")
	for _, tt := range []struct {
		name                string
		scope               service.Scope
		status              service.Status
		allowDowngrade      bool
		copyErr, restartErr error
		wantCalls           []string
	}{
		{
			name: "channel switch restarts the running user service", scope: service.User,
			status: service.Status{Installed: true, Running: true, Enabled: true}, allowDowngrade: true,
			wantCalls: []string{"copy", "restart"},
		},
		{
			name: "forced downgrade restarts the running system service", scope: service.System,
			status: service.Status{Installed: true, Running: true}, allowDowngrade: true,
			wantCalls: []string{"copy", "restart"},
		},
		{
			name: "stopped system service stays stopped", scope: service.System,
			status: service.Status{Installed: true}, allowDowngrade: true, wantCalls: []string{"copy"},
		},
		{
			name: "inactive enabled user service stays inactive", scope: service.User,
			status: service.Status{Installed: true, Enabled: true}, allowDowngrade: true, wantCalls: []string{"copy"},
		},
		{
			name: "ordinary update keeps a newer service build", scope: service.User,
			status: service.Status{Installed: true, Running: true},
		},
		{
			name: "copy failure leaves the running service alone", scope: service.System,
			status: service.Status{Installed: true, Running: true}, allowDowngrade: true,
			copyErr: errCopy, wantCalls: []string{"copy"},
		},
		{
			name: "restart failure propagates", scope: service.User,
			status: service.Status{Installed: true, Running: true}, allowDowngrade: true,
			restartErr: errRestart, wantCalls: []string{"copy", "restart"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			target := service.Target{Scope: tt.scope}
			rel := manualRelease{version: stable, source: "/staged/proxy-router", allowDowngrade: tt.allowDowngrade}
			var calls []string
			err := rel.apply(target, tt.status, nightly, func(got service.Target, source string) error {
				calls = append(calls, "copy")
				if got != target || source != rel.source {
					t.Errorf("copy target = %+v, source = %q", got, source)
				}
				return tt.copyErr
			}, func(got service.Target) error {
				calls = append(calls, "restart")
				if got != target {
					t.Errorf("restart target = %+v, want %+v", got, target)
				}
				return tt.restartErr
			})
			wantErr := tt.copyErr
			if wantErr == nil {
				wantErr = tt.restartErr
			}
			if !errors.Is(err, wantErr) {
				t.Errorf("apply error = %v, want %v", err, wantErr)
			}
			if !slices.Equal(calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", calls, tt.wantCalls)
			}
		})
	}
}
