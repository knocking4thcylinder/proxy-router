package cli

import "github.com/knocking4thcylinder/proxy-router/internal/update"

// Channel is the release channel this build was made for. Release builds
// set it with -ldflags "-X .../internal/cli.Channel=nightly"; stable builds
// and local builds stay on stable.
var Channel = update.StableChannel

// buildChannel is the channel this binary follows when auto_update.channel
// is "auto".
func buildChannel() string {
	if Channel == update.NightlyChannel {
		return update.NightlyChannel
	}
	return update.StableChannel
}

// updateChannel resolves auto_update.channel. "auto" (or anything else)
// follows the build, so installing a nightly once keeps updating from the
// nightly channel.
func updateChannel(configured string) string {
	switch configured {
	case update.NightlyChannel:
		return update.NightlyChannel
	case update.StableChannel:
		return update.StableChannel
	default:
		return buildChannel()
	}
}
