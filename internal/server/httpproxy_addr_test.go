package server

import "testing"

// The /web proxy destination must be the device itself. The connection is
// opened by the device, so an off-device address turns this route into an SSRF
// primitive pointed at the managed segment — the segment docs/THREAT-MODEL.md
// relies on being isolated.
//
// MUTATION CHECK (AGENTS.md rule 4): delete the ip.IsLoopback() guard in
// httpProxyVaildAddr and the "off-device" cases below go red. If they do not,
// the guard is dead and this test is not holding it down.
func TestHTTPProxyAddrIsLoopbackOnly(t *testing.T) {
	onDevice := []string{
		"127.0.0.1:443", // what the console actually uses (handleRemoteControl)
		"127.0.0.1:80",
		"127.0.0.1", // no port -> defaults to 80
		"127.1.2.3:8080",
	}
	for _, addr := range onDevice {
		if _, _, err := httpProxyVaildAddr(addr); err != nil {
			t.Errorf("on-device addr %q rejected: %v", addr, err)
		}
	}

	offDevice := []string{
		"10.0.0.9:443",   // managed segment
		"192.168.1.1:80", // the U-Boot failsafe address from migration.md
		"172.16.4.4:22",
		"8.8.8.8:53",         // egress
		"169.254.169.254:80", // cloud metadata
		"0.0.0.0:80",
	}
	for _, addr := range offDevice {
		if _, _, err := httpProxyVaildAddr(addr); err == nil {
			t.Errorf("off-device addr %q ACCEPTED — the proxy reaches the managed segment", addr)
		}
	}

	// Still rejects what it always rejected.
	for _, addr := range []string{"not-an-ip:80", "::1", "example.com:443"} {
		if _, _, err := httpProxyVaildAddr(addr); err == nil {
			t.Errorf("malformed/non-IPv4 addr %q accepted", addr)
		}
	}
}
