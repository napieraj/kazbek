package fixtures

// Self-tests for the RM4PE mock. They assert the firmware behaviours the mock
// claims to model, so that a later edit that "simplifies" the mux or the port
// numbering fails here instead of silently making every port-scope test
// meaningless.

import (
	"errors"
	"testing"
)

func TestPortIdentityMatchesFirmware(t *testing.T) {
	// sysfs_device.py:572 / state.py:229 — external id is "1.<channel+1>".
	for i, want := range map[int]string{0: "1.1", 1: "1.2", 2: "1.3", 3: "1.4"} {
		if got := PortIndex(i).ID(); got != want {
			t.Errorf("PortIndex(%d).ID() = %q, want %q", i, got, want)
		}
	}
	// The firmware formats an unknown active port the same way, producing
	// "1.0". The mock reproduces that rather than tidying it.
	if got := PortNone.ID(); got != "1.0" {
		t.Errorf("PortNone.ID() = %q, want %q (sysfs_device.py:572 does not special-case -1)", got, "1.0")
	}
	if PortNone.Valid() || PortIndex(PortCount).Valid() {
		t.Errorf("out-of-range channels must be invalid (sysfs_device.py:386 validates 0..3)")
	}
}

func TestTranslatePortMatchesFirmware(t *testing.T) {
	// sysfs_chain.py:50-56 — (unit-1)*4 + (ch-1), each clamped at 0.
	cases := []struct {
		unit, ch int
		want     PortIndex
	}{
		{1, 1, 0}, {1, 4, 3}, {2, 1, 4}, {2, 4, 7}, {0, 0, 0},
	}
	for _, c := range cases {
		if got := TranslatePort(c.unit, c.ch); got != c.want {
			t.Errorf("TranslatePort(%d, %d) = %d, want %d", c.unit, c.ch, got, c.want)
		}
	}
	// A bare integer is already a flat index (sysfs_chain.py:51-52).
	if p, err := ParsePortRef("2"); err != nil || p != 2 {
		t.Errorf(`ParsePortRef("2") = %d, %v; want 2, nil`, p, err)
	}
	if p, err := ParsePortRef("1.3"); err != nil || p != 2 {
		t.Errorf(`ParsePortRef("1.3") = %d, %v; want 2, nil`, p, err)
	}
}

func TestMuxIsDeviceGlobalAndVideoFollowsIt(t *testing.T) {
	d := NewRM4PE("kvm-1").SeedAllLinksUp()

	// Nothing selected yet: sysfs_device.py:62 starts at -1.
	if _, err := d.PullVideoFrame(); !errors.Is(err, ErrNoActivePort) {
		t.Fatalf("pull with no active channel = %v, want ErrNoActivePort", err)
	}
	if got := d.State().Summary.ActiveID; got != "1.0" {
		t.Errorf("unset active id = %q, want %q", got, "1.0")
	}

	if err := d.SetActivePort(0); err != nil {
		t.Fatalf("SetActivePort(0): %v", err)
	}
	f, err := d.PullVideoFrame()
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if f.Port != 0 {
		t.Errorf("frame from %s, want %s", f.Port, PortIndex(0))
	}

	// A second session moves the one mux; the first session's stream now
	// carries a different host's console. This is the fact that makes
	// port-scoped video enforcement load-bearing (sysfs_device.py:262-271).
	if err := d.SetActivePort(2); err != nil {
		t.Fatalf("SetActivePort(2): %v", err)
	}
	f, err = d.PullVideoFrame()
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if f.Port != 2 {
		t.Errorf("after a device-global switch the frame came from %s, want %s", f.Port, PortIndex(2))
	}
	if !d.Served(2) {
		t.Errorf("device should record having served channel 1.3")
	}
}

func TestInvalidChannelRejected(t *testing.T) {
	d := NewRM4PE("kvm-1")
	if err := d.SetActivePort(PortCount); !errors.Is(err, ErrInvalidPort) {
		t.Errorf("SetActivePort(%d) = %v, want ErrInvalidPort (sysfs_device.py:386)", PortCount, err)
	}
	if err := d.ATX(-1, ATXPowerOffHard); !errors.Is(err, ErrInvalidPort) {
		t.Errorf("ATX(-1) = %v, want ErrInvalidPort", err)
	}
	// A rejected call is still recorded, with its error: a test asserting
	// "port 3 was never reached" must not be fooled by a failed attempt.
	if n := d.CallCount(); n != 2 {
		t.Errorf("rejected calls recorded = %d, want 2", n)
	}
	if d.Served(PortCount) {
		t.Errorf("a rejected call must not count as served")
	}
}

func TestATXIsPerPortAndInertOnThisChain(t *testing.T) {
	d := NewRM4PE("kvm-1").SeedActivePort(0)
	if err := d.ATX(3, ATXPowerOffHard); err != nil {
		t.Fatalf("ATX(3): %v", err)
	}
	calls := d.Calls()
	last := calls[len(calls)-1]
	if last.Op != OpATX || last.Port != 3 {
		t.Fatalf("ATX recorded as %v on %s, want %v on %s", last.Op, last.Port, OpATX, PortIndex(3))
	}
	// sysfs_chain.py:117-121 / sysfs_device.py:609-613: accepted, does nothing.
	if !last.Inert {
		t.Errorf("ATX on the sysfs chain is a no-op stub and must be recorded Inert")
	}
	// ATX is addressed to a named port and does NOT move the mux.
	if d.ActivePort() != 0 {
		t.Errorf("ATX on 1.4 changed the active channel to %s; it must not", d.ActivePort())
	}
}

func TestSetPortParamsTouchesOnlyItsPort(t *testing.T) {
	d := NewRM4PE("kvm-1")
	name := "renamed"
	if err := d.SetPortParams(1, PortParams{Name: &name}); err != nil {
		t.Fatalf("SetPortParams: %v", err)
	}
	st := d.State()
	if st.Ports[1].Name != name {
		t.Errorf("port 1.2 name = %q, want %q", st.Ports[1].Name, name)
	}
	for _, other := range []int{0, 2, 3} {
		if st.Ports[other].Name != "" {
			t.Errorf("port %s name = %q, want empty: set_port_params is per port (switch/__init__.py:259-289)",
				PortIndex(other).ID(), st.Ports[other].Name)
		}
	}
}

func TestRebootUnitUnsupported(t *testing.T) {
	d := NewRM4PE("kvm-1")
	if err := d.RebootUnit(false); !errors.Is(err, ErrUnsupported) {
		t.Errorf("RebootUnit = %v, want ErrUnsupported (sysfs_chain.py:123-124)", err)
	}
}

func TestActiveChannelSurvivesReboot(t *testing.T) {
	d := NewRM4PE("kvm-1").SeedAllLinksUp()
	if err := d.SetActivePort(2); err != nil {
		t.Fatalf("SetActivePort: %v", err)
	}
	d.SimulateReboot()
	if got := d.ActivePort(); got != 2 {
		t.Errorf("after reboot active channel = %s, want %s: the channel is persisted to "+
			"/etc/kvmd/channel.conf and restored (sysfs_device.py:361-366, :321-351)", got, PortIndex(2))
	}
}

func TestStateDocumentShape(t *testing.T) {
	d := NewRM4PE("kvm-1").SeedActivePort(1).SeedVideoLink(0, true).SeedUSBLink(3, true)
	st := d.State()
	if st.Summary.ActivePort != 1 || st.Summary.ActiveID != "1.2" || !st.Summary.Synced {
		t.Errorf("summary = %+v, want active 1 / \"1.2\" / synced (sysfs_device.py:569-574)", st.Summary)
	}
	if len(st.Ports) != PortCount {
		t.Fatalf("state carries %d ports, want %d", len(st.Ports), PortCount)
	}
	for i, p := range st.Ports {
		if p.Unit != 0 || p.Channel != i || p.ID != PortIndex(i).ID() {
			t.Errorf("port %d = %+v, want unit 0 / channel %d / id %q (state.py:224-231)",
				i, p, i, PortIndex(i).ID())
		}
	}
	if !st.VideoLinks[0] || st.VideoLinks[1] {
		t.Errorf("video links = %v, want only channel 0 up (sysfs_device.py:499-515)", st.VideoLinks)
	}
	if !st.USBLinks[3] || st.USBLinks[0] {
		t.Errorf("usb links = %v, want only channel 3 up (sysfs_device.py:520-535)", st.USBLinks)
	}
}

func TestSnapshotRestoreRewindsStateAndLog(t *testing.T) {
	d := NewRM4PE("kvm-1").SeedActivePort(0)
	snap := d.Snapshot()
	if err := d.SetActivePort(3); err != nil {
		t.Fatalf("SetActivePort: %v", err)
	}
	if _, err := d.PullVideoFrame(); err != nil {
		t.Fatalf("pull: %v", err)
	}
	d.Restore(snap)
	if d.ActivePort() != 0 {
		t.Errorf("restore left active channel at %s, want %s", d.ActivePort(), PortIndex(0))
	}
	if n := d.CallCount(); n != 0 {
		t.Errorf("restore left %d calls in the log, want 0", n)
	}
}
