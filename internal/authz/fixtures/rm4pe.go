package fixtures

// rm4pe.go — a mock of the RM4PE 4-port switch, for port-scope authorization
// tests (D-009: scope may be a port on a multi-channel device).
//
// NOT provisional. Every behaviour below is modelled on the shipping firmware
// in the glkvm-debloat tree and cites the file:line it was read from. Paths are
// relative to the firmware repo root (glkvm-debloat/). Re-derive before
// trusting these citations (AGENTS.md rule 1) — they were read against the
// working tree, not copied from a doc.
//
// Why a mock and not a stub: a test asserting "a grant on port 1 does not
// reach port 3" is worthless against a hand-waved stub that has no notion of
// which port an operation touched. This mock records, per call, exactly which
// channel the device served, and it reproduces the two hardware facts that
// make port scoping hard:
//
//   - There is ONE video/USB mux with ONE active channel, device-global. Video
//     and HID are NOT addressable per port: you get whatever channel is active.
//     A capability check that authorises "view port 1" and then pulls a frame
//     without binding the stream to port 1 hands the caller port 3's screen.
//   - Switching the active channel is a whole-device operation. It changes what
//     every other session sees, and it persists across reboot.
//
// Firmware facts, with citations:
//
//	4 channels                     kvmd/apps/kvmd/switch/sysfs_device.py:26
//	                               kvmd/apps/kvmd/switch/sysfs_chain.py:33
//	channel index range 0..3       kvmd/apps/kvmd/switch/sysfs_device.py:386
//	                               kvmd/apps/kvmd/switch/sysfs_chain.py:71
//	external port id "1.N"         kvmd/apps/kvmd/switch/sysfs_device.py:572
//	                               kvmd/apps/kvmd/switch/state.py:189, :229
//	unit.channel -> flat index     kvmd/apps/kvmd/switch/sysfs_chain.py:50-56
//	single active channel written  kvmd/apps/kvmd/switch/sysfs_device.py:262-271
//	active port is device-global   kvmd/apps/kvmd/switch/sysfs_device.py:569-574
//	switch serialised by a lock    kvmd/apps/kvmd/switch/sysfs_device.py:593-595
//	HID suspended across a switch  kvmd/apps/kvmd/switch/sysfs_device.py:462-464, :490-491
//	channel persisted + restored   kvmd/apps/kvmd/switch/sysfs_device.py:361-366, :353-359, :321-351
//	per-port HDMI link sense       kvmd/apps/kvmd/switch/sysfs_device.py:499-515
//	per-port USB-OTG link sense    kvmd/apps/kvmd/switch/sysfs_device.py:520-535
//	per-port params (edid/dummy/
//	  name/atx delays)             kvmd/apps/kvmd/switch/__init__.py:259-289
//	                               kvmd/apps/kvmd/api/switch.py:86-102
//	per-port ATX ops               kvmd/apps/kvmd/switch/__init__.py:174-204
//	                               kvmd/apps/kvmd/api/switch.py:155-176
//	ATX inert on this sysfs chain  kvmd/apps/kvmd/switch/sysfs_chain.py:117-121
//	                               kvmd/apps/kvmd/switch/sysfs_device.py:609-613
//	unit reboot unsupported        kvmd/apps/kvmd/switch/sysfs_chain.py:123-124
//	                               kvmd/apps/kvmd/switch/sysfs_device.py:600-601
//	whole-device colours           kvmd/apps/kvmd/switch/__init__.py:244-255
//	switch only exists on rm4pe    kvmd/apps/kvmd/__init__.py:94-100

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// TranslatePort maps a 1-based (unit, channel) pair to a flat channel index.
//
// sysfs_chain.py:50-56 — `unit = max(unit - 1, 0); ch = max(ch - 1, 0);
// return unit * 4 + ch`. The clamping to 0 is the firmware's, reproduced here
// on purpose: "0.0" does not error, it silently means channel 0.
func TranslatePort(unit, channel int) PortIndex {
	if unit > 0 {
		unit--
	} else {
		unit = 0
	}
	if channel > 0 {
		channel--
	} else {
		channel = 0
	}
	return PortIndex(unit*4 + channel)
}

// ParsePortRef parses the port argument the switch API accepts.
//
// sysfs_chain.py:50-53: a bare integer is already a flat index; a value with a
// dot is "unit.channel", both 1-based. api/switch.py:68 passes it through
// valid_float_f0, so "1.3" arrives as a float.
func ParsePortRef(s string) (PortIndex, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return PortNone, fmt.Errorf("fixtures: empty port ref")
	}
	if !strings.Contains(s, ".") {
		n, err := strconv.Atoi(s)
		if err != nil {
			return PortNone, fmt.Errorf("fixtures: bad port ref %q: %w", s, err)
		}
		return PortIndex(n), nil
	}
	parts := strings.SplitN(s, ".", 2)
	unit, err := strconv.Atoi(parts[0])
	if err != nil {
		return PortNone, fmt.Errorf("fixtures: bad unit in port ref %q: %w", s, err)
	}
	ch, err := strconv.Atoi(parts[1])
	if err != nil {
		return PortNone, fmt.Errorf("fixtures: bad channel in port ref %q: %w", s, err)
	}
	return TranslatePort(unit, ch), nil
}

// Device-level errors the mock can return.
var (
	// ErrInvalidPort mirrors sysfs_device.py:386-387
	// `raise ValueError(f"invalid channel: {ch}")`.
	ErrInvalidPort = errors.New("rm4pe: invalid channel")

	// ErrNoActivePort is returned when video/HID is pulled before any channel
	// has been selected (sysfs_device.py:62, active port starts at -1).
	ErrNoActivePort = errors.New("rm4pe: no active channel")

	// ErrHIDSuspended mirrors the HID suspend flag the firmware raises for the
	// duration of a channel switch (sysfs_device.py:462-464).
	ErrHIDSuspended = errors.New("rm4pe: HID suspended during channel switch")

	// ErrUnsupported mirrors sysfs_chain.py:123-124 / sysfs_device.py:600-601
	// `raise DeviceError("Reboot not supported via sysfs")`.
	ErrUnsupported = errors.New("rm4pe: operation not supported on the sysfs chain")
)

// Op names a device operation. The authorization core will map capabilities to
// these; the mapping is the core's business, not the fixture's.
type Op string

const (
	OpSetActivePort Op = "switch.set_active"      // api/switch.py:66-70
	OpPullVideo     Op = "video.pull"             // follows the mux, not a port argument
	OpHIDInput      Op = "hid.input"              // follows the mux, not a port argument
	OpATX           Op = "switch.atx"             // api/switch.py:155-176, per port
	OpSetPortParams Op = "switch.set_port_params" // api/switch.py:86-102, per port
	OpMagicChord    Op = "hid.magic-chord"        // vnc/server.py:373, localhid/server.py:179
	OpReadState     Op = "switch.state"           // api/switch.py:52-54, whole device
	OpRebootUnit    Op = "switch.reset"           // api/switch.py:116-121, whole device
	OpSetColors     Op = "switch.set_colors"      // api/switch.py:104-112, whole device
)

// PerPort reports whether the operation takes a port argument on the real
// device. Whole-device operations cannot be port-scoped: a grant scoped to a
// port must never authorise one of these.
func (o Op) PerPort() bool {
	switch o {
	case OpSetPortParams, OpATX:
		return true
	case OpSetActivePort:
		// Takes a port argument, but its EFFECT is device-global: it moves the
		// one mux for every session. Treated as whole-device on purpose — see
		// RM4PE.SetActivePort.
		return false
	default:
		return false
	}
}

// ATXAction is one of the ATX operations the switch API exposes.
//
// api/switch.py:159-164 (power on/off/off_hard/reset_hard) and :171-175
// (click power/power_long/reset).
type ATXAction string

const (
	ATXPowerOn        ATXAction = "on"
	ATXPowerOff       ATXAction = "off"
	ATXPowerOffHard   ATXAction = "off_hard"
	ATXPowerResetHard ATXAction = "reset_hard"
	ATXClickPower     ATXAction = "click.power"
	ATXClickPowerLong ATXAction = "click.power_long"
	ATXClickReset     ATXAction = "click.reset"
)

// ATXClickDelays are the per-port click delays (state.py:230-236).
type ATXClickDelays struct {
	Power     float64
	PowerLong float64
	Reset     float64
}

// PortState is the per-channel state the firmware keeps.
//
// Link senses: sysfs_device.py:499-515 (HDMI) and :520-535 (USB-OTG), both
// returning a per-channel dict. Params: switch/__init__.py:259-289.
type PortState struct {
	VideoLink bool // HDMI "Connected" on this channel
	USBLink   bool // USB-OTG "Connected" on this channel
	Name      string
	Dummy     bool
	EDIDID    string
	ATXDelays ATXClickDelays
}

// PortParams is the argument set of POST /switch/set_port_params
// (api/switch.py:89-100). A nil field means "leave alone", matching the
// firmware, which only applies parameters actually present in the query.
type PortParams struct {
	EDIDID             *string
	Dummy              *bool
	Name               *string
	ATXClickPowerDelay *float64
	ATXClickPowerLong  *float64
	ATXClickResetDelay *float64
}

// Call is one operation the device was asked to perform. The call log is the
// evidence a port-isolation test asserts on: it records which channel was
// actually served, which for video and HID is the ACTIVE channel and not any
// port the caller named.
type Call struct {
	Op     Op
	Port   PortIndex // channel actually served; PortNone for whole-device ops
	Detail string
	Err    error
	Inert  bool // the firmware accepts the call but the sysfs chain does nothing
}

// Frame is one video frame pulled off the mux.
type Frame struct {
	Port      PortIndex // the ACTIVE channel — never a port the caller asked for
	HasSignal bool      // that channel's HDMI link sense
	Seq       int
}

// DeviceSummary mirrors state["summary"] (sysfs_device.py:569-574).
type DeviceSummary struct {
	ActivePort int
	ActiveID   string
	Synced     bool
}

// PortModel mirrors one entry of state["model"]["ports"] (state.py:224-240).
type PortModel struct {
	Unit           int
	Channel        int
	ID             string
	Name           string
	Dummy          bool
	ATXClickDelays ATXClickDelays
}

// DeviceState mirrors the switch state document (state.py:154-240,
// sysfs_device.py:565-583).
type DeviceState struct {
	Summary    DeviceSummary
	VideoLinks [PortCount]bool
	USBLinks   [PortCount]bool
	Ports      [PortCount]PortModel
}

// RM4PE is the mock. It is safe for concurrent use: the firmware serialises
// channel switches behind an asyncio lock (sysfs_device.py:593-595), and a
// harness that drives two sessions at once must not race on the call log.
type RM4PE struct {
	mu           sync.Mutex
	id           string
	ports        [PortCount]PortState
	active       PortIndex
	saved        PortIndex // /etc/kvmd/channel.conf, sysfs_device.py:361-366
	hidSuspended bool
	seq          int
	calls        []Call
}

// NewRM4PE returns a device with no active channel, matching a freshly
// constructed firmware Device (sysfs_device.py:62 `__active_port = -1`) with no
// persisted channel to restore (sysfs_device.py:353-359 returns None when
// /etc/kvmd/channel.conf is absent).
func NewRM4PE(id string) *RM4PE {
	return &RM4PE{id: id, active: PortNone, saved: PortNone}
}

// ID is the kazbek-side device id this mock stands for.
func (d *RM4PE) ID() string { return d.id }

// Ports returns the number of channels. Constant on this hardware.
func (d *RM4PE) Ports() int { return PortCount }

// ---------- seeding (setup helpers; they do NOT appear in the call log) ----------

// SeedActivePort sets the active channel without recording an operation, for
// arranging a test's starting conditions.
func (d *RM4PE) SeedActivePort(p PortIndex) *RM4PE {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.active, d.saved = p, p
	return d
}

// SeedVideoLink sets a channel's HDMI link sense (sysfs_device.py:499-515).
func (d *RM4PE) SeedVideoLink(p PortIndex, up bool) *RM4PE {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p.Valid() {
		d.ports[p].VideoLink = up
	}
	return d
}

// SeedUSBLink sets a channel's USB-OTG link sense (sysfs_device.py:520-535).
func (d *RM4PE) SeedUSBLink(p PortIndex, up bool) *RM4PE {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p.Valid() {
		d.ports[p].USBLink = up
	}
	return d
}

// SeedPortName sets a channel's name (switch/__init__.py:125-128).
func (d *RM4PE) SeedPortName(p PortIndex, name string) *RM4PE {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p.Valid() {
		d.ports[p].Name = name
	}
	return d
}

// SeedAllLinksUp marks every channel as having both HDMI and USB connected —
// the worst case for a port-isolation test, because nothing about the physical
// state stops a wrongly-authorised session from getting a picture.
func (d *RM4PE) SeedAllLinksUp() *RM4PE {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.ports {
		d.ports[i].VideoLink = true
		d.ports[i].USBLink = true
	}
	return d
}

// ---------- operations ----------

// ActivePort returns the current channel without recording an operation.
func (d *RM4PE) ActivePort() PortIndex {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.active
}

// SetActivePort moves the one video/USB mux.
//
// This is the operation that makes port scoping load-bearing. Although it
// takes a port argument, its effect is DEVICE-GLOBAL: sysfs_device.py:262-271
// writes a single channel value to /sys/.../channel and
// /sys/.../usb_host_channel, so the caller changes what every other session on
// this device sees. The firmware serialises it behind a lock
// (sysfs_device.py:593-595), suspends HID for the duration
// (sysfs_device.py:462-464, released at :490-491) and persists the new channel
// to /etc/kvmd/channel.conf (sysfs_device.py:451-453, :492-494) so it survives
// a reboot (:321-351).
//
// Authorization consequence a test should hold down: a subject granted a
// capability on port 1 only must NOT be able to call this for port 3 — and
// must not be able to call it for port 1 either unless the grant covers the
// device-global effect. Which of those the core chooses is the core's design
// call; the mock's job is to make the global effect visible.
func (d *RM4PE) SetActivePort(p PortIndex) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !p.Valid() {
		err := fmt.Errorf("%w: %d", ErrInvalidPort, int(p))
		d.record(Call{Op: OpSetActivePort, Port: p, Detail: "rejected", Err: err})
		return err
	}
	d.hidSuspended = true // sysfs_device.py:462-464
	d.active = p
	d.saved = p // sysfs_device.py:451-453 persists only after a real switch
	d.hidSuspended = false
	d.record(Call{Op: OpSetActivePort, Port: p, Detail: "mux moved (device-global)"})
	return nil
}

// SetActivePrev and SetActiveNext step the mux one channel.
//
// sysfs_chain.py:62-68 — they CLAMP at the ends rather than wrapping, and they
// are driven from Chain's own idea of the active port. Modelled because they
// are the operations the magic chord reaches (switch/__init__.py:147-151), and
// because "step to the next port" is a port-scope boundary crossing that a
// naive check on set_active(port=N) will not see.
func (d *RM4PE) SetActivePrev() error { return d.step(-1, "prev") }

// SetActiveNext steps the mux up one channel. See SetActivePrev.
func (d *RM4PE) SetActiveNext() error { return d.step(+1, "next") }

func (d *RM4PE) step(delta int, label string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	next := d.active + PortIndex(delta)
	if !d.active.Valid() || !next.Valid() {
		// sysfs_chain.py:62-68 guard and silently do nothing.
		d.record(Call{Op: OpSetActivePort, Port: PortNone, Detail: label + " (clamped, no-op)", Inert: true})
		return nil
	}
	d.active, d.saved = next, next
	d.record(Call{Op: OpSetActivePort, Port: next, Detail: label + " (mux moved, device-global)"})
	return nil
}

// MagicChordSwitch moves the mux from INSIDE a session, by keystroke.
//
// This is a port-isolation bypass path that exists in the shipping firmware:
// the VNC server and the local-HID daemon both watch for a magic chord and
// call switch.set_active_prev/next/port directly —
// vnc/server.py:361, :367, :373 and localhid/server.py:169, :174, :179, which
// land on switch/__init__.py:147-154. No HTTP request is made, so a capability
// check installed on POST /switch/set_active (api/switch.py:66-70) is NOT on
// this path.
//
// The mock cannot refuse it — it has no authorization, and neither does the
// hardware. That is the point: a subject holding hid.input on one port can
// type its way to another unless the HID path itself carries an interlock. A
// test asserts that the interlock exists by asking the engine at PointHID
// before calling this, and failing if the engine allows.
func (d *RM4PE) MagicChordSwitch(p PortIndex) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !p.Valid() {
		err := fmt.Errorf("%w: %d", ErrInvalidPort, int(p))
		d.record(Call{Op: OpMagicChord, Port: p, Err: err})
		return err
	}
	d.active, d.saved = p, p
	d.record(Call{Op: OpMagicChord, Port: p, Detail: "mux moved by keystroke, no HTTP request"})
	return nil
}

// PullVideoFrame takes one frame off the streamer.
//
// There is no port argument, and that is the whole point. The streamer is fed
// by the mux, so the frame belongs to whatever channel is active
// (sysfs_device.py:262-271 for the mux write, :569-574 for the single
// active_port in the state document). A capability check that says "view is
// allowed on port 1" and then lets the session pull a frame while channel 3 is
// active has leaked port 3's console.
//
// This is also the bypass surface from docs/modules/permissions.md: hiding the
// button is not enforcing the permission — the stream endpoint must itself
// refuse.
func (d *RM4PE) PullVideoFrame() (Frame, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.active.Valid() {
		d.record(Call{Op: OpPullVideo, Port: PortNone, Err: ErrNoActivePort})
		return Frame{Port: PortNone}, ErrNoActivePort
	}
	d.seq++
	f := Frame{Port: d.active, HasSignal: d.ports[d.active].VideoLink, Seq: d.seq}
	d.record(Call{Op: OpPullVideo, Port: d.active, Detail: "served active channel"})
	return f, nil
}

// SendHIDInput delivers keyboard/mouse input.
//
// Like video, HID follows the mux and takes no port argument; the gadget is
// suspended while a channel switch is in flight (sysfs_device.py:462-464).
func (d *RM4PE) SendHIDInput(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.hidSuspended {
		d.record(Call{Op: OpHIDInput, Port: d.active, Err: ErrHIDSuspended})
		return ErrHIDSuspended
	}
	if !d.active.Valid() {
		d.record(Call{Op: OpHIDInput, Port: PortNone, Err: ErrNoActivePort})
		return ErrNoActivePort
	}
	d.record(Call{Op: OpHIDInput, Port: d.active, Detail: fmt.Sprintf("%d bytes to active channel", len(data))})
	return nil
}

// ATX performs a per-port ATX operation (switch/__init__.py:174-204,
// api/switch.py:155-176). Unlike video and HID this really is addressed to a
// named port and does not depend on the active channel.
//
// Fidelity note, do not "fix" this: on the sysfs chain the ATX calls are
// accepted and then do nothing — sysfs_chain.py:117-121 `click_power` and
// `click_reset` are `pass`, and sysfs_device.py:609-613 `request_atx_cp` /
// `request_atx_cr` return 0 without touching hardware. The mock therefore
// records the attempt with Inert=true and changes no state. A test asserting
// port isolation asserts on the call log (which port was addressed), not on a
// simulated power state that this hardware does not produce.
func (d *RM4PE) ATX(p PortIndex, action ATXAction) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !p.Valid() {
		err := fmt.Errorf("%w: %d", ErrInvalidPort, int(p))
		d.record(Call{Op: OpATX, Port: p, Detail: string(action), Err: err})
		return err
	}
	d.record(Call{Op: OpATX, Port: p, Detail: string(action), Inert: true})
	return nil
}

// SetPortParams applies per-port parameters (switch/__init__.py:259-289,
// api/switch.py:86-102). Genuinely per-port: a grant on port 1 must not let a
// caller rename or re-EDID port 3.
func (d *RM4PE) SetPortParams(p PortIndex, params PortParams) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !p.Valid() {
		err := fmt.Errorf("%w: %d", ErrInvalidPort, int(p))
		d.record(Call{Op: OpSetPortParams, Port: p, Err: err})
		return err
	}
	st := &d.ports[p]
	var changed []string
	if params.EDIDID != nil {
		st.EDIDID = *params.EDIDID
		changed = append(changed, "edid_id")
	}
	if params.Dummy != nil {
		st.Dummy = *params.Dummy
		changed = append(changed, "dummy")
	}
	if params.Name != nil {
		st.Name = *params.Name
		changed = append(changed, "name")
	}
	if params.ATXClickPowerDelay != nil {
		st.ATXDelays.Power = *params.ATXClickPowerDelay
		changed = append(changed, "atx_click_power_delay")
	}
	if params.ATXClickPowerLong != nil {
		st.ATXDelays.PowerLong = *params.ATXClickPowerLong
		changed = append(changed, "atx_click_power_long_delay")
	}
	if params.ATXClickResetDelay != nil {
		st.ATXDelays.Reset = *params.ATXClickResetDelay
		changed = append(changed, "atx_click_reset_delay")
	}
	d.record(Call{Op: OpSetPortParams, Port: p, Detail: strings.Join(changed, ",")})
	return nil
}

// SetColors is whole-device: the colour roles are global to the switch, not
// per port (switch/__init__.py:244-255, api/switch.py:104-112). A port-scoped
// grant must never authorise it.
func (d *RM4PE) SetColors(role, value string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record(Call{Op: OpSetColors, Port: PortNone, Detail: role + "=" + value})
	return nil
}

// RebootUnit is whole-device and, on this chain, unsupported:
// sysfs_chain.py:123-124 and sysfs_device.py:600-601 both raise DeviceError.
// The mock returns ErrUnsupported so a test cannot accidentally assert that a
// reboot "worked" on hardware where it cannot.
func (d *RM4PE) RebootUnit(bootloader bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record(Call{Op: OpRebootUnit, Port: PortNone, Detail: fmt.Sprintf("bootloader=%v", bootloader), Err: ErrUnsupported})
	return ErrUnsupported
}

// State returns the switch state document (api/switch.py:52-54).
//
// Whole-device read: it exposes every channel's link sense and name at once
// (state.py:213-215, :224-240). A subject scoped to one port that is allowed
// to read this learns about the other three — worth a deliberate decision in
// the core, and worth a test either way.
func (d *RM4PE) State() DeviceState {
	d.mu.Lock()
	defer d.mu.Unlock()
	var st DeviceState
	st.Summary = DeviceSummary{
		ActivePort: int(d.active),
		// sysfs_device.py:571-573 formats this unconditionally, so an unset
		// channel really does render as "1.0".
		ActiveID: d.active.ID(),
		Synced:   true, // sysfs_device.py:573 hardcodes synced=True
	}
	for i := 0; i < PortCount; i++ {
		st.VideoLinks[i] = d.ports[i].VideoLink
		st.USBLinks[i] = d.ports[i].USBLink
		st.Ports[i] = PortModel{
			Unit:           0, // state.py:226 — sysfs chain is always unit 0
			Channel:        i,
			ID:             PortIndex(i).ID(),
			Name:           d.ports[i].Name,
			Dummy:          d.ports[i].Dummy,
			ATXClickDelays: d.ports[i].ATXDelays,
		}
	}
	d.record(Call{Op: OpReadState, Port: PortNone})
	return st
}

// SimulateReboot restarts the device. The active channel is restored from the
// persisted /etc/kvmd/channel.conf (sysfs_device.py:353-359 load,
// :321-351 delayed restore), so a channel a session switched to before the
// reboot is still active after it — an authorization test that assumes the
// device comes back neutral is wrong.
func (d *RM4PE) SimulateReboot() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hidSuspended = false
	d.seq = 0
	d.active = d.saved
}

// ---------- observation ----------

// Calls returns a copy of the call log.
func (d *RM4PE) Calls() []Call {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Call, len(d.calls))
	copy(out, d.calls)
	return out
}

// CallsSince returns a copy of the call log from index n onward. Use with
// len(Calls()) taken before an operation to isolate what that operation did.
func (d *RM4PE) CallsSince(n int) []Call {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n < 0 {
		n = 0
	}
	if n > len(d.calls) {
		n = len(d.calls)
	}
	out := make([]Call, len(d.calls)-n)
	copy(out, d.calls[n:])
	return out
}

// CallCount is the length of the call log.
func (d *RM4PE) CallCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

// Served reports whether any successful call touched the given channel. This
// is the primitive a port-isolation assertion is built on: "a grant on port 1
// did not reach port 3" is `!dev.Served(2)`.
func (d *RM4PE) Served(p PortIndex) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.calls {
		if c.Err == nil && c.Port == p {
			return true
		}
	}
	return false
}

// Snapshot captures enough state to rewind the device between harness runs —
// needed by the mutation check, which replays the same table twice.
type Snapshot struct {
	ports        [PortCount]PortState
	active       PortIndex
	saved        PortIndex
	hidSuspended bool
	seq          int
	calls        int
}

// Snapshot captures the current device state.
func (d *RM4PE) Snapshot() Snapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Snapshot{
		ports:        d.ports,
		active:       d.active,
		saved:        d.saved,
		hidSuspended: d.hidSuspended,
		seq:          d.seq,
		calls:        len(d.calls),
	}
}

// Restore rewinds to a snapshot, truncating the call log to its length then.
func (d *RM4PE) Restore(s Snapshot) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ports = s.ports
	d.active = s.active
	d.saved = s.saved
	d.hidSuspended = s.hidSuspended
	d.seq = s.seq
	if s.calls <= len(d.calls) {
		d.calls = d.calls[:s.calls]
	}
}

// record appends to the call log. Caller must hold d.mu.
func (d *RM4PE) record(c Call) { d.calls = append(d.calls, c) }
