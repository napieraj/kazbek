package authz

import (
	"fmt"
	"strconv"
)

// Port identity. This lives in the core rather than with the device mock
// because Scope carries a port (D-009), so the authorization model needs the
// type even where no device is present. The firmware citations are kept: if
// the hardware and this disagree, the hardware is right (rule 1).

// PortCount is the number of channels on an RM4PE.
//
// sysfs_device.py:26 `__channel_count = 4`; sysfs_chain.py:33 `CHANNEL_COUNT = 4`.
// Do NOT parameterise this away: the port-scope decision in D-009 exists
// because this number is 4 and the mux is one-of-four.
const PortCount = 4

// PortIndex is a channel index, 0-based, exactly as the firmware indexes it
// internally (sysfs_device.py:386 validates `0 <= ch <= 3`).
type PortIndex int

// PortNone marks "no port": the initial active channel, and the port field of
// a whole-device operation or a non-port scope.
//
// sysfs_device.py:62 `self.__active_port = -1`.
const PortNone PortIndex = -1

// Valid reports whether p addresses a real channel.
//
// sysfs_chain.py:71 `if not (0 <= port < self.CHANNEL_COUNT): return`.
func (p PortIndex) Valid() bool { return p >= 0 && p < PortCount }

// ID renders the external port id the firmware exposes to clients.
//
// sysfs_device.py:572 `"active_id": f"1.{self.__active_port + 1}"` and
// state.py:229 `"id": f"1.{ch + 1}"`. Note the firmware does NOT special-case
// an unknown active port, so an unset channel renders as "1.0" — the mock
// reproduces that rather than tidying it up, because a client parsing "1.0"
// as a port is a real bug class.
func (p PortIndex) ID() string { return "1." + strconv.Itoa(int(p)+1) }

func (p PortIndex) String() string {
	if !p.Valid() {
		return fmt.Sprintf("port(none:%d)", int(p))
	}
	return "port " + p.ID()
}
