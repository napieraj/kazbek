package server

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestWriteMsgRefusesBodiesTheEnvelopeCannotDescribe pins the uint16 bound.
//
// Before the bound existed, a 70000-byte body declared a length of 4464 and
// wrote all 70000 bytes with a nil error. The peer then read 4464 bytes as the
// message and parsed the remaining ~65k as further frames -- frame
// desynchronisation, reachable from anything able to produce a large message.
// Truncation would merely lose data; desynchronisation lets the tail be read
// as attacker-chosen frames.
func TestWriteMsgRefusesBodiesTheEnvelopeCannotDescribe(t *testing.T) {
	// The write must be raced against a deadline rather than called directly.
	// net.Pipe is unbuffered, so a WriteMsg that does NOT refuse blocks forever
	// on an unread pipe -- and a hung test is not a failed test. Removing the
	// bound has to turn this red, not make it time out.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	dev := &Device{conn: c1}
	done := make(chan error, 1)
	go func() { done <- dev.WriteMsg(0xF1, "", make([]byte, 70000)) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted a 70000-byte body; the envelope length field is a uint16")
		}
		if !strings.Contains(err.Error(), "exceeds the uint16 envelope") {
			t.Fatalf("unexpected error %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WriteMsg neither refused nor returned: it is writing a body the " +
			"envelope cannot describe, so the peer will desynchronise")
	}
}

// TestWriteMsgDeclaresTheLengthItWrites covers the boundary from below, so a
// bound that refused everything would not pass.
func TestWriteMsgDeclaresTheLengthItWrites(t *testing.T) {
	for _, n := range []int{0, 1, 4464, 65535} {
		c1, c2 := net.Pipe()
		dev := &Device{conn: c1}
		done := make(chan error, 1)
		go func() { done <- dev.WriteMsg(0xF1, "", make([]byte, n)) }()

		// Deadline, not a bare read: if WriteMsg wrongly REFUSES a legal size
		// nothing is ever written, and an undeadlined ReadFull would hang here
		// rather than fail. A too-strict bound has to go red like any other.
		if err := c2.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("n=%d: set deadline: %v", n, err)
		}
		hdr := make([]byte, 3)
		if _, err := io.ReadFull(c2, hdr); err != nil {
			t.Fatalf("n=%d: read header (WriteMsg may have refused a legal size): %v", n, err)
		}
		if got := int(binary.BigEndian.Uint16(hdr[1:])); got != n {
			t.Fatalf("n=%d: declared %d", n, got)
		}
		if n > 0 {
			if _, err := io.ReadFull(c2, make([]byte, n)); err != nil {
				t.Fatalf("n=%d: read body: %v", n, err)
			}
		}
		_ = c2.SetReadDeadline(time.Time{})
		if err := <-done; err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		c1.Close()
		c2.Close()
	}
}

// TestWriteMsgCountsTheSidTowardTheBound -- the length field describes
// sid+data, so a bound that only measured data would still wrap.
func TestWriteMsgCountsTheSidTowardTheBound(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	dev := &Device{conn: c1}
	done := make(chan error, 1)
	go func() {
		done <- dev.WriteMsg(0xF1, strings.Repeat("s", 32), make([]byte, 65535-31))
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted sid+data of 65536 bytes")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WriteMsg did not refuse a 65536-byte sid+data")
	}
}
