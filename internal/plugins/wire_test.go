package plugins

import (
	"bytes"
	"encoding/json"
	"testing"
)

// ===== protocol version =====

// A message from a future protocol is not a message with unknown fields to
// ignore; it is a message whose meaning is unknown.
func TestDecodeJSONBodyEnforcesVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		code string
	}{
		{"accepts the current version", `{"sha256":"abc","v":2}`, ""},
		{"refuses a future version", `{"sha256":"abc","v":3}`, CodeUnsupportedVersion},
		{"refuses the superseded v1", `{"sha256":"abc","v":1}`, CodeUnsupportedVersion},
		{"refuses a missing version", `{"sha256":"abc"}`, CodeUnsupportedVersion},
		{"refuses non-JSON", `not json`, CodeMalformed},
		{"refuses a non-object", `[1,2,3]`, CodeMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var into FetchBody
			err := DecodeJSONBody([]byte(tc.body), &into)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("expected accept, got %v", err)
				}
				return
			}
			if CodeOf(err) != tc.code {
				t.Fatalf("code %q, want %q (%v)", CodeOf(err), tc.code, err)
			}
		})
	}
}

// TestVectorBodiesCarryVersionOne is the cheapest way to catch a vector
// generated without "v".
func TestVectorBodiesCarryCurrentVersion(t *testing.T) {
	var v frameVectors
	loadVectors(t, "frames.json", &v)
	checked := 0
	for _, c := range v.Cases {
		if c.Decoded == nil || len(c.Decoded.JSON) == 0 || c.Hex == "" {
			continue
		}
		if err := DecodeJSONBody(c.Decoded.JSON, nil); err != nil {
			t.Errorf("%s: %v", c.ID, err)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no JSON bodies checked")
	}
}

// ===== wire vocabulary =====

// The sub-type numbering is wire-visible: a renumber silently breaks every
// deployed device, so it is pinned rather than left to declaration order.
func TestSubTypesMatchContract(t *testing.T) {
	got := [5]byte{SubOffer, SubFetch, SubPayload, SubInstallResult, SubReadback}
	want := [5]byte{0x00, 0x01, 0x02, 0x03, 0x04}
	if got != want {
		t.Errorf("sub-types %v, want %v", got, want)
	}
}

// "refused" and "failed" must stay distinct: refused is the observable
// signature of invariant 3 (nothing touched the disk), and collapsing them
// would make that invariant untestable from the server's side.
func TestInstallStatesMatchContract(t *testing.T) {
	states := map[string]bool{StateInstalled: true, StateNoop: true, StateRefused: true, StateFailed: true}
	for _, want := range []string{"installed", "noop", "refused", "failed"} {
		if !states[want] {
			t.Errorf("missing install state %q", want)
		}
	}
	if len(states) != 4 {
		t.Errorf("got %d distinct states, want 4", len(states))
	}

	var v frameVectors
	loadVectors(t, "frames.json", &v)
	seen := map[string]bool{}
	for _, c := range v.Cases {
		if c.Decoded == nil || c.Decoded.Sub != SubInstallResult {
			continue
		}
		var body InstallResultBody
		if err := json.Unmarshal(c.Decoded.JSON, &body); err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		seen[body.State] = true
	}
	for want := range states {
		if !seen[want] {
			t.Errorf("no vector exercises install state %q", want)
		}
	}
}

// ===== reassembly =====

func mustChunk(t *testing.T, seq uint32, last bool, data []byte) *Chunk {
	t.Helper()
	body, err := EncodeChunk(seq, last, data)
	if err != nil {
		t.Fatalf("encode chunk: %v", err)
	}
	c, err := DecodeChunk(body)
	if err != nil {
		t.Fatalf("decode chunk: %v", err)
	}
	return c
}

func TestReassemblerJoinsChunks(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), 6000) // spans several chunks
	asm := NewReassembler(int64(len(payload)))
	var done bool
	total := (len(payload) + PayloadChunkMax - 1) / PayloadChunkMax
	for i := 0; i < total; i++ {
		end := min((i+1)*PayloadChunkMax, len(payload))
		var err error
		done, err = asm.Push(mustChunk(t, uint32(i), i == total-1, payload[i*PayloadChunkMax:end]))
		if err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	if !done || !asm.Complete() {
		t.Fatal("transfer did not complete")
	}
	if !bytes.Equal(asm.Bytes(), payload) {
		t.Error("reassembled bytes differ from the original")
	}
}

// Ordering is the tunnel's job; a receiver that quietly repairs sequence
// errors hides a real fault.
func TestReassemblerRefusesBadSequence(t *testing.T) {
	t.Run("gap", func(t *testing.T) {
		asm := NewReassembler(1024)
		mustPush(t, asm, mustChunk(t, 0, false, []byte("a")))
		_, err := asm.Push(mustChunk(t, 2, true, []byte("c")))
		assertCode(t, err, CodeWireBadSequence, "a gap must drop the transfer")
	})

	t.Run("repeat", func(t *testing.T) {
		asm := NewReassembler(1024)
		mustPush(t, asm, mustChunk(t, 0, false, []byte("a")))
		_, err := asm.Push(mustChunk(t, 0, true, []byte("a")))
		assertCode(t, err, CodeWireBadSequence, "a repeat must drop the transfer")
	})

	t.Run("after LAST", func(t *testing.T) {
		asm := NewReassembler(1024)
		mustPush(t, asm, mustChunk(t, 0, true, []byte("a")))
		_, err := asm.Push(mustChunk(t, 1, true, []byte("b")))
		assertCode(t, err, CodeWireBadSequence, "nothing follows LAST")
	})
}

// A peer must not be able to stream unbounded data by never setting LAST.
func TestReassemblerBoundsTotal(t *testing.T) {
	asm := NewReassembler(4)
	_, err := asm.Push(mustChunk(t, 0, false, []byte("12345")))
	assertCode(t, err, CodePayloadTooLarge, "the transfer cap must hold")
}

func mustPush(t *testing.T, asm *Reassembler, c *Chunk) {
	t.Helper()
	if _, err := asm.Push(c); err != nil {
		t.Fatalf("push: %v", err)
	}
}

// ===== compat ordering =====

// Bytewise ordering would put "1.10.0" before "1.9.0", which is exactly the
// bug a firmware_compat constraint must not have.
func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.10.0", "1.9.0", 1},
		{"1.9.0", "1.10.0", -1},
		{"1.10.0", "1.10.0", 0},
		{"rm1pe", "rm4pe", -1},
		{"rm4pe", "rm1pe", 1},
		{"1.10", "1.10.0", -1},
		{"1.10.0", "1.10", 1},
	} {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCanonicalBodyIsCompactSortedAndUnescaped(t *testing.T) {
	// Go escapes <, > and & by default and Python does not; this pins the Go
	// side of that agreement.
	got, err := EncodeJSONBody(map[string]any{"b": 1, "a": "<&>"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if string(got) != `{"a":"<&>","b":1}` {
		t.Errorf("canonical body = %s", got)
	}
}
