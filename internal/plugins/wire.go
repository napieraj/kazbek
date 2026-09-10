package plugins

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strconv"
)

// Wire constants. See contract/plugins/wire.md.
const (
	// MsgTypePlugin sits in the custom-extension range kazbek already reserves
	// above the upstream rtty message types (0xF0 is DEVICE_INFO). Upstream
	// runs 0x00-0x09; keeping extensions at 0xF0+ leaves room for upstream to
	// grow without collision.
	MsgTypePlugin = byte(0xF1)

	// TIDLen matches the existing 32-byte sid convention used by the
	// login/termdata/file messages, so device-side framing keeps its shape.
	TIDLen = 32

	// HeaderLen is tid + sub.
	HeaderLen = TIDLen + 1

	// PayloadChunkMax caps the data bytes in one payload chunk. The uint16
	// envelope would permit 65502; 32768 leaves clear headroom and is a size
	// an embedded device can buffer without thought.
	PayloadChunkMax = 32768

	// ChunkHeaderLen is seq(4) + flags(1), on top of HeaderLen.
	ChunkHeaderLen = 5

	// FlagLast marks the final payload chunk. All other bits must be zero.
	FlagLast = byte(0x01)

	// ProtocolVersion is carried as "v" in every JSON body.
	ProtocolVersion = 1
)

// Sub-types.
const (
	SubOffer         = byte(0x00)
	SubFetch         = byte(0x01)
	SubPayload       = byte(0x02)
	SubInstallResult = byte(0x03)
	SubReadback      = byte(0x04)
)

// Install result states. "refused" and "failed" are deliberately distinct:
// refused means the plugin never touched the disk and is the observable
// signature of invariant 3, while failed means the disk was touched and then
// restored.
const (
	StateInstalled = "installed"
	StateNoop      = "noop"
	StateRefused   = "refused"
	StateFailed    = "failed"
)

// OfferBody is server -> device: "this plugin is available". Manifest only.
type OfferBody struct {
	Manifest *Manifest `json:"manifest"`
	V        int       `json:"v"`
}

// FetchBody is device -> server: request the bundle for an offered manifest.
type FetchBody struct {
	SHA256 string `json:"sha256"`
	V      int    `json:"v"`
}

// InstallResultBody is device -> server: the verify+install outcome.
type InstallResultBody struct {
	Reason string `json:"reason"`
	SHA256 string `json:"sha256"`
	State  string `json:"state"`
	V      int    `json:"v"`
}

// ReadbackEntry is one placed file, for actionable drift reporting.
type ReadbackEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ReadbackBody is device -> server: what is actually on disk post-install,
// hashed by the device rather than assumed from what it was told to write.
type ReadbackBody struct {
	Entries    []ReadbackEntry `json:"entries"`
	SHA256     string          `json:"sha256"`
	TreeSHA256 string          `json:"tree_sha256"`
	V          int             `json:"v"`
}

// ReadbackMaxEntries caps per-file detail; a larger tree reports tree_sha256
// only and an empty entries list.
const ReadbackMaxEntries = 64

// Frame is a decoded plugin message body (the rtty envelope already stripped).
type Frame struct {
	TID  string
	Sub  byte
	Body []byte // sub-type specific: canonical JSON, or a payload chunk
}

// Chunk is a decoded payload chunk.
type Chunk struct {
	Seq   uint32
	Flags byte
	Data  []byte
}

// Last reports whether this is the final chunk of a transfer.
func (c *Chunk) Last() bool { return c.Flags&FlagLast != 0 }

// EncodeFrame builds a complete wire frame including the rtty envelope.
func EncodeFrame(tid string, sub byte, body []byte) ([]byte, error) {
	if len(tid) != TIDLen {
		return nil, refuse(CodeWireBadFrame, "tid is %d bytes, want %d", len(tid), TIDLen)
	}
	inner := HeaderLen + len(body)
	if inner > 0xFFFF {
		// The envelope's length field is a uint16. This is the single hardest
		// constraint on the design and is why payloads are chunked at all.
		return nil, refuse(CodeWireBadFrame, "body %d bytes exceeds the uint16 envelope", inner)
	}
	out := make([]byte, 3, 3+inner)
	out[0] = MsgTypePlugin
	binary.BigEndian.PutUint16(out[1:3], uint16(inner))
	out = append(out, tid...)
	out = append(out, sub)
	out = append(out, body...)
	return out, nil
}

// DecodeFrame parses a complete wire frame, envelope included.
func DecodeFrame(raw []byte) (*Frame, error) {
	if len(raw) < 3 {
		return nil, refuse(CodeWireBadFrame, "frame shorter than the envelope")
	}
	if raw[0] != MsgTypePlugin {
		return nil, refuse(CodeWireBadFrame, "message type 0x%02x is not a plugin frame", raw[0])
	}
	msgLen := int(binary.BigEndian.Uint16(raw[1:3]))
	if len(raw)-3 != msgLen {
		return nil, refuse(CodeWireBadFrame, "envelope claims %d bytes, got %d", msgLen, len(raw)-3)
	}
	return DecodeBody(raw[3:])
}

// DecodeBody parses a plugin body once the rtty envelope has been stripped,
// which is the shape kazbek's existing DeviceMsgHandlers receive.
func DecodeBody(body []byte) (*Frame, error) {
	if len(body) < HeaderLen {
		// A short read drops the connection, as every other message type in
		// this protocol already does.
		return nil, refuse(CodeWireBadFrame, "body %d bytes, need at least %d", len(body), HeaderLen)
	}
	sub := body[TIDLen]
	if sub > SubReadback {
		return nil, refuse(CodeWireBadFrame, "unknown sub-type 0x%02x", sub)
	}
	return &Frame{TID: string(body[:TIDLen]), Sub: sub, Body: body[HeaderLen:]}, nil
}

// EncodeChunk builds a payload chunk body (the part after tid+sub).
func EncodeChunk(seq uint32, last bool, data []byte) ([]byte, error) {
	if len(data) > PayloadChunkMax {
		return nil, refuse(CodeWireChunkTooLarge, "chunk %d bytes exceeds %d", len(data), PayloadChunkMax)
	}
	out := make([]byte, ChunkHeaderLen, ChunkHeaderLen+len(data))
	binary.BigEndian.PutUint32(out[0:4], seq)
	if last {
		out[4] = FlagLast
	}
	return append(out, data...), nil
}

// DecodeChunk parses a payload chunk body.
func DecodeChunk(body []byte) (*Chunk, error) {
	if len(body) < ChunkHeaderLen {
		return nil, refuse(CodeWireBadFrame, "chunk body %d bytes, need at least %d", len(body), ChunkHeaderLen)
	}
	flags := body[4]
	if flags&^FlagLast != 0 {
		// Refusing unknown bits is what stops a flag added later from being
		// silently ignored by an old device.
		return nil, refuse(CodeWireBadFlags, "unknown flags bits in 0x%02x", flags)
	}
	data := body[ChunkHeaderLen:]
	if len(data) > PayloadChunkMax {
		return nil, refuse(CodeWireChunkTooLarge, "chunk %d bytes exceeds %d", len(data), PayloadChunkMax)
	}
	return &Chunk{Seq: binary.BigEndian.Uint32(body[0:4]), Flags: flags, Data: data}, nil
}

// EncodeJSONBody encodes a JSON message body in canonical form: keys sorted
// bytewise (guaranteed by declaring struct fields in sorted order), no
// insignificant whitespace, and no HTML escaping — Go escapes <, > and & by
// default, which Python's json does not, and the two must agree byte for byte.
//
// Every body type in this package already carries V, so the version is
// stamped by construction rather than by this function.
func EncodeJSONBody(v any) ([]byte, error) {
	return canonicalJSON(v)
}

// DecodeJSONBody parses a JSON message body and enforces the protocol version.
//
// A receiver that does not recognise "v" refuses rather than guessing: a
// message from a future protocol is not a message with unknown fields to
// ignore, it is a message whose meaning is unknown.
func DecodeJSONBody(body []byte, into any) error {
	// Probe the object shape first so a non-object body reports as malformed
	// rather than as an unmarshal type error, which is what the Python side
	// reports for the same input.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return refuse(CodeMalformed, "body is not a JSON object: %v", err)
	}
	var probe struct {
		V *int `json:"v"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return refuse(CodeMalformed, "body is not JSON: %v", err)
	}
	if probe.V == nil || *probe.V != ProtocolVersion {
		got := "absent"
		if probe.V != nil {
			got = strconv.Itoa(*probe.V)
		}
		return refuse(CodeUnsupportedVersion, "body version %s", got)
	}
	if into != nil {
		if err := json.Unmarshal(body, into); err != nil {
			return refuse(CodeMalformed, "body decode: %v", err)
		}
	}
	return nil
}

// Reassembler accumulates payload chunks into a bundle.
//
// It does not reorder: a gap or a repeat drops the transfer. Ordering is the
// tunnel's job, and a receiver that quietly repairs sequence errors hides a
// real fault.
type Reassembler struct {
	buf      []byte
	next     uint32
	done     bool
	maxTotal int64
}

// NewReassembler bounds the total accepted bytes, so a peer cannot stream
// unbounded data by never setting LAST.
func NewReassembler(maxTotal int64) *Reassembler {
	return &Reassembler{maxTotal: maxTotal}
}

// Push adds a chunk. It reports whether the transfer is complete.
func (r *Reassembler) Push(c *Chunk) (bool, error) {
	if r.done {
		return true, refuse(CodeWireBadSequence, "chunk %d after LAST", c.Seq)
	}
	if c.Seq != r.next {
		return false, refuse(CodeWireBadSequence, "expected seq %d, got %d", r.next, c.Seq)
	}
	if int64(len(r.buf))+int64(len(c.Data)) > r.maxTotal {
		return false, refuse(CodePayloadTooLarge, "transfer exceeds %d bytes", r.maxTotal)
	}
	r.buf = append(r.buf, c.Data...)
	r.next++
	r.done = c.Last()
	return r.done, nil
}

// Bytes returns the assembled bundle. It is only meaningful once Push has
// reported completion.
func (r *Reassembler) Bytes() []byte { return r.buf }

// Complete reports whether LAST has been seen.
func (r *Reassembler) Complete() bool { return r.done }

func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encoder.Encode appends a newline; canonical form has none.
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
