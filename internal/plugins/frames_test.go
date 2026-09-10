package plugins

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("bad base64 in vector: %v", err)
	}
	return b
}

type frameVectors struct {
	MsgType         byte `json:"msg_type"`
	PayloadChunkMax int  `json:"payload_chunk_max"`
	TIDLen          int  `json:"tid_len"`
	Cases           []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Hex         string `json:"hex"`
		Code        string `json:"code"`
		Construct   *struct {
			TID        string `json:"tid"`
			Sub        byte   `json:"sub"`
			Seq        uint32 `json:"seq"`
			Flags      byte   `json:"flags"`
			DataRepeat *struct {
				Byte  byte `json:"byte"`
				Count int  `json:"count"`
			} `json:"data_repeat"`
		} `json:"construct"`
		Decoded *struct {
			TID     string          `json:"tid"`
			Sub     byte            `json:"sub"`
			JSON    json.RawMessage `json:"json"`
			Seq     *uint32         `json:"seq"`
			Flags   *byte           `json:"flags"`
			DataB64 string          `json:"data_b64"`
		} `json:"decoded"`
	} `json:"cases"`
}

// TestFrameConstants pins the wire constants to the contract, so a local edit
// to either cannot drift silently.
func TestFrameConstants(t *testing.T) {
	var v frameVectors
	loadVectors(t, "frames.json", &v)
	if v.MsgType != MsgTypePlugin {
		t.Errorf("msg type 0x%02x, contract says 0x%02x", MsgTypePlugin, v.MsgType)
	}
	if v.PayloadChunkMax != PayloadChunkMax {
		t.Errorf("chunk max %d, contract says %d", PayloadChunkMax, v.PayloadChunkMax)
	}
	if v.TIDLen != TIDLen {
		t.Errorf("tid len %d, contract says %d", TIDLen, v.TIDLen)
	}
}

func TestFrameVectors(t *testing.T) {
	var v frameVectors
	loadVectors(t, "frames.json", &v)
	if len(v.Cases) == 0 {
		t.Fatal("no frame vectors loaded")
	}

	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			var raw []byte
			if c.Hex != "" {
				b, err := hex.DecodeString(c.Hex)
				if err != nil {
					t.Fatalf("bad hex in vector: %v", err)
				}
				raw = b
			} else if c.Construct != nil {
				body, err := EncodeChunk(c.Construct.Seq, c.Construct.Flags&FlagLast != 0,
					bytes.Repeat([]byte{c.Construct.DataRepeat.Byte}, c.Construct.DataRepeat.Count))
				if err != nil {
					// An oversized chunk is refused at encode as well as at
					// decode; either end of the wire is a valid place to catch it.
					assertCode(t, err, c.Code, c.Description)
					return
				}
				raw, err = EncodeFrame(c.Construct.TID, c.Construct.Sub, body)
				if err != nil {
					t.Fatalf("encode frame: %v", err)
				}
			} else {
				t.Fatal("vector has neither hex nor construct")
			}

			f, err := DecodeFrame(raw)
			if err == nil && f.Sub == SubPayload {
				_, err = DecodeChunk(f.Body)
			}

			if c.Code != "" {
				assertCode(t, err, c.Code, c.Description)
				return
			}
			if err != nil {
				t.Fatalf("expected decode, refused with %q (%v)\n%s", CodeOf(err), err, c.Description)
			}

			d := c.Decoded
			if d == nil {
				return
			}
			if f.TID != d.TID {
				t.Errorf("tid %q, want %q", f.TID, d.TID)
			}
			if f.Sub != d.Sub {
				t.Errorf("sub 0x%02x, want 0x%02x", f.Sub, d.Sub)
			}

			if len(d.JSON) > 0 {
				// The body must already be canonical on the wire: re-encoding
				// the decode has to reproduce the exact bytes, or the two
				// languages cannot hash the same message to the same value.
				var got any
				if err := json.Unmarshal(f.Body, &got); err != nil {
					t.Fatalf("body is not JSON: %v", err)
				}
				gotCanon, err := canonicalJSON(got)
				if err != nil {
					t.Fatalf("canonical: %v", err)
				}
				if !bytes.Equal(gotCanon, f.Body) {
					t.Errorf("body is not canonical on the wire\n got: %s\ncanon: %s", f.Body, gotCanon)
				}
			}

			if d.Seq != nil {
				ch, err := DecodeChunk(f.Body)
				if err != nil {
					t.Fatalf("decode chunk: %v", err)
				}
				if ch.Seq != *d.Seq || ch.Flags != *d.Flags {
					t.Errorf("seq/flags %d/0x%02x, want %d/0x%02x", ch.Seq, ch.Flags, *d.Seq, *d.Flags)
				}
				if d.DataB64 != "" && !bytes.Equal(ch.Data, decodeB64(t, d.DataB64)) {
					t.Error("chunk data mismatch")
				}
			}

			// Round-trip: re-encoding the decoded frame reproduces the bytes.
			if c.Hex != "" {
				out, err := EncodeFrame(f.TID, f.Sub, f.Body)
				if err != nil {
					t.Fatalf("re-encode: %v", err)
				}
				if !bytes.Equal(out, raw) {
					t.Error("frame did not round-trip to identical bytes")
				}
			}
		})
	}
}

func assertCode(t *testing.T, err error, want, desc string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected refusal %q, got success\n%s", want, desc)
	}
	if got := CodeOf(err); got != want {
		t.Fatalf("refusal code %q, want %q (%v)\n%s", got, want, err, desc)
	}
}
