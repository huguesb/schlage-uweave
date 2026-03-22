package schlage

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestHeaderRoundTripData(t *testing.T) {
	h := PacketHeader{
		IsControl: false,
		Counter:   5,
		IsFirst:   true,
		IsLast:    false,
		Command:   0,
	}
	b := EncodeHeader(h)
	got := DecodeHeader(b)
	if got != h {
		t.Fatalf("round-trip mismatch: encoded %+v, decoded %+v", h, got)
	}
}

func TestHeaderRoundTripControl(t *testing.T) {
	// Control packets don't have First/Last flags — those bits are part of Command
	h := PacketHeader{
		IsControl: true,
		Counter:   3,
		Command:   1,
	}
	b := EncodeHeader(h)
	got := DecodeHeader(b)
	if got != h {
		t.Fatalf("round-trip mismatch: encoded %+v, decoded %+v", h, got)
	}
}

func TestHeaderBitLayout(t *testing.T) {
	// Control=1, Counter=7, Command=2
	// Control packets: bit7=1, bits6-4=counter, bits3-0=command
	h := PacketHeader{
		IsControl: true,
		Counter:   7,
		Command:   2,
	}
	b := EncodeHeader(h)
	// = 1_111_0010 = 0xF2
	if b != 0xF2 {
		t.Fatalf("expected 0xF2, got 0x%02X", b)
	}

	// Data packet: Counter=7, First=1, Last=1
	hd := PacketHeader{
		Counter: 7,
		IsFirst: true,
		IsLast:  true,
	}
	bd := EncodeHeader(hd)
	// = 0_111_1_1_00 = 0x7C
	if bd != 0x7C {
		t.Fatalf("expected 0x7C, got 0x%02X", bd)
	}
}

func TestConnectionRequestPassthrough(t *testing.T) {
	pkt, clientRandom := NewConnectionRequest(20, CryptoModePassthrough)
	// Should be 8 bytes: 1 header + 6 version/size (big-endian) + 1 crypto mode
	if len(pkt) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(pkt))
	}
	if clientRandom != nil {
		t.Fatal("expected nil clientRandom for passthrough")
	}

	hdr := DecodeHeader(pkt[0])
	if !hdr.IsControl || hdr.Command != 0x0 {
		t.Fatalf("unexpected header: %+v", hdr)
	}

	minVer := binary.BigEndian.Uint16(pkt[1:3])
	maxVer := binary.BigEndian.Uint16(pkt[3:5])
	maxPkt := binary.BigEndian.Uint16(pkt[5:7])
	if minVer != ProtocolVersionMin {
		t.Fatalf("expected min version %d, got %d", ProtocolVersionMin, minVer)
	}
	if maxVer != ProtocolVersionMax {
		t.Fatalf("expected max version %d, got %d", ProtocolVersionMax, maxVer)
	}
	if maxPkt != 20 {
		t.Fatalf("expected max packet size 20, got %d", maxPkt)
	}
	if pkt[7] != CryptoModePassthrough {
		t.Fatalf("expected crypto mode 0x00, got 0x%02X", pkt[7])
	}
}

func TestConnectionRequestTokenSHA256(t *testing.T) {
	pkt, clientRandom := NewConnectionRequest(20, CryptoModeTokenSHA256)
	// Should be 20 bytes: 1 header + 6 version/size + 1 crypto mode + 12 random
	if len(pkt) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(pkt))
	}
	if len(clientRandom) != 12 {
		t.Fatalf("expected 12-byte clientRandom, got %d", len(clientRandom))
	}
	if pkt[7] != CryptoModeTokenSHA256 {
		t.Fatalf("expected crypto mode 0x02, got 0x%02X", pkt[7])
	}
	if !bytes.Equal(pkt[8:], clientRandom) {
		t.Fatal("clientRandom mismatch in packet")
	}
}

func TestParseConnectionConfirm(t *testing.T) {
	// Build a valid ConnectionConfirm packet (big-endian)
	hdr := PacketHeader{IsControl: true, Counter: 0, Command: 1}
	buf := make([]byte, 5)
	buf[0] = EncodeHeader(hdr)
	binary.BigEndian.PutUint16(buf[1:3], 1)  // version
	binary.BigEndian.PutUint16(buf[3:5], 64) // packet size

	ver, ps, _, err := ParseConnectionConfirm(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != 1 {
		t.Fatalf("expected version 1, got %d", ver)
	}
	if ps != 64 {
		t.Fatalf("expected packet size 64, got %d", ps)
	}
}

func TestParseConnectionConfirmWithServerRandom(t *testing.T) {
	hdr := PacketHeader{IsControl: true, Counter: 0, Command: 1}
	buf := make([]byte, 17) // 1 header + 4 version/size + 12 server random
	buf[0] = EncodeHeader(hdr)
	binary.BigEndian.PutUint16(buf[1:3], 1)  // version
	binary.BigEndian.PutUint16(buf[3:5], 20) // packet size
	for i := 0; i < 12; i++ {
		buf[5+i] = byte(i + 1)
	}

	ver, ps, serverRandom, err := ParseConnectionConfirm(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != 1 || ps != 20 {
		t.Fatalf("unexpected version=%d, packetSize=%d", ver, ps)
	}
	if len(serverRandom) != 12 {
		t.Fatalf("expected 12-byte serverRandom, got %d", len(serverRandom))
	}
}

func TestParseConnectionConfirmErrors(t *testing.T) {
	// Too short
	_, _, _, err := ParseConnectionConfirm([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for short packet")
	}

	// Not a control packet
	buf := make([]byte, 5)
	buf[0] = EncodeHeader(PacketHeader{IsControl: false, IsFirst: true, IsLast: true})
	_, _, _, err = ParseConnectionConfirm(buf)
	if err == nil {
		t.Fatal("expected error for non-control packet")
	}

	// Wrong command
	buf[0] = EncodeHeader(PacketHeader{IsControl: true, Command: 0})
	_, _, _, err = ParseConnectionConfirm(buf)
	if err == nil {
		t.Fatal("expected error for wrong command")
	}
}

func TestFragmentSinglePacket(t *testing.T) {
	conn := &ConnectionState{MaxPacketSize: 20, Version: 1}
	f := NewFragmenter(conn)
	msg := []byte("hello")
	pkts := f.Fragment(msg)
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts))
	}
	hdr := DecodeHeader(pkts[0][0])
	if !hdr.IsFirst || !hdr.IsLast {
		t.Fatalf("single packet should have first and last set: %+v", hdr)
	}
	if !bytes.Equal(pkts[0][1:], msg) {
		t.Fatalf("payload mismatch: got %q, want %q", pkts[0][1:], msg)
	}
}

func TestFragmentMultiPacket(t *testing.T) {
	conn := &ConnectionState{MaxPacketSize: 5, Version: 1} // 4 bytes payload per packet
	f := NewFragmenter(conn)
	msg := []byte("abcdefghij") // 10 bytes -> 3 packets (4+4+2)
	pkts := f.Fragment(msg)
	if len(pkts) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(pkts))
	}

	// First packet
	h0 := DecodeHeader(pkts[0][0])
	if !h0.IsFirst || h0.IsLast {
		t.Fatalf("packet 0: expected first=true, last=false, got %+v", h0)
	}
	if !bytes.Equal(pkts[0][1:], []byte("abcd")) {
		t.Fatalf("packet 0 payload: got %q", pkts[0][1:])
	}

	// Middle packet
	h1 := DecodeHeader(pkts[1][0])
	if h1.IsFirst || h1.IsLast {
		t.Fatalf("packet 1: expected first=false, last=false, got %+v", h1)
	}
	if !bytes.Equal(pkts[1][1:], []byte("efgh")) {
		t.Fatalf("packet 1 payload: got %q", pkts[1][1:])
	}

	// Last packet
	h2 := DecodeHeader(pkts[2][0])
	if h2.IsFirst || !h2.IsLast {
		t.Fatalf("packet 2: expected first=false, last=true, got %+v", h2)
	}
	if !bytes.Equal(pkts[2][1:], []byte("ij")) {
		t.Fatalf("packet 2 payload: got %q", pkts[2][1:])
	}
}

func TestFragmentPacketSize(t *testing.T) {
	conn := &ConnectionState{MaxPacketSize: 20, Version: 1}
	f := NewFragmenter(conn)
	// Message that requires exactly 2 packets: 19 bytes payload each
	msg := make([]byte, 30)
	for i := range msg {
		msg[i] = byte(i)
	}
	pkts := f.Fragment(msg)
	for i, pkt := range pkts {
		if len(pkt) > 20 {
			t.Fatalf("packet %d exceeds max size: %d > 20", i, len(pkt))
		}
	}
}

func TestAssemblerSinglePacket(t *testing.T) {
	a := NewAssembler()
	hdr := EncodeHeader(PacketHeader{IsFirst: true, IsLast: true, Counter: 0})
	pkt := append([]byte{hdr}, []byte("hello")...)
	msg, done, err := a.Feed(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !done {
		t.Fatal("expected done=true")
	}
	if !bytes.Equal(msg, []byte("hello")) {
		t.Fatalf("message mismatch: got %q", msg)
	}
}

func TestAssemblerMultiPacket(t *testing.T) {
	a := NewAssembler()

	// First packet
	h0 := EncodeHeader(PacketHeader{IsFirst: true, IsLast: false, Counter: 0})
	pkt0 := append([]byte{h0}, []byte("abc")...)
	msg, done, err := a.Feed(pkt0)
	if err != nil {
		t.Fatalf("packet 0 error: %v", err)
	}
	if done || msg != nil {
		t.Fatal("should not be done after first packet")
	}

	// Middle packet
	h1 := EncodeHeader(PacketHeader{IsFirst: false, IsLast: false, Counter: 0})
	pkt1 := append([]byte{h1}, []byte("def")...)
	msg, done, err = a.Feed(pkt1)
	if err != nil {
		t.Fatalf("packet 1 error: %v", err)
	}
	if done || msg != nil {
		t.Fatal("should not be done after middle packet")
	}

	// Last packet
	h2 := EncodeHeader(PacketHeader{IsFirst: false, IsLast: true, Counter: 0})
	pkt2 := append([]byte{h2}, []byte("ghi")...)
	msg, done, err = a.Feed(pkt2)
	if err != nil {
		t.Fatalf("packet 2 error: %v", err)
	}
	if !done {
		t.Fatal("expected done after last packet")
	}
	if !bytes.Equal(msg, []byte("abcdefghi")) {
		t.Fatalf("message mismatch: got %q", msg)
	}
}

func TestRoundTrip(t *testing.T) {
	original := make([]byte, 100)
	for i := range original {
		original[i] = byte(i)
	}

	conn := &ConnectionState{MaxPacketSize: 20, Version: 1}
	f := NewFragmenter(conn)
	a := NewAssembler()

	pkts := f.Fragment(original)
	if len(pkts) < 2 {
		t.Fatal("expected multiple packets for 100-byte message")
	}

	var msg []byte
	var done bool
	var err error
	for i, pkt := range pkts {
		msg, done, err = a.Feed(pkt)
		if err != nil {
			t.Fatalf("feed packet %d: %v", i, err)
		}
		if i < len(pkts)-1 {
			if done {
				t.Fatalf("done too early at packet %d", i)
			}
		}
	}
	if !done {
		t.Fatal("expected done after all packets")
	}
	if !bytes.Equal(msg, original) {
		t.Fatal("round-trip message mismatch")
	}
}

func TestCounterIncrements(t *testing.T) {
	conn := &ConnectionState{MaxPacketSize: 20, Version: 1}
	f := NewFragmenter(conn)

	for i := 0; i < 10; i++ {
		expectedCounter := uint8(i % 8)
		pkts := f.Fragment([]byte("x"))
		hdr := DecodeHeader(pkts[0][0])
		if hdr.Counter != expectedCounter {
			t.Fatalf("call %d: expected counter %d, got %d", i, expectedCounter, hdr.Counter)
		}
	}
}

func TestCounterIncrementsPerPacket(t *testing.T) {
	conn := &ConnectionState{MaxPacketSize: 5, Version: 1}
	f := NewFragmenter(conn)

	pkts := f.Fragment([]byte("abcdefghij")) // multiple fragments
	for i, pkt := range pkts {
		hdr := DecodeHeader(pkt[0])
		expected := uint8(i % 8)
		if hdr.Counter != expected {
			t.Fatalf("packet %d counter %d != expected %d", i, hdr.Counter, expected)
		}
	}
	// conn.Counter should reflect total packets sent
	if conn.Counter != uint8(len(pkts)%8) {
		t.Fatalf("conn.Counter = %d, expected %d", conn.Counter, len(pkts)%8)
	}
}

func TestAssemblerErrorOnEmpty(t *testing.T) {
	a := NewAssembler()
	_, _, err := a.Feed([]byte{})
	if err == nil {
		t.Fatal("expected error on empty packet")
	}
}

func TestAssemblerErrorOnContinuationWithoutFirst(t *testing.T) {
	a := NewAssembler()
	hdr := EncodeHeader(PacketHeader{IsFirst: false, IsLast: true, Counter: 0})
	_, _, err := a.Feed([]byte{hdr, 0x01})
	if err == nil {
		t.Fatal("expected error on continuation without first")
	}
}

func TestFragmentEmptyMessage(t *testing.T) {
	conn := &ConnectionState{MaxPacketSize: 20, Version: 1}
	f := NewFragmenter(conn)
	pkts := f.Fragment([]byte{})
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet for empty message, got %d", len(pkts))
	}
	hdr := DecodeHeader(pkts[0][0])
	if !hdr.IsFirst || !hdr.IsLast {
		t.Fatalf("empty message packet should have first and last set")
	}
	if len(pkts[0]) != 1 {
		t.Fatalf("empty message packet should be header only, got %d bytes", len(pkts[0]))
	}
}
