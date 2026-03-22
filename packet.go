package schlage_uweave

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

const (
	MaxDefaultPacketSize = 20 // BLE default (no MTU negotiation)
	MinPacketSize        = 20
	ProtocolVersionMin   = 1
	ProtocolVersionMax   = 1
)

// PacketHeader represents a decoded uWeave packet header byte.
type PacketHeader struct {
	IsControl bool
	Counter   uint8 // 0-7
	IsFirst   bool
	IsLast    bool
	Command   uint8 // only for control packets
}

// EncodeHeader encodes a PacketHeader into a single byte.
//
// Control packets (bit 7 = 1):
//
//	Bit 7:    1 (control)
//	Bits 6-4: Counter (3 bits, mod 8)
//	Bits 3-0: Command number (4 bits)
//
// Data packets (bit 7 = 0):
//
//	Bit 7:    0 (data)
//	Bits 6-4: Counter (3 bits, mod 8)
//	Bit 3:    First packet flag
//	Bit 2:    Last packet flag
//	Bits 1-0: Reserved
func EncodeHeader(h PacketHeader) byte {
	var b byte
	if h.IsControl {
		b |= 1 << 7
		b |= (h.Counter & 0x07) << 4
		b |= h.Command & 0x0F
	} else {
		b |= (h.Counter & 0x07) << 4
		if h.IsFirst {
			b |= 1 << 3
		}
		if h.IsLast {
			b |= 1 << 2
		}
	}
	return b
}

// DecodeHeader decodes a single byte into a PacketHeader.
func DecodeHeader(b byte) PacketHeader {
	h := PacketHeader{
		IsControl: (b & 0x80) != 0,
		Counter:   (b >> 4) & 0x07,
	}
	if h.IsControl {
		h.Command = b & 0x0F
	} else {
		h.IsFirst = (b & 0x08) != 0
		h.IsLast = (b & 0x04) != 0
	}
	return h
}

// ConnectionState tracks the negotiated connection parameters.
type ConnectionState struct {
	MaxPacketSize int
	Version       int
	Counter       uint8 // our send counter, wraps mod 8
}

// Crypto modes for the uWeave channel encryption handshake.
const (
	CryptoModePassthrough = 0x00 // No encryption
	CryptoModeTokenSHA256 = 0x02 // SAT-based auth with AES-EAX
)

// NewConnectionRequest builds the bytes for a ConnectionRequest control packet.
// The payload is: uint16 min_version, uint16 max_version, uint16 max_packet_size
// (all big-endian per libuweave), followed by the crypto handshake data.
// For TOKEN_SHA256 mode: 1 byte crypto mode (0x02) + 12 bytes client random.
// Returns the packet and the 12-byte client random (nil for passthrough).
func NewConnectionRequest(maxPacketSize int, cryptoMode byte) ([]byte, []byte) {
	h := PacketHeader{
		IsControl: true,
		Counter:   0,
		Command:   0x0, // kUwPacketHeaderCmdConnectionRequest
	}

	var handshake []byte
	var clientRandom []byte
	switch cryptoMode {
	case CryptoModePassthrough:
		handshake = []byte{CryptoModePassthrough}
	case CryptoModeTokenSHA256:
		clientRandom = make([]byte, 12)
		rand.Read(clientRandom)
		handshake = make([]byte, 13)
		handshake[0] = CryptoModeTokenSHA256
		copy(handshake[1:], clientRandom)
	}

	buf := make([]byte, 1+6+len(handshake))
	buf[0] = EncodeHeader(h)
	binary.BigEndian.PutUint16(buf[1:3], ProtocolVersionMin)
	binary.BigEndian.PutUint16(buf[3:5], ProtocolVersionMax)
	binary.BigEndian.PutUint16(buf[5:7], uint16(maxPacketSize))
	copy(buf[7:], handshake)
	return buf, clientRandom
}

// ParseConnectionConfirm parses a ConnectionConfirm control packet and returns
// the negotiated version, packet size, and server random (if TOKEN_SHA256 mode).
func ParseConnectionConfirm(data []byte) (version int, packetSize int, serverRandom []byte, err error) {
	if len(data) < 5 {
		return 0, 0, nil, fmt.Errorf("connection confirm too short: %d bytes", len(data))
	}
	hdr := DecodeHeader(data[0])
	if !hdr.IsControl {
		return 0, 0, nil, fmt.Errorf("expected control packet, got data packet")
	}
	if hdr.Command != 0x1 {
		return 0, 0, nil, fmt.Errorf("expected ConnectionConfirm (command 1), got command %d", hdr.Command)
	}
	version = int(binary.BigEndian.Uint16(data[1:3]))
	packetSize = int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) > 5 {
		serverRandom = data[5:]
	}
	return version, packetSize, serverRandom, nil
}

// Fragmenter handles splitting outgoing messages into BLE packets.
type Fragmenter struct {
	conn *ConnectionState
}

// NewFragmenter creates a Fragmenter tied to a ConnectionState.
func NewFragmenter(conn *ConnectionState) *Fragmenter {
	return &Fragmenter{conn: conn}
}

// Fragment splits a complete message into one or more BLE packets,
// each no larger than conn.MaxPacketSize. The connection counter is
// incremented once per packet (wrapping mod 8), matching the uWeave
// protocol as observed in the Android Schlage app's HCI traces.
func (f *Fragmenter) Fragment(msg []byte) [][]byte {
	maxPayload := f.conn.MaxPacketSize - 1 // 1 byte for header
	if maxPayload < 1 {
		maxPayload = 1
	}

	var packets [][]byte
	offset := 0

	for offset <= len(msg) {
		isFirst := offset == 0
		end := offset + maxPayload
		if end > len(msg) {
			end = len(msg)
		}
		isLast := end == len(msg)

		hdr := PacketHeader{
			IsControl: false,
			Counter:   f.conn.Counter,
			IsFirst:   isFirst,
			IsLast:    isLast,
		}
		f.conn.Counter = (f.conn.Counter + 1) % 8

		pkt := make([]byte, 1+end-offset)
		pkt[0] = EncodeHeader(hdr)
		copy(pkt[1:], msg[offset:end])
		packets = append(packets, pkt)

		offset = end
		if isLast {
			break
		}
	}

	return packets
}

// Assembler handles reassembling incoming BLE packets into complete messages.
type Assembler struct {
	buf     []byte
	started bool
}

// NewAssembler creates a new Assembler.
func NewAssembler() *Assembler {
	return &Assembler{}
}

// Feed processes an incoming BLE packet. Returns the complete message and true
// when the last packet of a message has been received, or nil and false if
// more packets are needed.
func (a *Assembler) Feed(packet []byte) ([]byte, bool, error) {
	if len(packet) < 1 {
		return nil, false, fmt.Errorf("empty packet")
	}

	hdr := DecodeHeader(packet[0])

	if hdr.IsControl {
		return nil, false, fmt.Errorf("unexpected control packet in assembler")
	}

	if hdr.IsFirst {
		a.buf = nil
		a.started = true
	} else if !a.started {
		return nil, false, fmt.Errorf("received continuation packet without first packet")
	}

	a.buf = append(a.buf, packet[1:]...)

	if hdr.IsLast {
		msg := a.buf
		a.buf = nil
		a.started = false
		return msg, true, nil
	}

	return nil, false, nil
}
