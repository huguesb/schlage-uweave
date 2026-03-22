// Package schlage implements BLE communication with Schlage locks using the
// uWeave protocol. This file implements the session encryption layer:
// AES-128-EAX authenticated encryption, HKDF-SHA256 key derivation, and
// session cipher management.
package schlage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	eaxKeySize   = 16 // AES-128
	eaxNonceBase = 16 // base nonce length
	eaxTagSize   = 12 // truncated auth tag used by uWeave

	senderClient = 0x01
	senderServer = 0x03

	maxCounter = (1 << 24) - 1 // 3-byte counter, max 2^24 - 1
)

// ---- AES-CMAC (OMAC1) per RFC 4493 ----

// cmac computes AES-CMAC (OMAC1) over data using the given 16-byte key.
// Returns a 16-byte authentication tag.
func cmac(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("cmac: invalid key size")
	}

	// Generate subkeys K1, K2.
	k1, k2 := cmacSubkeys(block)

	bs := block.BlockSize() // 16

	// Determine number of blocks.
	n := (len(data) + bs - 1) / bs
	if n == 0 {
		n = 1
	}

	// Check if the last block is complete.
	lastBlockComplete := (len(data) > 0) && (len(data)%bs == 0)

	// Process all blocks except the last with CBC-MAC.
	x := make([]byte, bs) // running MAC state (starts as zero)

	for i := 0; i < n-1; i++ {
		xorBlock(x, data[i*bs:(i+1)*bs])
		block.Encrypt(x, x)
	}

	// Process the last block.
	lastBlock := make([]byte, bs)
	if lastBlockComplete {
		copy(lastBlock, data[(n-1)*bs:n*bs])
		xorBlock(lastBlock, k1)
	} else {
		// Copy whatever remains and pad with 10*
		remaining := len(data) - (n-1)*bs
		copy(lastBlock, data[(n-1)*bs:])
		lastBlock[remaining] = 0x80
		// rest is already zero
		xorBlock(lastBlock, k2)
	}

	xorBlock(x, lastBlock)
	block.Encrypt(x, x)
	return x
}

// cmacSubkeys derives the CMAC subkeys K1 and K2 from the cipher.
func cmacSubkeys(block cipher.Block) (k1, k2 []byte) {
	bs := block.BlockSize()
	zero := make([]byte, bs)
	l := make([]byte, bs)
	block.Encrypt(l, zero)

	k1 = dbl(l)
	k2 = dbl(k1)
	return
}

// dbl performs the doubling operation in GF(2^128) with the AES polynomial.
func dbl(data []byte) []byte {
	n := len(data)
	out := make([]byte, n)
	carry := byte(0)
	for i := n - 1; i >= 0; i-- {
		out[i] = (data[i] << 1) | carry
		carry = (data[i] >> 7) & 1
	}
	// If the original MSB was set, XOR with the AES-128 constant 0x87.
	if data[0]&0x80 != 0 {
		out[n-1] ^= 0x87
	}
	return out
}

// xorBlock XORs src into dst in-place. Both must be the same length.
func xorBlock(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// ---- AES-EAX authenticated encryption ----

// eaxCMAC computes CMAC with a tweak byte prepended: CMAC_K([tweak] || [0]*15 || data).
// The tweak is encoded as a 16-byte block with the tweak value in the last byte.
func eaxCMAC(block cipher.Block, key []byte, tweak byte, data []byte) []byte {
	bs := block.BlockSize()
	// Prepend a 16-byte tweak block: [0, 0, ..., 0, tweak]
	tweakBlock := make([]byte, bs)
	tweakBlock[bs-1] = tweak
	input := make([]byte, bs+len(data))
	copy(input, tweakBlock)
	copy(input[bs:], data)
	return cmac(key, input)
}

// eaxEncrypt performs AES-EAX authenticated encryption.
// key: 16-byte AES-128 key
// nonce: arbitrary length (uWeave uses 20 bytes)
// plaintext: data to encrypt
// aad: additional authenticated data (can be nil)
// Returns ciphertext || 12-byte auth tag.
func eaxEncrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("eax: %w", err)
	}

	// N = CMAC_K(0 || nonce) — the nonce tag
	nTag := eaxCMAC(block, key, 0, nonce)

	// H = CMAC_K(1 || aad) — the header/AAD tag
	hTag := eaxCMAC(block, key, 1, aad)

	// Encrypt plaintext with AES-CTR using nTag as the IV.
	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, nTag)
	stream.XORKeyStream(ciphertext, plaintext)

	// C = CMAC_K(2 || ciphertext) — the ciphertext tag
	cTag := eaxCMAC(block, key, 2, ciphertext)

	// Final tag = N XOR H XOR C, truncated to eaxTagSize bytes.
	tag := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		tag[i] = nTag[i] ^ hTag[i] ^ cTag[i]
	}

	// Return ciphertext || truncated tag.
	result := make([]byte, len(ciphertext)+eaxTagSize)
	copy(result, ciphertext)
	copy(result[len(ciphertext):], tag[:eaxTagSize])
	return result, nil
}

// eaxDecrypt performs AES-EAX authenticated decryption.
// key: 16-byte AES-128 key
// nonce: arbitrary length
// ciphertext: encrypted data with 12-byte auth tag appended
// aad: additional authenticated data (can be nil)
// Returns plaintext, or error if authentication fails.
func eaxDecrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < eaxTagSize {
		return nil, errors.New("eax: ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("eax: %w", err)
	}

	// Split ciphertext and tag.
	ct := ciphertext[:len(ciphertext)-eaxTagSize]
	receivedTag := ciphertext[len(ciphertext)-eaxTagSize:]

	// N = CMAC_K(0 || nonce)
	nTag := eaxCMAC(block, key, 0, nonce)

	// H = CMAC_K(1 || aad)
	hTag := eaxCMAC(block, key, 1, aad)

	// C = CMAC_K(2 || ciphertext)
	cTag := eaxCMAC(block, key, 2, ct)

	// Compute expected tag = N XOR H XOR C.
	expectedTag := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		expectedTag[i] = nTag[i] ^ hTag[i] ^ cTag[i]
	}

	// Compare truncated tags in constant time.
	if !hmacEqual(expectedTag[:eaxTagSize], receivedTag) {
		return nil, errors.New("eax: authentication failed")
	}

	// Decrypt with AES-CTR using nTag as the IV.
	plaintext := make([]byte, len(ct))
	stream := cipher.NewCTR(block, nTag)
	stream.XORKeyStream(plaintext, ct)
	return plaintext, nil
}

// hmacEqual compares two byte slices in constant time.
func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// ---- HKDF-SHA256 (RFC 5869) ----

// hkdfExtract performs HKDF-Extract: PRK = HMAC-SHA256(salt, ikm).
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpand performs HKDF-Expand: produces okm of length outLen bytes.
func hkdfExpand(prk, info []byte, outLen int) ([]byte, error) {
	hashLen := sha256.Size
	n := (outLen + hashLen - 1) / hashLen
	if n > 255 {
		return nil, errors.New("hkdf: output length too large")
	}

	okm := make([]byte, 0, n*hashLen)
	var prev []byte

	for i := 1; i <= n; i++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		prev = mac.Sum(nil)
		okm = append(okm, prev...)
	}
	return okm[:outLen], nil
}

// ---- Session key derivation ----

// kModeSaltTokenSha256 is the 32-byte HKDF salt used for session key
// derivation in the uWeave UW_CRYPTO_MODE_TOKEN_SHA256 (0x02) mode.
// From libuweave channel_encryption.c.
var kModeSaltTokenSha256 = []byte{
	0x00, 0x8a, 0x39, 0x36, 0x22, 0x04, 0x1f, 0x5f,
	0x0f, 0xc7, 0x5d, 0x97, 0xda, 0xee, 0x6e, 0x81,
	0xcb, 0xbb, 0x2b, 0xc7, 0x4f, 0x9c, 0xcc, 0x91,
	0xe7, 0x5e, 0x77, 0xa5, 0x6b, 0x4a, 0x4b, 0x05,
}

// SessionKeys holds the derived encryption keys for a session.
type SessionKeys struct {
	Key       []byte // 16-byte AES key
	NonceBase []byte // 16-byte nonce base
}

// DeriveSessionKeys derives AES-EAX session keys from key material using
// HKDF-SHA256.
//
// keyMaterial is typically [0x02] || clientRandom(12) || serverRandom(12) || macTag(16)
// totaling 41 bytes.
//
// The HKDF info/context string is "session key" (11 bytes).
// The salt is kModeSaltTokenSha256 (32 bytes).
//
// We derive 32 bytes total: first 16 for the AES key, next 16 for the nonce base.
func DeriveSessionKeys(keyMaterial []byte) (*SessionKeys, error) {
	if len(keyMaterial) == 0 {
		return nil, errors.New("session: empty key material")
	}

	salt := kModeSaltTokenSha256
	info := []byte("session key")

	prk := hkdfExtract(salt, keyMaterial)
	okm, err := hkdfExpand(prk, info, eaxKeySize+eaxNonceBase)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	return &SessionKeys{
		Key:       okm[:eaxKeySize],
		NonceBase: okm[eaxKeySize : eaxKeySize+eaxNonceBase],
	}, nil
}

// BuildNonce constructs the 20-byte EAX nonce for a message.
// nonce = nonceBase(16) || senderID(1) || counter(3, big-endian)
func (sk *SessionKeys) BuildNonce(senderID byte, counter uint32) []byte {
	nonce := make([]byte, eaxNonceBase+1+3) // 20 bytes
	copy(nonce, sk.NonceBase)
	nonce[eaxNonceBase] = senderID
	// 3-byte big-endian counter.
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], counter)
	copy(nonce[eaxNonceBase+1:], buf[1:]) // last 3 bytes
	return nonce
}

// ---- Session cipher ----

// SessionCipher manages encryption/decryption for an active session.
type SessionCipher struct {
	keys       *SessionKeys
	sendCount  uint32 // our send counter
	recvCount  uint32 // expected receive counter
	senderID   byte   // our sender ID
	receiverID byte   // their sender ID
}

// NewSessionCipher creates a new SessionCipher for an active session.
// If isClient is true, we send as senderClient (0x01) and expect to
// receive from senderServer (0x03).
func NewSessionCipher(keys *SessionKeys, isClient bool) *SessionCipher {
	sc := &SessionCipher{
		keys:      keys,
		sendCount: 1, // libuweave pre-increments: counters start at 1
		recvCount: 1,
	}
	if isClient {
		sc.senderID = senderClient
		sc.receiverID = senderServer
	} else {
		sc.senderID = senderServer
		sc.receiverID = senderClient
	}
	return sc
}

// Encrypt encrypts a plaintext message, incrementing the send counter.
// Returns ciphertext with the 12-byte auth tag appended.
func (sc *SessionCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if sc.sendCount > maxCounter {
		return nil, errors.New("session: send counter overflow")
	}

	nonce := sc.keys.BuildNonce(sc.senderID, sc.sendCount)
	sc.sendCount++

	return eaxEncrypt(sc.keys.Key, nonce, plaintext, nil)
}

// Decrypt decrypts and authenticates a message from the peer.
// Returns the plaintext, or an error if authentication fails.
func (sc *SessionCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if sc.recvCount > maxCounter {
		return nil, errors.New("session: receive counter overflow")
	}

	nonce := sc.keys.BuildNonce(sc.receiverID, sc.recvCount)
	sc.recvCount++

	return eaxDecrypt(sc.keys.Key, nonce, ciphertext, nil)
}
