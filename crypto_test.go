package schlage

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// mustHex decodes a hex string, panicking on error. For test convenience.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// ---- CMAC tests (RFC 4493 test vectors) ----

func TestCMACRFC4493(t *testing.T) {
	// RFC 4493 Section 4: AES-CMAC test vectors with key K.
	key := mustHex("2b7e151628aed2a6abf7158809cf4f3c")

	tests := []struct {
		name     string
		data     string // hex
		expected string // hex
	}{
		{
			name:     "empty message",
			data:     "",
			expected: "bb1d6929e95937287fa37d129b756746",
		},
		{
			name:     "16-byte message",
			data:     "6bc1bee22e409f96e93d7e117393172a",
			expected: "070a16b46b4d4144f79bdd9dd04a287c",
		},
		{
			name:     "40-byte message",
			data:     "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			expected: "dfa66747de9ae63030ca32611497c827",
		},
		{
			name:     "64-byte message",
			data:     "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			expected: "51f0bebf7e3b9d92fc49741779363cfe",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := mustHex(tc.data)
			expected := mustHex(tc.expected)
			got := cmac(key, data)
			if !bytes.Equal(got, expected) {
				t.Errorf("CMAC mismatch:\n  got:    %x\n  expect: %x", got, expected)
			}
		})
	}
}

// ---- EAX tests ----

func TestEAXRoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 20)
	for i := range nonce {
		nonce[i] = byte(i + 0x80)
	}
	plaintext := []byte("hello, uWeave session encryption!")

	ct, err := eaxEncrypt(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Ciphertext should be plaintext length + tag size.
	if len(ct) != len(plaintext)+eaxTagSize {
		t.Fatalf("ciphertext length: got %d, want %d", len(ct), len(plaintext)+eaxTagSize)
	}

	pt, err := eaxDecrypt(key, nonce, ct, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("plaintext mismatch:\n  got:    %q\n  expect: %q", pt, plaintext)
	}
}

func TestEAXAuthFailure(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	plaintext := []byte("test data")

	ct, err := eaxEncrypt(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Tamper with the ciphertext body (not the tag).
	ct[0] ^= 0xff

	_, err = eaxDecrypt(key, nonce, ct, nil)
	if err == nil {
		t.Fatal("expected authentication error after tampering, got nil")
	}
}

func TestEAXWithAAD(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i * 3)
	}
	nonce := make([]byte, 12)
	plaintext := []byte("authenticated data test")
	aad := []byte("additional authenticated data")

	ct, err := eaxEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Decrypt with correct AAD should succeed.
	pt, err := eaxDecrypt(key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("plaintext mismatch")
	}

	// Decrypt with wrong AAD should fail.
	_, err = eaxDecrypt(key, nonce, ct, []byte("wrong aad"))
	if err == nil {
		t.Fatal("expected error with wrong AAD")
	}

	// Decrypt with no AAD should fail.
	_, err = eaxDecrypt(key, nonce, ct, nil)
	if err == nil {
		t.Fatal("expected error with missing AAD")
	}
}

func TestEAXKnownVector(t *testing.T) {
	// EAX test vectors from the original EAX paper (Bellare, Rogaway, Wagner).
	// The paper uses full 16-byte tags; we truncate to 12 bytes.
	// Each entry: key, nonce, header, msg, expected full ciphertext||tag (16-byte tag).
	type vector struct {
		name                          string
		key, nonce, header, msg, ctag string
	}
	vectors := []vector{
		{
			name:   "paper vector 2 (2-byte msg)",
			key:    "91945D3F4DCBEE0BF45EF52255F095A4",
			nonce:  "BECAF043B0A23D843194BA972C66DEBD",
			header: "FA3BFD4806EB53FA",
			msg:    "F7FB",
			ctag:   "19DD5C4C9331049D0BDAB0277408F67967E5",
		},
		{
			name:   "paper vector 3 (5-byte msg)",
			key:    "01F74AD64077F2E704C0F60ADA3DD523",
			nonce:  "70C3DB4F0D26368400A10ED05D2BFF5E",
			header: "234A3463C1264AC6",
			msg:    "1A47CB4933",
			ctag:   "D851D5BAE03A59F238A23E39199DC9266626C40F80",
		},
		{
			name:   "paper vector 4 (5-byte msg)",
			key:    "D07CF6CBB7F313BDDE66B727AFD3C5E8",
			nonce:  "8408DFFF3C1A2B1292DC199E46B7D617",
			header: "33CCE2EABFF5A79D",
			msg:    "481C9E39B1",
			ctag:   "632A9D131AD4C168A4225D8E1FF755939974A7BEDE",
		},
		{
			name:   "paper vector 5 (6-byte msg)",
			key:    "35B6D0580005BBC12B0587124557D2C2",
			nonce:  "FDB6B06676EEDC5C61D74276E1F8E816",
			header: "AEB96EAEBE2970E9",
			msg:    "40D0C07DA5E4",
			ctag:   "071DFE16C675CB0677E536F73AFE6A14B74EE49844DD",
		},
		{
			name:   "paper vector 6 (12-byte msg)",
			key:    "BD8E6E11475E60B268784C38C62FEB22",
			nonce:  "6EAC5C93072D8E8513F750935E46DA1B",
			header: "D4482D1CA78DCE0F",
			msg:    "4DE3B35C3FC039245BD1FB7D",
			ctag:   "835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			key := mustHex(v.key)
			nonce := mustHex(v.nonce)
			header := mustHex(v.header)
			msg := mustHex(v.msg)
			expectedFull := mustHex(v.ctag)

			ct, err := eaxEncrypt(key, nonce, msg, header)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			msgLen := len(msg)

			// Our output: ciphertext(msgLen) + 12-byte tag.
			// Known vector: ciphertext(msgLen) + 16-byte tag.
			// The ciphertext bytes and first 12 tag bytes must match.
			expectedCT := expectedFull[:msgLen]
			expectedTag12 := expectedFull[msgLen : msgLen+eaxTagSize]

			gotCT := ct[:msgLen]
			gotTag := ct[msgLen:]

			if !bytes.Equal(gotCT, expectedCT) {
				t.Errorf("ciphertext mismatch:\n  got:    %x\n  expect: %x", gotCT, expectedCT)
			}
			if !bytes.Equal(gotTag, expectedTag12) {
				t.Errorf("tag mismatch:\n  got:    %x\n  expect: %x", gotTag, expectedTag12)
			}

			// Verify round-trip decryption with our truncated tag.
			pt, err := eaxDecrypt(key, nonce, ct, header)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(pt, msg) {
				t.Errorf("plaintext mismatch: got %x, want %x", pt, msg)
			}
		})
	}
}

func TestEAXEmptyPlaintext(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)

	ct, err := eaxEncrypt(key, nonce, nil, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ct) != eaxTagSize {
		t.Fatalf("expected %d bytes, got %d", eaxTagSize, len(ct))
	}

	pt, err := eaxDecrypt(key, nonce, ct, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(pt) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(pt))
	}
}

// ---- HKDF tests ----

func TestHKDF(t *testing.T) {
	// Verify deterministic output: same input -> same output.
	keyMaterial := make([]byte, 41)
	keyMaterial[0] = 0x02
	for i := 1; i < len(keyMaterial); i++ {
		keyMaterial[i] = byte(i)
	}

	keys1, err := DeriveSessionKeys(keyMaterial)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}

	keys2, err := DeriveSessionKeys(keyMaterial)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}

	if !bytes.Equal(keys1.Key, keys2.Key) {
		t.Error("Key derivation not deterministic")
	}
	if !bytes.Equal(keys1.NonceBase, keys2.NonceBase) {
		t.Error("NonceBase derivation not deterministic")
	}

	// Key and nonce base should be 16 bytes each.
	if len(keys1.Key) != eaxKeySize {
		t.Errorf("Key length: got %d, want %d", len(keys1.Key), eaxKeySize)
	}
	if len(keys1.NonceBase) != eaxNonceBase {
		t.Errorf("NonceBase length: got %d, want %d", len(keys1.NonceBase), eaxNonceBase)
	}

	// Different key material should produce different keys.
	keyMaterial2 := make([]byte, 41)
	copy(keyMaterial2, keyMaterial)
	keyMaterial2[5] ^= 0xff

	keys3, err := DeriveSessionKeys(keyMaterial2)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}
	if bytes.Equal(keys1.Key, keys3.Key) {
		t.Error("Different input produced same key")
	}
}

func TestHKDFExtractExpand(t *testing.T) {
	// RFC 5869 Test Case 1 (SHA-256):
	//   IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
	//   salt = 0x000102030405060708090a0b0c (13 bytes)
	//   info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
	//   L    = 42
	//   PRK  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
	//   OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
	ikm := mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex("000102030405060708090a0b0c")
	info := mustHex("f0f1f2f3f4f5f6f7f8f9")
	expectedPRK := mustHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	expectedOKM := mustHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	prk := hkdfExtract(salt, ikm)
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("HKDF-Extract mismatch:\n  got:    %x\n  expect: %x", prk, expectedPRK)
	}

	okm, err := hkdfExpand(prk, info, 42)
	if err != nil {
		t.Fatalf("HKDF-Expand: %v", err)
	}
	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("HKDF-Expand mismatch:\n  got:    %x\n  expect: %x", okm, expectedOKM)
	}
}

func TestDeriveSessionKeysEmpty(t *testing.T) {
	_, err := DeriveSessionKeys(nil)
	if err == nil {
		t.Fatal("expected error for nil key material")
	}
	_, err = DeriveSessionKeys([]byte{})
	if err == nil {
		t.Fatal("expected error for empty key material")
	}
}

// ---- Session nonce construction ----

func TestBuildNonce(t *testing.T) {
	keys := &SessionKeys{
		Key:       make([]byte, 16),
		NonceBase: make([]byte, 16),
	}
	// Fill nonce base with recognizable pattern.
	for i := range keys.NonceBase {
		keys.NonceBase[i] = byte(0xA0 + i)
	}

	nonce := keys.BuildNonce(senderClient, 0x000042)

	// Total length should be 20.
	if len(nonce) != 20 {
		t.Fatalf("nonce length: got %d, want 20", len(nonce))
	}

	// First 16 bytes should be the nonce base.
	if !bytes.Equal(nonce[:16], keys.NonceBase) {
		t.Error("nonce base portion mismatch")
	}

	// Byte 16 should be senderID.
	if nonce[16] != senderClient {
		t.Errorf("sender ID: got %02x, want %02x", nonce[16], senderClient)
	}

	// Bytes 17-19 should be big-endian counter 0x000042.
	if nonce[17] != 0x00 || nonce[18] != 0x00 || nonce[19] != 0x42 {
		t.Errorf("counter bytes: got %02x%02x%02x, want 000042", nonce[17], nonce[18], nonce[19])
	}
}

func TestBuildNonceCounterWrap(t *testing.T) {
	keys := &SessionKeys{
		Key:       make([]byte, 16),
		NonceBase: make([]byte, 16),
	}

	// Test with max 3-byte counter value.
	nonce := keys.BuildNonce(senderServer, 0xFFFFFF)
	if nonce[17] != 0xFF || nonce[18] != 0xFF || nonce[19] != 0xFF {
		t.Errorf("max counter: got %02x%02x%02x, want ffffff", nonce[17], nonce[18], nonce[19])
	}

	// Test counter zero.
	nonce = keys.BuildNonce(senderClient, 0)
	if nonce[17] != 0 || nonce[18] != 0 || nonce[19] != 0 {
		t.Errorf("zero counter: got %02x%02x%02x, want 000000", nonce[17], nonce[18], nonce[19])
	}
}

// ---- SessionCipher tests ----

func TestSessionCipherRoundTrip(t *testing.T) {
	// Simulate a client-server encrypted session.
	keyMaterial := make([]byte, 41)
	keyMaterial[0] = 0x02
	for i := 1; i < len(keyMaterial); i++ {
		keyMaterial[i] = byte(i * 7)
	}

	keys, err := DeriveSessionKeys(keyMaterial)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}

	client := NewSessionCipher(keys, true)
	server := NewSessionCipher(keys, false)

	// Client sends to server.
	msg1 := []byte("hello from client")
	ct1, err := client.Encrypt(msg1)
	if err != nil {
		t.Fatalf("client encrypt: %v", err)
	}
	pt1, err := server.Decrypt(ct1)
	if err != nil {
		t.Fatalf("server decrypt: %v", err)
	}
	if !bytes.Equal(pt1, msg1) {
		t.Errorf("message 1 mismatch: got %q, want %q", pt1, msg1)
	}

	// Server sends to client.
	msg2 := []byte("hello from server")
	ct2, err := server.Encrypt(msg2)
	if err != nil {
		t.Fatalf("server encrypt: %v", err)
	}
	pt2, err := client.Decrypt(ct2)
	if err != nil {
		t.Fatalf("client decrypt: %v", err)
	}
	if !bytes.Equal(pt2, msg2) {
		t.Errorf("message 2 mismatch: got %q, want %q", pt2, msg2)
	}

	// Multiple messages in one direction — counters should advance.
	for i := 0; i < 10; i++ {
		msg := []byte("client message " + string(rune('0'+i)))
		ct, err := client.Encrypt(msg)
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		pt, err := server.Decrypt(ct)
		if err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Errorf("message %d mismatch", i)
		}
	}
}

func TestSessionCipherCrossDecryptFails(t *testing.T) {
	keyMaterial := make([]byte, 41)
	keyMaterial[0] = 0x02

	keys, err := DeriveSessionKeys(keyMaterial)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}

	client := NewSessionCipher(keys, true)
	server := NewSessionCipher(keys, false)

	// Client encrypts, but client tries to decrypt its own message — should fail
	// because sender IDs won't match.
	ct, err := client.Encrypt([]byte("test"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Create another client cipher to try decrypting.
	client2 := NewSessionCipher(keys, true)
	_, err = client2.Decrypt(ct)
	if err == nil {
		t.Fatal("expected error: client should not decrypt its own messages")
	}

	// But server can decrypt it.
	_, err = server.Decrypt(ct)
	if err != nil {
		t.Fatalf("server should decrypt client message: %v", err)
	}
}

func TestSessionCipherCounterOverflow(t *testing.T) {
	keyMaterial := make([]byte, 41)
	keyMaterial[0] = 0x02

	keys, err := DeriveSessionKeys(keyMaterial)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}

	client := NewSessionCipher(keys, true)

	// Set counter to max value.
	client.sendCount = maxCounter + 1

	_, err = client.Encrypt([]byte("overflow"))
	if err == nil {
		t.Fatal("expected counter overflow error")
	}

	// Same for receive side.
	server := NewSessionCipher(keys, false)
	server.recvCount = maxCounter + 1

	_, err = server.Decrypt(make([]byte, eaxTagSize+1))
	if err == nil {
		t.Fatal("expected counter overflow error on decrypt")
	}
}

func TestSessionCipherSenderIDs(t *testing.T) {
	keyMaterial := make([]byte, 41)
	keyMaterial[0] = 0x02

	keys, err := DeriveSessionKeys(keyMaterial)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}

	client := NewSessionCipher(keys, true)
	server := NewSessionCipher(keys, false)

	if client.senderID != senderClient {
		t.Errorf("client senderID: got %02x, want %02x", client.senderID, senderClient)
	}
	if client.receiverID != senderServer {
		t.Errorf("client receiverID: got %02x, want %02x", client.receiverID, senderServer)
	}
	if server.senderID != senderServer {
		t.Errorf("server senderID: got %02x, want %02x", server.senderID, senderServer)
	}
	if server.receiverID != senderClient {
		t.Errorf("server receiverID: got %02x, want %02x", server.receiverID, senderClient)
	}
}
