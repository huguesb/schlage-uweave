package schlage

import (
	"bytes"
	"crypto/elliptic"
	"testing"
)

// TestFixedPointsOnCurve verifies that the hardcoded blinding points KM and
// KN are valid points on the P-224 curve.
func TestFixedPointsOnCurve(t *testing.T) {
	curve := elliptic.P224()

	if !curve.IsOnCurve(kmX, kmY) {
		t.Fatal("KM is not on the P-224 curve")
	}
	if !curve.IsOnCurve(knX, knY) {
		t.Fatal("KN is not on the P-224 curve")
	}
}

// TestPasswordHashing verifies basic properties of the password hash function.
func TestPasswordHashing(t *testing.T) {
	h1 := hashPassword("12345678")
	h2 := hashPassword("12345678")
	h3 := hashPassword("87654321")

	if h1.Cmp(h2) != 0 {
		t.Fatal("same password should produce same hash")
	}
	if h1.Cmp(h3) == 0 {
		t.Fatal("different passwords should produce different hashes")
	}
	// The hash should be at most 28 bytes (224 bits).
	if len(h1.Bytes()) > p224CoordLen {
		t.Fatalf("password hash too large: %d bytes", len(h1.Bytes()))
	}
}

// TestPointEncodeDecode verifies that encoding a point and decoding it back
// produces the original coordinates.
func TestPointEncodeDecode(t *testing.T) {
	encoded := encodePoint(kmX, kmY)
	if len(encoded) != p224PointLen {
		t.Fatalf("encoded length = %d, want %d", len(encoded), p224PointLen)
	}

	x, y, err := decodePoint(encoded)
	if err != nil {
		t.Fatalf("decodePoint: %v", err)
	}
	if x.Cmp(kmX) != 0 || y.Cmp(kmY) != 0 {
		t.Fatal("round-trip encode/decode mismatch")
	}
}

// TestDecodePointInvalidLength checks that decodePoint rejects wrong-sized input.
func TestDecodePointInvalidLength(t *testing.T) {
	_, _, err := decodePoint(make([]byte, 55))
	if err == nil {
		t.Fatal("expected error for invalid length")
	}
}

// TestFullHandshake simulates a complete SPAKE2 handshake between a client
// and a server using the same password, and verifies both sides derive the
// same shared secret and can verify each other's confirmations.
func TestFullHandshake(t *testing.T) {
	password := "12345678"

	// Client generates commitment.
	client, clientCommitment, err := NewSpakeClient(password)
	if err != nil {
		t.Fatalf("NewSpakeClient: %v", err)
	}
	if len(clientCommitment) != p224PointLen {
		t.Fatalf("client commitment length = %d, want %d", len(clientCommitment), p224PointLen)
	}

	// Server generates commitment.
	server, serverCommitment, err := NewSpakeServer(password)
	if err != nil {
		t.Fatalf("NewSpakeServer: %v", err)
	}
	if len(serverCommitment) != p224PointLen {
		t.Fatalf("server commitment length = %d, want %d", len(serverCommitment), p224PointLen)
	}

	// Client computes shared secret from server's commitment.
	clientSecret, err := client.ComputeSecret(serverCommitment)
	if err != nil {
		t.Fatalf("client.ComputeSecret: %v", err)
	}

	// Server computes shared secret from client's commitment.
	serverSecret, err := server.ComputeServerSecret(clientCommitment)
	if err != nil {
		t.Fatalf("server.ComputeServerSecret: %v", err)
	}

	// Both sides must derive the same shared secret.
	if !bytes.Equal(clientSecret, serverSecret) {
		t.Fatalf("shared secrets differ:\n  client: %x\n  server: %x", clientSecret, serverSecret)
	}

	// Key confirmation: client sends confirmation to server.
	clientConf, err := client.ComputeConfirmation()
	if err != nil {
		t.Fatalf("client.ComputeConfirmation: %v", err)
	}

	// Server verifies client's confirmation.
	if err := server.VerifyConfirmation(clientConf); err != nil {
		t.Fatalf("server.VerifyConfirmation: %v", err)
	}

	// Server sends confirmation to client.
	serverConf, err := server.ComputeConfirmation()
	if err != nil {
		t.Fatalf("server.ComputeConfirmation: %v", err)
	}

	// Client verifies server's confirmation.
	if err := client.VerifyConfirmation(serverConf); err != nil {
		t.Fatalf("client.VerifyConfirmation: %v", err)
	}
}

// TestShortPassword verifies the handshake works with a minimal 4-character
// password.
func TestShortPassword(t *testing.T) {
	password := "1234"

	client, clientCommitment, err := NewSpakeClient(password)
	if err != nil {
		t.Fatalf("NewSpakeClient: %v", err)
	}

	server, serverCommitment, err := NewSpakeServer(password)
	if err != nil {
		t.Fatalf("NewSpakeServer: %v", err)
	}

	clientSecret, err := client.ComputeSecret(serverCommitment)
	if err != nil {
		t.Fatalf("client.ComputeSecret: %v", err)
	}

	serverSecret, err := server.ComputeServerSecret(clientCommitment)
	if err != nil {
		t.Fatalf("server.ComputeServerSecret: %v", err)
	}

	if !bytes.Equal(clientSecret, serverSecret) {
		t.Fatalf("shared secrets differ for short password:\n  client: %x\n  server: %x", clientSecret, serverSecret)
	}
}

// TestWrongPasswordDifferentSecrets verifies that when the client and server
// use different passwords, they derive different shared secrets.
func TestWrongPasswordDifferentSecrets(t *testing.T) {
	client, clientCommitment, err := NewSpakeClient("12345678")
	if err != nil {
		t.Fatalf("NewSpakeClient: %v", err)
	}

	server, serverCommitment, err := NewSpakeServer("87654321")
	if err != nil {
		t.Fatalf("NewSpakeServer: %v", err)
	}

	clientSecret, err := client.ComputeSecret(serverCommitment)
	if err != nil {
		t.Fatalf("client.ComputeSecret: %v", err)
	}

	serverSecret, err := server.ComputeServerSecret(clientCommitment)
	if err != nil {
		t.Fatalf("server.ComputeServerSecret: %v", err)
	}

	if bytes.Equal(clientSecret, serverSecret) {
		t.Fatal("different passwords should produce different shared secrets")
	}
}

// TestWrongConfirmationRejected verifies that a bogus confirmation value is
// rejected.
func TestWrongConfirmationRejected(t *testing.T) {
	password := "12345678"

	client, clientCommitment, err := NewSpakeClient(password)
	if err != nil {
		t.Fatalf("NewSpakeClient: %v", err)
	}

	server, serverCommitment, err := NewSpakeServer(password)
	if err != nil {
		t.Fatalf("NewSpakeServer: %v", err)
	}

	if _, err := client.ComputeSecret(serverCommitment); err != nil {
		t.Fatalf("client.ComputeSecret: %v", err)
	}
	if _, err := server.ComputeServerSecret(clientCommitment); err != nil {
		t.Fatalf("server.ComputeServerSecret: %v", err)
	}

	// Fabricate a bogus confirmation.
	bogus := make([]byte, 32)
	for i := range bogus {
		bogus[i] = 0xFF
	}

	if err := server.VerifyConfirmation(bogus); err == nil {
		t.Fatal("expected verification to fail with bogus confirmation")
	}
}

// TestInvalidCommitmentRejected verifies that a commitment that is not on the
// curve is rejected.
func TestInvalidCommitmentRejected(t *testing.T) {
	client, _, err := NewSpakeClient("12345678")
	if err != nil {
		t.Fatalf("NewSpakeClient: %v", err)
	}

	// All-zero is not a valid curve point (it's the point at infinity).
	badCommitment := make([]byte, p224PointLen)
	_, err = client.ComputeSecret(badCommitment)
	if err == nil {
		t.Fatal("expected error for invalid commitment")
	}
}
