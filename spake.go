// Package schlage implements BLE communication with Schlage locks using the
// uWeave protocol. This file implements the SPAKE2 key exchange over NIST P-224,
// used by the Schlage/uWeave pairing protocol.
package schlage_uweave

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// P-224 curve point size in bytes. Each coordinate is 28 bytes, and a raw
// (uncompressed, no prefix) point encoding is 56 bytes.
const (
	p224CoordLen = 28
	p224PointLen = 2 * p224CoordLen // 56 bytes: X || Y
)

// Fixed blinding points for the uWeave SPAKE2 protocol.
// KM is the client blinding point; KN is the server blinding point.
var (
	kmX, _ = new(big.Int).SetString("4D48C8EA8D23392E07E851FA6AA82048094E051372499C6FBA62A74B", 16)
	kmY, _ = new(big.Int).SetString("6C185CABD52E2E8A9E2D21B0EC4EE141211FE29D64EA4D04463AE833", 16)

	knX, _ = new(big.Int).SetString("0B1CFC6A407CDCB15DC1704CD13EDAAB8FDEFF8CFBFB50D2C81DE2C2", 16)
	knY, _ = new(big.Int).SetString("3E14F62996080907B56DD282071AA7A121C39934BC30DA5BCBC6A3CC", 16)
)

// SpakeState represents the state of a SPAKE2 handshake.
type SpakeState struct {
	curve    elliptic.Curve
	x        *big.Int // our random scalar
	pwHash   *big.Int // hashed password (first 28 bytes of SHA-256)
	ourMsg   []byte   // our commitment (56 bytes)
	theirMsg []byte   // their commitment (56 bytes)
	secret   []byte   // shared secret (56 bytes)
}

// hashPassword computes the password hash used in the SPAKE2 protocol:
// SHA-256 of the raw password bytes, truncated to 28 bytes and interpreted
// as a big-endian unsigned integer.
func hashPassword(password string) *big.Int {
	h := sha256.Sum256([]byte(password))
	// Take the first 28 bytes (224 bits) to match the P-224 field size.
	return new(big.Int).SetBytes(h[:p224CoordLen])
}

// encodePoint encodes an elliptic curve point as 56 raw bytes: X (28 bytes,
// big-endian) || Y (28 bytes, big-endian). No 0x04 prefix byte—this matches
// the encoding used by the Schlage/uWeave protocol.
func encodePoint(x, y *big.Int) []byte {
	buf := make([]byte, p224PointLen)
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	// Pad to 28 bytes and copy into the output buffer, right-aligned.
	copy(buf[p224CoordLen-len(xBytes):p224CoordLen], xBytes)
	copy(buf[p224PointLen-len(yBytes):p224PointLen], yBytes)
	return buf
}

// decodePoint decodes a 56-byte raw point encoding into X, Y coordinates.
func decodePoint(data []byte) (*big.Int, *big.Int, error) {
	if len(data) != p224PointLen {
		return nil, nil, fmt.Errorf("spake: invalid point length %d, expected %d", len(data), p224PointLen)
	}
	x := new(big.Int).SetBytes(data[:p224CoordLen])
	y := new(big.Int).SetBytes(data[p224CoordLen:])
	return x, y, nil
}

// NewSpakeClient creates a new SPAKE2 client-side handshake.
// password is the pairing code (e.g., the 8-digit code from the lock).
// Returns the SpakeState and the 56-byte commitment to send to the server.
//
// Protocol step:
//
//	passwordHash = SHA256(password)[0:28] as big-endian integer
//	x            = random scalar in [1, order-1]
//	T            = x*G + passwordHash*KM
func NewSpakeClient(password string) (*SpakeState, []byte, error) {
	curve := elliptic.P224()
	order := curve.Params().N

	// Hash the password.
	pwHash := hashPassword(password)

	// Generate a random scalar x in [1, order-1].
	x, err := rand.Int(rand.Reader, new(big.Int).Sub(order, big.NewInt(1)))
	if err != nil {
		return nil, nil, fmt.Errorf("spake: failed to generate random scalar: %w", err)
	}
	x.Add(x, big.NewInt(1)) // shift from [0, order-2] to [1, order-1]

	// Compute T = x*G + passwordHash*KM.
	// First term: x*G (scalar multiplication of the generator).
	xGx, xGy := curve.ScalarBaseMult(x.Bytes())
	// Second term: passwordHash*KM.
	pwKMx, pwKMy := curve.ScalarMult(kmX, kmY, pwHash.Bytes())
	// Add the two points.
	tX, tY := curve.Add(xGx, xGy, pwKMx, pwKMy)

	commitment := encodePoint(tX, tY)

	state := &SpakeState{
		curve:  curve,
		x:      x,
		pwHash: pwHash,
		ourMsg: commitment,
	}
	return state, commitment, nil
}

// NewSpakeServer creates a new SPAKE2 server-side handshake. This is used
// for testing—the actual lock plays the server role over BLE.
//
// Protocol step:
//
//	y            = random scalar in [1, order-1]
//	S            = y*G + passwordHash*KN
func NewSpakeServer(password string) (*SpakeState, []byte, error) {
	curve := elliptic.P224()
	order := curve.Params().N

	pwHash := hashPassword(password)

	// Generate random scalar y in [1, order-1].
	y, err := rand.Int(rand.Reader, new(big.Int).Sub(order, big.NewInt(1)))
	if err != nil {
		return nil, nil, fmt.Errorf("spake: failed to generate random scalar: %w", err)
	}
	y.Add(y, big.NewInt(1))

	// Compute S = y*G + passwordHash*KN.
	yGx, yGy := curve.ScalarBaseMult(y.Bytes())
	pwKNx, pwKNy := curve.ScalarMult(knX, knY, pwHash.Bytes())
	sX, sY := curve.Add(yGx, yGy, pwKNx, pwKNy)

	commitment := encodePoint(sX, sY)

	state := &SpakeState{
		curve:  curve,
		x:      y, // reuse field; this is the server's random scalar
		pwHash: pwHash,
		ourMsg: commitment,
	}
	return state, commitment, nil
}

// ComputeSecret processes the peer's 56-byte commitment and computes the
// shared secret.
//
// Client side: K = x * (S - passwordHash*KN)
// Server side: K = y * (T - passwordHash*KM)
//
// The caller is responsible for passing the correct peer commitment. The
// role (client vs. server) is determined by which blinding point to subtract.
// For simplicity we expose ComputeClientSecret and ComputeServerSecret as
// the public helpers; ComputeSecret dispatches to the client path by default.
func (s *SpakeState) ComputeSecret(peerCommitment []byte) ([]byte, error) {
	return s.computeSecret(peerCommitment, knX, knY)
}

// ComputeServerSecret is the server-side variant of ComputeSecret.
// It subtracts passwordHash*KM (the client blinding point) instead of KN.
func (s *SpakeState) ComputeServerSecret(peerCommitment []byte) ([]byte, error) {
	return s.computeSecret(peerCommitment, kmX, kmY)
}

// computeSecret is the shared implementation for both client and server.
// blindX, blindY is KN for the client or KM for the server.
func (s *SpakeState) computeSecret(peerCommitment []byte, blindX, blindY *big.Int) ([]byte, error) {
	curve := s.curve

	pX, pY, err := decodePoint(peerCommitment)
	if err != nil {
		return nil, err
	}
	if !curve.IsOnCurve(pX, pY) {
		return nil, errors.New("spake: peer commitment is not on the curve")
	}

	s.theirMsg = make([]byte, len(peerCommitment))
	copy(s.theirMsg, peerCommitment)

	// Compute passwordHash * blindingPoint.
	pwBx, pwBy := curve.ScalarMult(blindX, blindY, s.pwHash.Bytes())

	// Negate the Y coordinate to subtract: -(pwBx, pwBy) = (pwBx, -pwBy mod p).
	p := curve.Params().P
	negPwBy := new(big.Int).Neg(pwBy)
	negPwBy.Mod(negPwBy, p)

	// Compute peerPoint - passwordHash*blindingPoint.
	diffX, diffY := curve.Add(pX, pY, pwBx, negPwBy)

	// Multiply by our secret scalar.
	kX, kY := curve.ScalarMult(diffX, diffY, s.x.Bytes())

	s.secret = encodePoint(kX, kY)
	return s.secret, nil
}

// ComputeConfirmation computes the HMAC-SHA256 confirmation value to send
// to the peer.
//
// The key derivation follows the standard SPAKE2 confirmation pattern:
//
//	hashInput  = ourCommitment || theirCommitment || sharedSecret
//	confirmKey = SHA256(hashInput)
//	confirmation = HMAC-SHA256(confirmKey, theirCommitment)
func (s *SpakeState) ComputeConfirmation() ([]byte, error) {
	if s.secret == nil {
		return nil, errors.New("spake: shared secret not yet computed")
	}
	key := s.deriveConfirmKey(s.ourMsg, s.theirMsg)
	mac := hmac.New(sha256.New, key)
	mac.Write(s.theirMsg)
	return mac.Sum(nil), nil
}

// VerifyConfirmation verifies the peer's HMAC-SHA256 confirmation value.
//
// The peer computes their confirmation with the roles reversed:
//
//	hashInput  = theirCommitment || ourCommitment || sharedSecret
//	confirmKey = SHA256(hashInput)
//	expected   = HMAC-SHA256(confirmKey, ourCommitment)
func (s *SpakeState) VerifyConfirmation(peerConfirmation []byte) error {
	if s.secret == nil {
		return errors.New("spake: shared secret not yet computed")
	}
	// The peer's confirm key is derived with the order reversed.
	key := s.deriveConfirmKey(s.theirMsg, s.ourMsg)
	mac := hmac.New(sha256.New, key)
	mac.Write(s.ourMsg)
	expected := mac.Sum(nil)

	if !hmac.Equal(expected, peerConfirmation) {
		return errors.New("spake: confirmation mismatch")
	}
	return nil
}

// deriveConfirmKey computes SHA-256(senderMsg || receiverMsg || sharedSecret)
// which is used as the HMAC key for confirmation messages.
func (s *SpakeState) deriveConfirmKey(senderMsg, receiverMsg []byte) []byte {
	h := sha256.New()
	h.Write(senderMsg)
	h.Write(receiverMsg)
	h.Write(s.secret)
	key := h.Sum(nil)
	return key
}
