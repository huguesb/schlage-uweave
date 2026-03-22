package schlage_uweave

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// uWeave macaroon MAC tag length (HMAC-SHA256 truncated to 16 bytes).
const macaroonMACLen = 16

// Macaroon represents a deserialized uWeave macaroon.
// A macaroon is a chain of caveats signed with HMAC-SHA256.
type Macaroon struct {
	Caveats [][]byte // raw CBOR bytes of each caveat
	MACTag  []byte   // 16-byte HMAC tag
}

// DeserializeMacaroon decodes a serialized uWeave macaroon.
//
// Wire format (CBOR):
//
//	bstr( array(N) bstr(caveat1) ... bstr(caveatN) bstr(mac_tag) )
//
// The array header specifies N caveats. The MAC tag is appended AFTER the
// N array items (it is not part of the CBOR array).
func DeserializeMacaroon(data []byte) (*Macaroon, error) {
	// Outer layer: CBOR byte string wrapping the body
	v, _, err := cborDecodeValue(data)
	if err != nil {
		return nil, fmt.Errorf("macaroon: failed to decode outer bstr: %w", err)
	}
	body, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("macaroon: expected outer bstr, got %T", v)
	}

	// Decode the CBOR array (contains N caveats)
	arrVal, arrLen, err := cborDecodeValue(body)
	if err != nil {
		return nil, fmt.Errorf("macaroon: failed to decode array: %w", err)
	}
	arr, ok := arrVal.([]interface{})
	if !ok {
		return nil, fmt.Errorf("macaroon: expected array, got %T", arrVal)
	}

	m := &Macaroon{}
	for i, item := range arr {
		cavBytes, ok := item.([]byte)
		if !ok {
			return nil, fmt.Errorf("macaroon: caveat %d: expected bstr, got %T", i, item)
		}
		m.Caveats = append(m.Caveats, cavBytes)
	}

	// MAC tag is a bstr immediately after the array
	remaining := body[arrLen:]
	tagVal, _, err := cborDecodeValue(remaining)
	if err != nil {
		return nil, fmt.Errorf("macaroon: failed to decode mac_tag: %w", err)
	}
	macTag, ok := tagVal.([]byte)
	if !ok {
		return nil, fmt.Errorf("macaroon: mac_tag: expected bstr, got %T", tagVal)
	}
	if len(macTag) != macaroonMACLen {
		return nil, fmt.Errorf("macaroon: mac_tag length %d, expected %d", len(macTag), macaroonMACLen)
	}
	m.MACTag = macTag
	return m, nil
}

// SerializeMacaroon encodes a macaroon to wire format.
//
// Wire format: bstr( array(N) bstr(cav1) ... bstr(cavN) bstr(mac_tag) )
//
// The array contains only the N caveats. The MAC tag is appended after the
// array items (outside the CBOR array).
func SerializeMacaroon(m *Macaroon) ([]byte, error) {
	// Build the inner body: array of caveats, then mac_tag after array
	items := make([]interface{}, len(m.Caveats))
	for i, c := range m.Caveats {
		items[i] = c
	}

	innerBody, err := cborEncodeArray(items)
	if err != nil {
		return nil, fmt.Errorf("macaroon: failed to encode inner array: %w", err)
	}

	// Append MAC tag as a separate bstr after the array
	innerBody = append(innerBody, cborEncodeBytes(m.MACTag)...)

	// Wrap in outer byte string
	return cborEncodeBytes(innerBody), nil
}

// ExtendMacaroon adds a caveat to a macaroon and recomputes the MAC tag.
// contextData is the additional context for caveats that use it (e.g.,
// authentication_challenge uses the session nonce).
func ExtendMacaroon(m *Macaroon, caveatBytes []byte, contextData []byte) (*Macaroon, error) {
	// Sign the new caveat using the current MAC tag as the HMAC key
	newTag, err := macaroonCaveatSign(m.MACTag, caveatBytes, contextData)
	if err != nil {
		return nil, err
	}

	extended := &Macaroon{
		Caveats: make([][]byte, len(m.Caveats)+1),
		MACTag:  newTag,
	}
	copy(extended.Caveats, m.Caveats)
	extended.Caveats[len(m.Caveats)] = caveatBytes

	return extended, nil
}

// macaroonCaveatSign computes the HMAC-SHA256 tag for a single caveat.
//
// For most caveats (no context data):
//
//	HMAC(key, cbor_bstr_header(caveat_len) || caveat_bytes)
//
// For caveats with context data (BleSessionID, AuthenticationChallenge):
//
//	HMAC(key, cbor_bstr_header(total_len) || caveat_bytes || cbor_bstr_header(ctx_len) || ctx_data)
//
// where total_len = len(caveat_bytes) + len(cbor_bstr_header(ctx_len)) + len(ctx_data)
func macaroonCaveatSign(key []byte, caveatBytes []byte, contextData []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)

	if contextData == nil || len(contextData) == 0 {
		// Simple case: no context data
		bstrHeader := cborEncodeTypedUint(cborBytes, uint64(len(caveatBytes)))
		mac.Write(bstrHeader)
		mac.Write(caveatBytes)
	} else {
		// Context data case (authentication_challenge, ble_session_id)
		ctxBstrHeader := cborEncodeTypedUint(cborBytes, uint64(len(contextData)))
		totalLen := len(caveatBytes) + len(ctxBstrHeader) + len(contextData)
		outerBstrHeader := cborEncodeTypedUint(cborBytes, uint64(totalLen))

		mac.Write(outerBstrHeader)
		mac.Write(caveatBytes)
		mac.Write(ctxBstrHeader)
		mac.Write(contextData)
	}

	// Truncate HMAC-SHA256 to 16 bytes
	fullMAC := mac.Sum(nil)
	tag := make([]byte, macaroonMACLen)
	copy(tag, fullMAC)
	return tag, nil
}

// Caveat type constants (from libuweave macaroon_caveat.h)
const (
	caveatTypeAuthenticationChallenge = 20
)

// CreateAuthChallengeCaveat creates an authentication_challenge caveat.
// This is a CBOR-encoded unsigned integer 20 (no value).
func CreateAuthChallengeCaveat() []byte {
	return cborEncodeUint(caveatTypeAuthenticationChallenge)
}
