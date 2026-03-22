package schlage

import (
	"bytes"
	"reflect"
	"testing"
)

// ---------------------------------------------------------------------------
// CBOR uint encoding edge cases
// ---------------------------------------------------------------------------

func TestCborEncodeUint(t *testing.T) {
	tests := []struct {
		name string
		val  uint64
		want []byte
	}{
		{"zero", 0, []byte{0x00}},
		{"small (23)", 23, []byte{0x17}},
		{"one-byte (24)", 24, []byte{0x18, 0x18}},
		{"one-byte (255)", 255, []byte{0x18, 0xff}},
		{"two-byte (256)", 256, []byte{0x19, 0x01, 0x00}},
		{"two-byte (65535)", 65535, []byte{0x19, 0xff, 0xff}},
		{"four-byte (65536)", 65536, []byte{0x1a, 0x00, 0x01, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cborEncodeUint(tt.val)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("cborEncodeUint(%d) = %x, want %x", tt.val, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CBOR negative int encoding
// ---------------------------------------------------------------------------

func TestCborEncodeNegativeInt(t *testing.T) {
	// -1 should be 0x20, -10 should be 0x29
	got := cborEncodeInt(-1)
	if !bytes.Equal(got, []byte{0x20}) {
		t.Errorf("cborEncodeInt(-1) = %x, want 20", got)
	}
	got = cborEncodeInt(-10)
	if !bytes.Equal(got, []byte{0x29}) {
		t.Errorf("cborEncodeInt(-10) = %x, want 29", got)
	}
}

// ---------------------------------------------------------------------------
// CBOR byte string encoding/decoding
// ---------------------------------------------------------------------------

func TestCborBytesRoundTrip(t *testing.T) {
	// Test various sizes including a 56-byte SPAKE commitment
	inputs := [][]byte{
		{},
		{0x01, 0x02, 0x03},
		bytes.Repeat([]byte{0xAB}, 56), // SPAKE commitment size
		bytes.Repeat([]byte{0xCD}, 300),
	}
	for _, input := range inputs {
		encoded := cborEncodeBytes(input)
		decoded, n, err := cborDecodeValue(encoded)
		if err != nil {
			t.Fatalf("decode error for len=%d: %v", len(input), err)
		}
		if n != len(encoded) {
			t.Errorf("consumed %d bytes, expected %d", n, len(encoded))
		}
		got, ok := decoded.([]byte)
		if !ok {
			t.Fatalf("expected []byte, got %T", decoded)
		}
		if !bytes.Equal(got, input) {
			t.Errorf("round-trip mismatch for len=%d", len(input))
		}
	}
}

// ---------------------------------------------------------------------------
// CBOR string encoding/decoding
// ---------------------------------------------------------------------------

func TestCborStringRoundTrip(t *testing.T) {
	inputs := []string{"", "hello", "lock", "unlock"}
	for _, input := range inputs {
		encoded := cborEncodeString(input)
		decoded, _, err := cborDecodeValue(encoded)
		if err != nil {
			t.Fatalf("decode error for %q: %v", input, err)
		}
		got, ok := decoded.(string)
		if !ok {
			t.Fatalf("expected string, got %T", decoded)
		}
		if got != input {
			t.Errorf("got %q, want %q", got, input)
		}
	}
}

// ---------------------------------------------------------------------------
// CBOR map encode/decode round-trip with various value types
// ---------------------------------------------------------------------------

func TestCborMapRoundTrip(t *testing.T) {
	original := map[int]interface{}{
		0:  42,
		1:  []byte{0xDE, 0xAD},
		2:  "hello",
		16: map[int]interface{}{0: 99, 1: "nested"},
	}

	encoded, err := cborEncodeMap(original)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	decoded, err := cborDecodeMap(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	// Check each key individually since int vs int64 comparison matters
	if cborInt(decoded[0]) != 42 {
		t.Errorf("key 0: got %v, want 42", decoded[0])
	}
	if !bytes.Equal(decoded[1].([]byte), []byte{0xDE, 0xAD}) {
		t.Errorf("key 1: got %v, want [DE AD]", decoded[1])
	}
	if decoded[2].(string) != "hello" {
		t.Errorf("key 2: got %v, want hello", decoded[2])
	}

	nested, ok := decoded[16].(map[int]interface{})
	if !ok {
		t.Fatalf("key 16: expected map, got %T", decoded[16])
	}
	if cborInt(nested[0]) != 99 {
		t.Errorf("key 16/0: got %v, want 99", nested[0])
	}
	if nested[1].(string) != "nested" {
		t.Errorf("key 16/1: got %v, want nested", nested[1])
	}
}

// ---------------------------------------------------------------------------
// CBOR array round-trip
// ---------------------------------------------------------------------------

func TestCborArrayRoundTrip(t *testing.T) {
	arr := []interface{}{int(1), int(2), "three"}
	encoded, err := cborEncodeArray(arr)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}
	decoded, _, err := cborDecodeValue(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	got, ok := decoded.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", decoded)
	}
	if len(got) != 3 {
		t.Fatalf("len=%d, want 3", len(got))
	}
	if cborInt(got[0]) != 1 || cborInt(got[1]) != 2 {
		t.Errorf("unexpected integer values")
	}
	if got[2].(string) != "three" {
		t.Errorf("got %q, want three", got[2])
	}
}

// ---------------------------------------------------------------------------
// PrivetRequest encoding produces valid CBOR that decodes back
// ---------------------------------------------------------------------------

func TestPrivetRequestRoundTrip(t *testing.T) {
	params := map[int]interface{}{
		0: 1,
		1: "test",
	}
	data := PrivetRequest(APIData, RequestIDReadData, params)

	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	// No version field should be present
	if _, ok := m[0]; ok {
		t.Errorf("version field (key 0) should not be present")
	}
	if cborInt(m[privetKeyAPI]) != APIData {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIData)
	}
	if cborInt(m[privetKeyRequestID]) != RequestIDReadData {
		t.Errorf("requestID = %v, want %d", m[privetKeyRequestID], RequestIDReadData)
	}

	p, ok := m[privetKeyParams].(map[int]interface{})
	if !ok {
		t.Fatalf("params: expected map, got %T", m[privetKeyParams])
	}
	if cborInt(p[0]) != 1 {
		t.Errorf("params[0] = %v, want 1", p[0])
	}
	if p[1].(string) != "test" {
		t.Errorf("params[1] = %v, want test", p[1])
	}
}

// ---------------------------------------------------------------------------
// ParsePrivetResponse — success
// ---------------------------------------------------------------------------

func TestParsePrivetResponseSuccess(t *testing.T) {
	resp := map[int]interface{}{
		privetKeyRequestID: 7,
		privetKeyResult: map[int]interface{}{
			0: "ok",
			1: 200,
		},
	}
	data, err := cborEncodeMap(resp)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	parsed, err := ParsePrivetResponse(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if parsed.RequestID != 7 {
		t.Errorf("requestID = %d, want 7", parsed.RequestID)
	}
	if parsed.Error != nil {
		t.Errorf("unexpected error: %v", parsed.Error)
	}
	if parsed.Result == nil {
		t.Fatal("result is nil")
	}
	if parsed.Result[0].(string) != "ok" {
		t.Errorf("result[0] = %v, want ok", parsed.Result[0])
	}
	if cborInt(parsed.Result[1]) != 200 {
		t.Errorf("result[1] = %v, want 200", parsed.Result[1])
	}
}

// ---------------------------------------------------------------------------
// ParsePrivetResponse — error
// ---------------------------------------------------------------------------

func TestParsePrivetResponseError(t *testing.T) {
	resp := map[int]interface{}{
		privetKeyRequestID: 3,
		privetKeyError: map[int]interface{}{
			privetKeyErrorCode: 403,
			privetKeyErrorMsg:  "forbidden",
		},
	}
	data, err := cborEncodeMap(resp)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	parsed, err := ParsePrivetResponse(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if parsed.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if parsed.Error.Code != 403 {
		t.Errorf("error code = %d, want 403", parsed.Error.Code)
	}
	if parsed.Error.Message != "forbidden" {
		t.Errorf("error message = %q, want forbidden", parsed.Error.Message)
	}
}

// ---------------------------------------------------------------------------
// Convenience request builders produce parseable CBOR
// ---------------------------------------------------------------------------

func TestInfoRequest(t *testing.T) {
	data := InfoRequest()
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIInfo {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIInfo)
	}
	if _, ok := m[privetKeyParams]; ok {
		t.Errorf("InfoRequest should have no params")
	}
}

func TestPairingStartRequest(t *testing.T) {
	data := PairingStartRequest(PairingTypeEmbedded, CryptoSPAKE_P224)
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIPairingStart {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIPairingStart)
	}
	if cborInt(m[privetKeyRequestID]) != RequestIDStartPairing {
		t.Errorf("requestID = %v, want %d", m[privetKeyRequestID], RequestIDStartPairing)
	}
	params, ok := m[privetKeyParams].(map[int]interface{})
	if !ok {
		t.Fatalf("params: expected map, got %T", m[privetKeyParams])
	}
	if cborInt(params[0]) != PairingTypeEmbedded {
		t.Errorf("pairingType = %v, want %d", params[0], PairingTypeEmbedded)
	}
	if cborInt(params[1]) != CryptoSPAKE_P224 {
		t.Errorf("cryptoMethod = %v, want %d", params[1], CryptoSPAKE_P224)
	}
}

func TestPairingConfirmRequest(t *testing.T) {
	sessionID := int64(0x01020304)
	commitment := bytes.Repeat([]byte{0xAA}, 56)
	encTimestamp := []byte{0x01, 0x02, 0x03} // dummy encrypted timestamp

	data := PairingConfirmRequest(sessionID, commitment, encTimestamp)
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIPairingConfirm {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIPairingConfirm)
	}
	params, ok := m[privetKeyParams].(map[int]interface{})
	if !ok {
		t.Fatalf("params: expected map, got %T", m[privetKeyParams])
	}
	if cborInt(params[0]) != int(sessionID) {
		t.Errorf("sessionID = %v, want %d", params[0], sessionID)
	}
	if !bytes.Equal(params[1].([]byte), commitment) {
		t.Errorf("commitment mismatch")
	}
	if !bytes.Equal(params[2].([]byte), encTimestamp) {
		t.Errorf("encrypted timestamp mismatch")
	}
}

func TestAuthRequest(t *testing.T) {
	token := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	data := AuthRequest(AuthModeToken, token)
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIAuth {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIAuth)
	}
	params, ok := m[privetKeyParams].(map[int]interface{})
	if !ok {
		t.Fatalf("params: expected map, got %T", m[privetKeyParams])
	}
	if cborInt(params[0]) != AuthModeToken {
		t.Errorf("auth mode = %v, want %d", params[0], AuthModeToken)
	}
	if !bytes.Equal(params[2].([]byte), token) {
		t.Errorf("token mismatch")
	}
}

func TestSaveDataRequest(t *testing.T) {
	// Lock command without userId: {1:8, 2:7, 16:{0:1, 1:0, 2:{0:1}}}
	data := SaveDataRequest(TraitLockData, PropLockStatus, LockStateLocked, nil)
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIData {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIData)
	}
	if cborInt(m[privetKeyRequestID]) != RequestIDWriteData {
		t.Errorf("requestID = %v, want %d", m[privetKeyRequestID], RequestIDWriteData)
	}
	params, ok := m[privetKeyParams].(map[int]interface{})
	if !ok {
		t.Fatalf("params: expected map, got %T", m[privetKeyParams])
	}
	if cborInt(params[0]) != TraitLockData {
		t.Errorf("traitGroup = %v, want %d", params[0], TraitLockData)
	}
	if cborInt(params[1]) != PropLockStatus {
		t.Errorf("propertyID = %v, want %d", params[1], PropLockStatus)
	}
	valueMap, ok := params[2].(map[int]interface{})
	if !ok {
		t.Fatalf("valueMap: expected map, got %T", params[2])
	}
	if cborInt(valueMap[0]) != LockStateLocked {
		t.Errorf("lockState = %v, want %d", valueMap[0], LockStateLocked)
	}
}

func TestRequestDataRequest(t *testing.T) {
	// Read model name: {1:8, 2:4, 16:{0:1, 1:3}}
	data := RequestDataRequest(TraitLockData, PropModelName)
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIData {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIData)
	}
	if cborInt(m[privetKeyRequestID]) != RequestIDReadData {
		t.Errorf("requestID = %v, want %d", m[privetKeyRequestID], RequestIDReadData)
	}
	params, ok := m[privetKeyParams].(map[int]interface{})
	if !ok {
		t.Fatalf("params: expected map, got %T", m[privetKeyParams])
	}
	if cborInt(params[0]) != TraitLockData {
		t.Errorf("traitGroup = %v, want %d", params[0], TraitLockData)
	}
	if cborInt(params[1]) != PropModelName {
		t.Errorf("propertyID = %v, want %d", params[1], PropModelName)
	}
}

func TestStateRequest(t *testing.T) {
	data := StateRequest()
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIState {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIState)
	}
	if cborInt(m[privetKeyRequestID]) != RequestIDState {
		t.Errorf("requestID = %v, want %d", m[privetKeyRequestID], RequestIDState)
	}
	if _, ok := m[privetKeyParams]; ok {
		t.Errorf("StateRequest should have no params")
	}
}

// ---------------------------------------------------------------------------
// Access code request builders
// ---------------------------------------------------------------------------

func TestAddAccessCodeRequest(t *testing.T) {
	// Wire format:{1:8, 2:3, 16:{0:4, 1:0, 2:{0:uuid, 1:name, 2:code_long, 5:blocked}}}
	uuid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	data := AddAccessCodeRequest(uuid, "Front Door", 1234, false)
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIData {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIData)
	}
	if cborInt(m[privetKeyRequestID]) != 3 {
		t.Errorf("requestID = %v, want 3", m[privetKeyRequestID])
	}
	params, ok := m[privetKeyParams].(map[int]interface{})
	if !ok {
		t.Fatalf("params: expected map, got %T", m[privetKeyParams])
	}
	if cborInt(params[0]) != TraitAccessCodes {
		t.Errorf("traitGroup = %v, want %d", params[0], TraitAccessCodes)
	}
	if cborInt(params[1]) != AccessCodeOpAdd {
		t.Errorf("opCode = %v, want %d", params[1], AccessCodeOpAdd)
	}
	codeData, ok := params[2].(map[int]interface{})
	if !ok {
		t.Fatalf("codeData: expected map, got %T", params[2])
	}
	if string(codeData[AccessCodeKeyUUID].([]byte)) != string(uuid) {
		t.Errorf("uuid mismatch")
	}
	if codeData[AccessCodeKeyName].(string) != "Front Door" {
		t.Errorf("name = %v, want Front Door", codeData[AccessCodeKeyName])
	}
	if cborInt(codeData[AccessCodeKeyCode]) != 1234 {
		t.Errorf("code = %v, want 1234", codeData[AccessCodeKeyCode])
	}
	if cborInt(codeData[AccessCodeKeyBlocked]) != 0 {
		t.Errorf("blocked = %v, want 0", codeData[AccessCodeKeyBlocked])
	}
}

func TestRemoveAccessCodeRequest(t *testing.T) {
	// Wire format:{1:8, 2:2, 16:{0:4, 1:1, 2:{2:code_long}}}
	data := RemoveAccessCodeRequest(5678)
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIData {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIData)
	}
	if cborInt(m[privetKeyRequestID]) != 2 {
		t.Errorf("requestID = %v, want 2", m[privetKeyRequestID])
	}
	params := m[privetKeyParams].(map[int]interface{})
	if cborInt(params[0]) != TraitAccessCodes {
		t.Errorf("traitGroup = %v, want %d", params[0], TraitAccessCodes)
	}
	if cborInt(params[1]) != AccessCodeOpDelete {
		t.Errorf("opCode = %v, want %d", params[1], AccessCodeOpDelete)
	}
	codeData := params[2].(map[int]interface{})
	if cborInt(codeData[AccessCodeKeyCode]) != 5678 {
		t.Errorf("code = %v, want 5678", codeData[AccessCodeKeyCode])
	}
}

func TestDeleteAllAccessCodesRequest(t *testing.T) {
	// Wire format:{1:8, 2:5, 16:{0:4, 1:2}}
	data := DeleteAllAccessCodesRequest()
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIData {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIData)
	}
	if cborInt(m[privetKeyRequestID]) != 5 {
		t.Errorf("requestID = %v, want 5", m[privetKeyRequestID])
	}
	params := m[privetKeyParams].(map[int]interface{})
	if cborInt(params[0]) != TraitAccessCodes {
		t.Errorf("traitGroup = %v, want %d", params[0], TraitAccessCodes)
	}
	if cborInt(params[1]) != AccessCodeOpDeleteAll {
		t.Errorf("opCode = %v, want %d", params[1], AccessCodeOpDeleteAll)
	}
}

func TestListAccessCodesCheckRequest(t *testing.T) {
	// Wire format:{1:8, 2:3, 16:{0:4, 1:6, 2:{0:0}}}
	data := ListAccessCodesCheckRequest()
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIData {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIData)
	}
	if cborInt(m[privetKeyRequestID]) != 3 {
		t.Errorf("requestID = %v, want 3", m[privetKeyRequestID])
	}
	params := m[privetKeyParams].(map[int]interface{})
	if cborInt(params[0]) != TraitAccessCodes {
		t.Errorf("traitGroup = %v, want %d", params[0], TraitAccessCodes)
	}
	if cborInt(params[1]) != AccessCodeOpCheck {
		t.Errorf("opCode = %v, want %d", params[1], AccessCodeOpCheck)
	}
}

func TestHistoryCheckRequest(t *testing.T) {
	// Wire format:{1:8, 2:2, 16:{0:3, 1:0, 2:{0:0}}}
	data := HistoryCheckRequest()
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIData {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIData)
	}
	if cborInt(m[privetKeyRequestID]) != 2 {
		t.Errorf("requestID = %v, want 2", m[privetKeyRequestID])
	}
	params := m[privetKeyParams].(map[int]interface{})
	if cborInt(params[0]) != TraitHistory {
		t.Errorf("traitGroup = %v, want %d", params[0], TraitHistory)
	}
}

func TestHistoryReadRequest(t *testing.T) {
	// Wire format:{1:8, 2:3, 16:{0:3, 1:count}}
	data := HistoryReadRequest(42)
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIData {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIData)
	}
	if cborInt(m[privetKeyRequestID]) != 3 {
		t.Errorf("requestID = %v, want 3", m[privetKeyRequestID])
	}
	params := m[privetKeyParams].(map[int]interface{})
	if cborInt(params[0]) != TraitHistory {
		t.Errorf("traitGroup = %v, want %d", params[0], TraitHistory)
	}
	if cborInt(params[1]) != 42 {
		t.Errorf("count = %v, want 42", params[1])
	}
}

// ---------------------------------------------------------------------------
// Settings request builders
// ---------------------------------------------------------------------------

func TestSaveDataRequestWithUserId(t *testing.T) {
	// Lock command with userId: {1:8, 2:7, 16:{0:1, 1:0, 2:{0:1, 1:<userId>}}}
	userId := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	data := SaveDataRequest(TraitLockData, PropLockStatus, LockStateLocked, userId)
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	params := m[privetKeyParams].(map[int]interface{})
	valueMap := params[2].(map[int]interface{})
	if cborInt(valueMap[0]) != LockStateLocked {
		t.Errorf("lockState = %v, want %d", valueMap[0], LockStateLocked)
	}
	gotUserId, ok := valueMap[1].([]byte)
	if !ok {
		t.Fatalf("userId: expected []byte, got %T", valueMap[1])
	}
	if !bytes.Equal(gotUserId, userId) {
		t.Errorf("userId mismatch: got %x, want %x", gotUserId, userId)
	}
}

func TestWriteSettingRequest(t *testing.T) {
	// saveData on TraitLockConfig: {1:8, 2:7, 16:{0:5, 1:settingKey, 2:{0:value, 1:userId}}}
	userId := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	data := WriteSettingRequest(SettingWriteAutoLockTime, 30, userId)
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIData {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIData)
	}
	if cborInt(m[privetKeyRequestID]) != RequestIDWriteData {
		t.Errorf("requestID = %v, want %d", m[privetKeyRequestID], RequestIDWriteData)
	}
	params := m[privetKeyParams].(map[int]interface{})
	if cborInt(params[0]) != TraitLockConfig {
		t.Errorf("traitGroup = %v, want %d", params[0], TraitLockConfig)
	}
	if cborInt(params[1]) != SettingWriteAutoLockTime {
		t.Errorf("propertyID = %v, want %d", params[1], SettingWriteAutoLockTime)
	}
	valueMap := params[2].(map[int]interface{})
	if cborInt(valueMap[0]) != 30 {
		t.Errorf("value = %v, want 30", valueMap[0])
	}
}

func TestReadSettingRequest(t *testing.T) {
	// requestData on TraitLockConfig: {1:8, 2:4, 16:{0:5, 1:settingKey}}
	data := ReadSettingRequest(SettingReadBeeperEnabled)
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIData {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIData)
	}
	if cborInt(m[privetKeyRequestID]) != RequestIDReadData {
		t.Errorf("requestID = %v, want %d", m[privetKeyRequestID], RequestIDReadData)
	}
	params := m[privetKeyParams].(map[int]interface{})
	if cborInt(params[0]) != TraitLockConfig {
		t.Errorf("traitGroup = %v, want %d", params[0], TraitLockConfig)
	}
	if cborInt(params[1]) != SettingReadBeeperEnabled {
		t.Errorf("propertyID = %v, want %d", params[1], SettingReadBeeperEnabled)
	}
}

func TestReadDeviceInfoRequest(t *testing.T) {
	// requestData on TraitLockData: {1:8, 2:4, 16:{0:1, 1:propID}}
	data := ReadDeviceInfoRequest(DeviceInfoKeyModelNumber)
	m, err := cborDecodeMap(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cborInt(m[privetKeyAPI]) != APIData {
		t.Errorf("api = %v, want %d", m[privetKeyAPI], APIData)
	}
	params := m[privetKeyParams].(map[int]interface{})
	if cborInt(params[0]) != TraitLockData {
		t.Errorf("traitGroup = %v, want %d", params[0], TraitLockData)
	}
	if cborInt(params[1]) != DeviceInfoKeyModelNumber {
		t.Errorf("propertyID = %v, want %d", params[1], DeviceInfoKeyModelNumber)
	}
}


// ---------------------------------------------------------------------------
// LockEventName coverage
// ---------------------------------------------------------------------------

func TestLockEventName(t *testing.T) {
	tests := []struct {
		eventType int
		want      string
	}{
		{LockEventLockedByCode, "locked_by_code"},
		{LockEventUnlockedByCode, "unlocked_by_code"},
		{LockEventJammed, "jammed"},
		{LockEventLockedByAutoLock, "locked_by_auto_lock"},
		{LockEventAccessCodeAdded, "access_code_added"},
		{LockEventLowBattery, "low_battery"},
		{LockEventLockedBySchedule, "locked_by_schedule"},
		{LockEventInternalMalfunction1, "internal_malfunction"},
		{LockEventInternalMalfunction2, "internal_malfunction"},
		{LockEventUnknown, "unknown_255"},
		{999, "unknown_999"},
	}
	for _, tt := range tests {
		got := LockEventName(tt.eventType)
		if got != tt.want {
			t.Errorf("LockEventName(%d) = %q, want %q", tt.eventType, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// CBOR map key ordering (deterministic encoding)
// ---------------------------------------------------------------------------

func TestCborMapDeterministicEncoding(t *testing.T) {
	m := map[int]interface{}{
		17: "b",
		0:  "a",
		2:  "c",
	}
	enc1, _ := cborEncodeMap(m)
	enc2, _ := cborEncodeMap(m)
	if !bytes.Equal(enc1, enc2) {
		t.Errorf("encoding not deterministic")
	}

	// Verify key order: decode and check first key encountered is 0
	decoded, err := cborDecodeMap(enc1)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !reflect.DeepEqual(sortedKeys(decoded), []int{0, 2, 17}) {
		t.Errorf("unexpected keys")
	}
}

func sortedKeys(m map[int]interface{}) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Already sorted from encoding, but sort here for comparison
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}
