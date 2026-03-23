package schlage_uweave

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
)

// ---------------------------------------------------------------------------
// BLE discovery constants
// ---------------------------------------------------------------------------

const (
	// WeaveAdvServiceUUID is the Google Weave BLE service UUID (0xFEAF),
	// advertised in non-connectable advertisements.
	WeaveAdvServiceUUID16 = 0xFEAF

	// UWeaveServiceUUID is the Schlage uWeave GATT service UUID,
	// exposed on the connectable BLE interface.
	UWeaveServiceUUID = "883f45ec-14cb-46aa-9864-9a4e782b33d0"

	// RXCharUUID is the GATT characteristic UUID the client writes to (lock receives).
	RXCharUUID = "ff530c78-cd50-4bb9-bbd4-0712f32b3796"

	// TXCharUUID is the GATT characteristic UUID the lock indicates on (client receives).
	TXCharUUID = "26002998-e001-4812-8c08-5cd2afda0830"

	// AllegionCompanyID is Allegion's Bluetooth SIG company identifier.
	AllegionCompanyID = 0x013B
)

// CBOR major types
const (
	cborUint   = 0 << 5 // 0x00
	cborNegInt = 1 << 5 // 0x20
	cborBytes  = 2 << 5 // 0x40
	cborText   = 3 << 5 // 0x60
	cborArray  = 4 << 5 // 0x80
	cborMap    = 5 << 5 // 0xa0
)

// ---------------------------------------------------------------------------
// Minimal CBOR encoder
// ---------------------------------------------------------------------------

// cborEncodeUint encodes an unsigned integer in CBOR format.
func cborEncodeUint(v uint64) []byte {
	return cborEncodeTypedUint(cborUint, v)
}

// cborEncodeTypedUint encodes a uint with the given major type.
func cborEncodeTypedUint(major byte, v uint64) []byte {
	if v <= 23 {
		return []byte{major | byte(v)}
	}
	if v <= math.MaxUint8 {
		return []byte{major | 24, byte(v)}
	}
	if v <= math.MaxUint16 {
		b := make([]byte, 3)
		b[0] = major | 25
		binary.BigEndian.PutUint16(b[1:], uint16(v))
		return b
	}
	if v <= math.MaxUint32 {
		b := make([]byte, 5)
		b[0] = major | 26
		binary.BigEndian.PutUint32(b[1:], uint32(v))
		return b
	}
	b := make([]byte, 9)
	b[0] = major | 27
	binary.BigEndian.PutUint64(b[1:], v)
	return b
}

// cborEncodeInt encodes a signed integer (handles negative values).
func cborEncodeInt(v int64) []byte {
	if v >= 0 {
		return cborEncodeUint(uint64(v))
	}
	// CBOR negative: encode -1-v as cborNegInt
	return cborEncodeTypedUint(cborNegInt, uint64(-1-v))
}

// cborEncodeBytes encodes a byte string.
func cborEncodeBytes(b []byte) []byte {
	hdr := cborEncodeTypedUint(cborBytes, uint64(len(b)))
	return append(hdr, b...)
}

// cborEncodeString encodes a text string.
func cborEncodeString(s string) []byte {
	hdr := cborEncodeTypedUint(cborText, uint64(len(s)))
	return append(hdr, []byte(s)...)
}

// cborEncodeValue encodes an arbitrary value (int64, uint64, int, []byte, string,
// []interface{}, map[int]interface{}).
func cborEncodeValue(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case int:
		return cborEncodeInt(int64(val)), nil
	case int64:
		return cborEncodeInt(val), nil
	case uint64:
		return cborEncodeUint(val), nil
	case []byte:
		return cborEncodeBytes(val), nil
	case string:
		return cborEncodeString(val), nil
	case []interface{}:
		return cborEncodeArray(val)
	case map[int]interface{}:
		return cborEncodeMap(val)
	default:
		return nil, fmt.Errorf("cbor: unsupported type %T", v)
	}
}

// cborEncodeArray encodes an array of values.
func cborEncodeArray(arr []interface{}) ([]byte, error) {
	out := cborEncodeTypedUint(cborArray, uint64(len(arr)))
	for _, v := range arr {
		enc, err := cborEncodeValue(v)
		if err != nil {
			return nil, err
		}
		out = append(out, enc...)
	}
	return out, nil
}

// cborEncodeMap encodes a map with integer keys. Keys are sorted in ascending
// order for deterministic output (canonical CBOR).
func cborEncodeMap(m map[int]interface{}) ([]byte, error) {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	out := cborEncodeTypedUint(cborMap, uint64(len(m)))
	for _, k := range keys {
		out = append(out, cborEncodeInt(int64(k))...)
		enc, err := cborEncodeValue(m[k])
		if err != nil {
			return nil, err
		}
		out = append(out, enc...)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Minimal CBOR decoder
// ---------------------------------------------------------------------------

var errCBORTruncated = errors.New("cbor: truncated input")

// cborDecodeValue decodes one CBOR value from data, returning the value and
// the number of bytes consumed.
func cborDecodeValue(data []byte) (interface{}, int, error) {
	if len(data) == 0 {
		return nil, 0, errCBORTruncated
	}
	major := data[0] & 0xe0
	addl := data[0] & 0x1f

	rawVal, hdrLen, err := cborDecodeArgument(data)
	if err != nil {
		return nil, 0, err
	}

	switch major {
	case cborUint:
		return int64(rawVal), hdrLen, nil

	case cborNegInt:
		// value is -1 - rawVal
		if rawVal > uint64(math.MaxInt64) {
			return nil, 0, errors.New("cbor: negative integer overflow")
		}
		return int64(-1) - int64(rawVal), hdrLen, nil

	case cborBytes:
		end := hdrLen + int(rawVal)
		if len(data) < end {
			return nil, 0, errCBORTruncated
		}
		b := make([]byte, rawVal)
		copy(b, data[hdrLen:end])
		return b, end, nil

	case cborText:
		end := hdrLen + int(rawVal)
		if len(data) < end {
			return nil, 0, errCBORTruncated
		}
		return string(data[hdrLen:end]), end, nil

	case cborArray:
		offset := hdrLen
		arr := make([]interface{}, 0, rawVal)
		for i := uint64(0); i < rawVal; i++ {
			v, n, err := cborDecodeValue(data[offset:])
			if err != nil {
				return nil, 0, err
			}
			arr = append(arr, v)
			offset += n
		}
		return arr, offset, nil

	case cborMap:
		offset := hdrLen
		m := make(map[int]interface{}, rawVal)
		for i := uint64(0); i < rawVal; i++ {
			kv, kn, err := cborDecodeValue(data[offset:])
			if err != nil {
				return nil, 0, err
			}
			offset += kn

			key, ok := kv.(int64)
			if !ok {
				return nil, 0, fmt.Errorf("cbor: expected integer map key, got %T", kv)
			}

			vv, vn, err := cborDecodeValue(data[offset:])
			if err != nil {
				return nil, 0, err
			}
			offset += vn
			m[int(key)] = vv
		}
		return m, offset, nil

	default:
		_ = addl
		return nil, 0, fmt.Errorf("cbor: unsupported major type %d", major>>5)
	}
}

// cborDecodeArgument extracts the argument value and header length from a CBOR
// initial byte (and following argument bytes).
func cborDecodeArgument(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, errCBORTruncated
	}
	addl := data[0] & 0x1f

	if addl <= 23 {
		return uint64(addl), 1, nil
	}
	switch addl {
	case 24:
		if len(data) < 2 {
			return 0, 0, errCBORTruncated
		}
		return uint64(data[1]), 2, nil
	case 25:
		if len(data) < 3 {
			return 0, 0, errCBORTruncated
		}
		return uint64(binary.BigEndian.Uint16(data[1:3])), 3, nil
	case 26:
		if len(data) < 5 {
			return 0, 0, errCBORTruncated
		}
		return uint64(binary.BigEndian.Uint32(data[1:5])), 5, nil
	case 27:
		if len(data) < 9 {
			return 0, 0, errCBORTruncated
		}
		return binary.BigEndian.Uint64(data[1:9]), 9, nil
	default:
		return 0, 0, fmt.Errorf("cbor: unsupported additional info %d", addl)
	}
}

// cborDecodeMap is a convenience wrapper that decodes a complete CBOR map from data.
func cborDecodeMap(data []byte) (map[int]interface{}, error) {
	v, _, err := cborDecodeValue(data)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[int]interface{})
	if !ok {
		return nil, fmt.Errorf("cbor: expected map, got %T", v)
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Privet RPC constants
// ---------------------------------------------------------------------------

// Privet RPC request/response keys (integer map keys in CBOR)
const (
	privetKeyAPI       = 1  // PRIVET_RPC_KEY_API_ID
	privetKeyRequestID = 2  // PRIVET_RPC_KEY_REQUEST_ID
	privetKeyError     = 3  // PRIVET_RPC_KEY_ERROR
	privetKeyErrorCode = 4  // PRIVET_RPC_ERROR_KEY_CODE
	privetKeyErrorMsg  = 5
	privetKeyParams    = 16 // PRIVET_RPC_KEY_PARAMS (0x10)
	privetKeyResult    = 17 // PRIVET_RPC_KEY_RESULT (0x11)
)

// Privet API endpoint IDs (value at key 1)
const (
	APIInfo           = 0  // /info
	APIPairingStart   = 2  // startPairing()
	APIPairingConfirm = 3  // /pairing/confirm
	APIAuth           = 5  // sendCATPostPairing() / sendCAT
	APIState          = 6  // requestLockState()
	APIData           = 8  // requestData() / saveData()
	APISetup          = 9  // /setup
	APIAccessClaim    = 24 // requestAccessControlClaim() (0x18)
	APIAccessConfirm  = 25 // confirmAccessControl() (0x19)
)

// Request type IDs (value at key 2) — these are fixed command types, NOT sequence numbers.
const (
	RequestIDStartPairing   = 1 // startPairing
	RequestIDCodeLength     = 2 // read access code length
	RequestIDState          = 3 // requestLockState / sendCAT
	RequestIDReadData       = 4 // requestData (read) / access claim
	RequestIDConfirmAccess  = 5 // confirmAccessControl
	RequestIDWriteData      = 7 // saveData (write)
)

// Pairing types — Privet wire values (PRIVET_INFO_AUTH_VALUE_*).
// Note: /info advertises capabilities using UwPairingType bitmask values (1, 2),
// but /pairing/start expects these wire values (0, 1).
const (
	PairingTypePIN      = 0 // PRIVET_INFO_AUTH_VALUE_PAIRING_PIN
	PairingTypeEmbedded = 1 // PRIVET_INFO_AUTH_VALUE_PAIRING_EMBEDDED
)

// Crypto types — Privet wire values
const (
	CryptoSPAKE_P224 = 0 // PRIVET_INFO_AUTH_VALUE_CRYPTO_SPAKE_P224
)

// Auth modes
const (
	AuthModeAnonymous = 0
	AuthModePairing   = 1
	AuthModeToken     = 2
)

// Lock state values for Schlage Sense locks.
// Used both for reading state and for lock/unlock commands.
// Note: JAMMED means the bolt DID extend (door IS locked) but with motor difficulty.
// MOTOR_JAMMED means the motor stalled and the bolt may NOT have moved.
const (
	LockStateUnlocked    = 0  // UNLOCKED — bolt retracted
	LockStateLocked      = 1  // LOCKED — bolt extended normally
	LockStateJammed      = 2  // JAMMED — bolt extended with difficulty (still locked!)
	LockStateUnknown     = 3  // UNKNOWN
	LockStateMotorJammed = 4  // MOTOR_JAMMED — motor stalled, bolt position uncertain
	LockStatePassageMode = 5  // PASSAGE_MODE — bolt always retracted
	LockStateDeadlocked  = 6  // DEADLOCKED — bolt fully extended, extra secure
	LockStateInvalid     = -1 // INVALID
)

// Trait groups used in requestData/saveData params key 0.
const (
	TraitLockData    = 1 // lockData: lock state, info, time, battery
	TraitHistory     = 3 // history/logs: event log
	TraitAccessCodes = 4 // access codes: keypad PIN management
	TraitLockConfig  = 5 // lockConfig: config, timezone, operating mode
)

// Property IDs for TraitLockData (trait 1) — used in requestData/saveData params key 1.
const (
	PropLockStatus      = 0    // Lock/unlock state (R/W)
	PropModelName       = 3    // Model name (R)
	PropSerialNumber    = 4    // Serial number (R)
	PropFirmwareVersion = 5    // Firmware version (R)
	PropSetCurrentTime  = 6    // Set time (W)
	PropCurrentTime     = 7    // Current time (R)
	PropBatteryState    = 0x0C // Battery state (R) — 12
	PropAlarmEnabled    = 0x0E // Alarm selection (R) — 14
	PropBatteryLevel    = 0x15 // Battery percentage (R) — 21
	PropDoorState       = 0x19 // Door state (R) — 25: UNKNOWN=0, OPEN=1, CLOSE=2, FAULTY=3
)

// Door state values for Schlage Sense locks.
// Returned in requestLockState response at key PropDoorState (0x19).
const (
	DoorStateUnknown = 0 // UNKNOWN
	DoorStateOpen    = 1 // OPEN
	DoorStateClosed  = 2 // CLOSE
	DoorStateFaulty  = 3 // FAULTY
)

// Property IDs for TraitLockConfig (trait 5).
const (
	PropAccessPointParams = 6    // Access point parameters
	PropAccessCodeLength  = 0x0F // Access code (PIN) length, 4-8 digits — 15
	PropTimeZone          = 0x14 // Time zone offset — 20
	PropDSTTimes          = 0x12 // DST times — 18
	PropOpMode            = 0x1B // Operating mode — 27
	PropMaxUserCodes      = 0x1C // Max user access codes (R) — 28
)

// Lock state response keys — inner map from requestLockState response.
// Response navigated as: result[0x11][0x01][0x00][0x00][0x01] → innerMap
// innerMap keys match PropLockStatus, PropBatteryState, PropAlarmEnabled, PropBatteryLevel, PropDoorState.

// Deprecated: old command execute constants. Lock/unlock uses saveData, not CommandExecute.
// Kept for reference only.
// const (
// 	TraitIDLock             = 1 // was used with CommandExecute
// 	CommandIDBoltLockChange = 1 // was BoltLockChangeRequest
// )

// ---------------------------------------------------------------------------
// Schlage vendor property operations
// ---------------------------------------------------------------------------
//
// Five trait groups:
//   1 = lock data (state, info, time, battery) — requestData/saveData
//   3 = history/logs — check+read pattern
//   4 = access codes — add/delete/list with dedicated commands
//   5 = lock config (settings, timezone) — requestData/saveData

// Access code operations use TraitAccessCodes (4) with specific request types
// and operation IDs, NOT the generic saveData/requestData pattern.
//   ADD:        {1:8, 2:3, 16:{0:4, 1:0, 2:{0:uuid, 1:name, 2:code_long, 5:blocked}}}
//   DELETE:     {1:8, 2:2, 16:{0:4, 1:1, 2:{2:code_long}}}
//   DELETE_ALL: {1:8, 2:5, 16:{0:4, 1:2}}
//   LIST check: {1:8, 2:3, 16:{0:4, 1:6, 2:{0:0}}}
//   LIST read:  {1:8, 2:4, 16:{0:4, 1:5}}

// Access code operation IDs (params key 1 when trait=4).
const (
	AccessCodeOpAdd       = 0 // add code (reqType 3)
	AccessCodeOpDelete    = 1 // delete code (reqType 2)
	AccessCodeOpDeleteAll = 2 // delete all codes (reqType 5)
	AccessCodeOpRead      = 5 // read codes batch (reqType 4)
	AccessCodeOpCheck     = 6 // check/count codes (reqType 3)
)

// Access code value keys (within params key 2 map for writes, or in response data map for reads).
const (
	AccessCodeKeyUUID          = 0    // []byte: 16-byte UUID
	AccessCodeKeyName          = 1    // string: user label
	AccessCodeKeyCode          = 2    // int64: PIN digits as integer (e.g. 1234)
	AccessCodeKeySchedule1     = 3    // []byte: weekly schedule (optional)
	AccessCodeKeySchedule2     = 4    // []byte: additional schedule (optional)
	AccessCodeKeyBlocked       = 5    // int: 0=active, 1=blocked
	AccessCodeKeyStartDate     = 6    // int64: start epoch seconds (0 if none)
	AccessCodeKeyEndDate       = 7    // int64: end epoch seconds (0xFFFFFFFF if none)
	AccessCodeKeyMoreAvailable = 0x0A // int: remaining codes to read (in read response only)
)

// History operations use TraitHistory (3) with a check+read pattern.
//   Check count: {1:8, 2:2, 16:{0:3, 1:0, 2:{0:0}}}
//   Read batch:  {1:8, 2:3, 16:{0:3, 1:count}}

// Settings use different property indices for read vs write on TraitLockConfig (trait 5).
// Pattern: read ID = write ID + 1.

// Setting write property IDs (used with saveData / saveLockConfigGroup).
const (
	SettingWriteBeeperEnabled    = 0x02 // int: 0=off, 1=on (keypress beep)
	SettingWriteAutoLockTime     = 0x04 // int: seconds (0=off, 15, 30, 60, 120, 240, 360, 600)
	SettingWriteAlarmMode        = 0x08 // int: alarm mode selection
	SettingWriteAlarmSensitivity = 0x0A // int: alarm sensitivity level
	SettingWriteLockAndLeave     = 0x0C // int: 0=off, 1=on (one-touch locking / lock-and-leave)
)

// Setting read property IDs (used with requestData / requestLockConfigGroup).
const (
	SettingReadBeeperEnabled    = 0x03
	SettingReadAutoLockTime     = 0x05
	SettingReadAlarmMode        = 0x09
	SettingReadAlarmSensitivity = 0x0B
	SettingReadLockAndLeave     = 0x0D
)

// Device info is read using requestData on TraitLockData (trait 1).
// Confirmed values on BE459:
//   3 → model ("be459wb"), 4 → serial, 5 → main firmware ("00.09.044544"),
//   7 → unix timestamp, 8 → keypad firmware ("1.1"), 10 → manufacturer ("Schlage"),
//   11 → model name ("Schlage Mode"), 12 (0x0C) → battery level (99)
// NOT available via requestData: 9 (error 5), 0x15 (error 5 — battery only in state response)
const (
	DeviceInfoKeyModelNumber    = PropModelName       // 3: confirmed "be459wb"
	DeviceInfoKeySerialNumber   = PropSerialNumber    // 4: confirmed
	DeviceInfoKeyFirmwareVer    = PropFirmwareVersion // 5: confirmed "00.09.044544"
	DeviceInfoKeyCurrentTime    = PropCurrentTime     // 7: confirmed (unix timestamp)
	DeviceInfoKeyKeypadFirmware = 8                   // confirmed "1.1"
	DeviceInfoKeyManufacturer   = 10                  // confirmed "Schlage"
	DeviceInfoKeyLockName       = 11                  // confirmed "Schlage Mode"
	DeviceInfoKeyBatteryLevel   = PropBatteryState    // 0x0C: returns battery % (e.g. 99)
)

// History log entry keys.
// Each read returns a batch (up to 5) at resp.Result[17].
// If batch size > 1, individual entries are at keys 0x0A–0x0E (LOG_0–LOG_4).
// If only 1 entry, the data is flat in the map (no LOG_*_INDEX_KEY wrapper).
// "More available" is at key 4 in the data map.
//
// Single entry structure:
//
//	0: [16 bytes]  — actor UUID (LOG_ACCESSOR_KEY)
//	1: int         — unix timestamp (LOG_TIME_KEY)
//	2: int         — action enum (LOG_ACTION_KEY)
//	3: map         — event details (LOG_EVENTS_KEY) {0: event_type, 1: [device_uuid]}
//	4: int         — more entries available (0 = last)
const (
	HistoryEntryKeyAccessor      = 0    // LOG_ACCESSOR_KEY: actor UUID bytes
	HistoryEntryKeyTimestamp     = 1    // LOG_TIME_KEY: unix timestamp
	HistoryEntryKeyAction        = 2    // LOG_ACTION_KEY: action enum int
	HistoryEntryKeyEvents        = 3    // LOG_EVENTS_KEY: nested event details map
	HistoryEntryKeyMoreAvailable = 4    // more entries flag (>0 means more)
	HistoryEventKeyType          = 0    // LOG_EVENTS_ACTION_KEY: event type int within events map
	HistoryEventKeyDeviceUUID    = 1    // LOG_EVENTS_ACTION_DEVICE_KEY: related device UUID

	// Batch index keys — when response contains multiple entries per read.
	// Batch mode is detected by checking for LOG_0_INDEX_KEY (0x0A).
	HistoryBatchLog0 = 0x0A // LOG_0_INDEX_KEY
	HistoryBatchLog1 = 0x0B // LOG_1_INDEX_KEY
	HistoryBatchLog2 = 0x0C // LOG_2_INDEX_KEY
	HistoryBatchLog3 = 0x0D // LOG_3_INDEX_KEY
	HistoryBatchLog4 = 0x0E // LOG_4_INDEX_KEY

	// Default batch size for history reads (matches app's mReadLogsInGroupOf).
	HistoryBatchSize = 5
)

// Lock event type IDs.
const (
	LockEventLockedByCode           = 1
	LockEventUnlockedByCode         = 2
	LockEventLockedByThumbturn      = 3
	LockEventUnlockedByThumbturn    = 4
	LockEventLockedByOneTouch       = 5
	LockEventLockedByBLE            = 6
	LockEventUnlockedByBLE          = 7
	LockEventLockedByAutoLock       = 8
	LockEventUnlockedByAutoLock     = 9  // "unlocked_by_time_delay"
	LockEventJammed                 = 10
	LockEventKeypadDisabled         = 11
	LockEventAlarmTriggered         = 12
	LockEventAccessCodeAdded        = 14
	LockEventAccessCodeDeleted      = 15
	LockEventMobileUserAdded        = 16
	LockEventMobileUserDeleted      = 17
	LockEventAdminAdded             = 18
	LockEventAdminDeleted           = 19
	LockEventFirmwareUpdated        = 20
	LockEventLowBattery             = 21
	LockEventBatteriesReplaced      = 22
	LockEventForcedEntryAlarmOff    = 23
	LockEventDoorSensorError        = 27
	LockEventFDRFailed              = 28
	LockEventCriticalBattery        = 29
	LockEventAllCodesDeleted        = 30
	LockEventFirmwareUpdateFailed   = 32
	LockEventBLEFWDownloadFailed    = 33
	LockEventWiFiFWDownloadFailed   = 34
	LockEventKeypadDisconnected     = 35
	LockEventCloudCommError         = 37
	LockEventCloudConnected         = 39
	LockEventAccessCodeAddFailed    = 40
	LockEventLockedBySchedule       = 47
	LockEventUnlockedByInsideButton = 48
	LockEventLockedByInsideButton   = 49
	LockEventActivityAlarm          = 51
	LockEventUnlockedByAppleHomeKey = 52
	LockEventLockedByAppleHomeKey   = 53
	LockEventInternalMalfunction1   = 54
	LockEventInternalMalfunction2   = 55
	LockEventInternalMalfunction3   = 56
	LockEventThreadDisconnect       = 57
	LockEventThreadConnect          = 58
	LockEventLockedByUWB            = 59
	LockEventUnlockedByUWB          = 60
	LockEventUWBAntennaDisconnected = 61
	LockEventLostAccurateTime       = 62
	LockEventUnknown                = 255
)

// ---------------------------------------------------------------------------
// Privet RPC message types
// ---------------------------------------------------------------------------

// PrivetError represents an error in a Privet RPC response.
type PrivetError struct {
	Code    int
	Message string
}

func (e *PrivetError) Error() string {
	return fmt.Sprintf("privet error %d: %s", e.Code, e.Message)
}

// PrivetResponse holds a parsed Privet RPC response.
type PrivetResponse struct {
	RequestID int
	Result    map[int]interface{}
	Error     *PrivetError
}

// PrivetRequest builds a CBOR-encoded Privet RPC request.
// apiID is the API endpoint (key 1), requestTypeID is the fixed request type (key 2).
func PrivetRequest(apiID int, requestTypeID int, params map[int]interface{}) []byte {
	m := map[int]interface{}{
		privetKeyAPI:       apiID,
		privetKeyRequestID: requestTypeID,
	}
	if params != nil {
		m[privetKeyParams] = params
	}
	data, err := cborEncodeMap(m)
	if err != nil {
		// Should not happen with well-formed input; panic to surface bugs.
		panic(fmt.Sprintf("privet: failed to encode request: %v", err))
	}
	return data
}

// ParsePrivetResponse parses a CBOR-encoded Privet RPC response.
func ParsePrivetResponse(data []byte) (*PrivetResponse, error) {
	m, err := cborDecodeMap(data)
	if err != nil {
		return nil, fmt.Errorf("privet: failed to decode response: %w", err)
	}

	resp := &PrivetResponse{}

	if v, ok := m[privetKeyRequestID]; ok {
		resp.RequestID = cborInt(v)
	}

	// Check for error
	if errMap, ok := m[privetKeyError]; ok {
		if em, ok := errMap.(map[int]interface{}); ok {
			pe := &PrivetError{}
			if v, ok := em[privetKeyErrorCode]; ok {
				pe.Code = cborInt(v)
			}
			if v, ok := em[privetKeyErrorMsg]; ok {
				if s, ok := v.(string); ok {
					pe.Message = s
				}
			}
			resp.Error = pe
		}
	}

	// Extract result
	if result, ok := m[privetKeyResult]; ok {
		if rm, ok := result.(map[int]interface{}); ok {
			resp.Result = rm
		}
	}

	return resp, nil
}

// cborInt converts a CBOR-decoded value to int. CBOR integers decode as int64.
func cborInt(v interface{}) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------
// Convenience request builders
// ---------------------------------------------------------------------------

// InfoRequest builds a /info request (no params).
func InfoRequest() []byte {
	return PrivetRequest(APIInfo, 0, nil)
}

// PairingStartRequest builds a startPairing request.
// Wire format: {1:2, 2:1, 16:{0:<pairingType>, 1:<cryptoMethod>}}
func PairingStartRequest(pairingType, cryptoMethod int) []byte {
	params := map[int]interface{}{
		0: pairingType,
		1: cryptoMethod,
	}
	return PrivetRequest(APIPairingStart, RequestIDStartPairing, params)
}

// SendCATRequest builds a sendCAT request.
// Wire format: {1:5, 2:3, 16:{0:<pairingType>, 1:<cryptoMethod>, 2:<cat_bytes>}}
func SendCATRequest(pairingType int, cryptoMethod int, catBytes []byte) []byte {
	params := map[int]interface{}{
		0: pairingType,
		1: cryptoMethod,
		2: catBytes,
	}
	return PrivetRequest(APIAuth, RequestIDState, params)
}

// PairingConfirmRequest builds a /pairing/confirm request.
// sessionID: from PairingStart response (integer, passed through as-is)
// clientCommitment: 56-byte SPAKE commitment
// encryptedTimestamp: AES-EAX encrypted CBOR {0: unix_time} (optional but required by Schlage)
func PairingConfirmRequest(sessionID interface{}, clientCommitment []byte, encryptedTimestamp []byte) []byte {
	params := map[int]interface{}{
		0: sessionID,
		1: clientCommitment,
	}
	if encryptedTimestamp != nil {
		params[2] = encryptedTimestamp
	}
	return PrivetRequest(APIPairingConfirm, RequestIDState, params)
}

// AuthRequest builds an /auth request with a CAT token.
// mode: AuthModePairing (1) for pairing token, AuthModeToken (2) for delegated token.
func AuthRequest(mode int, token []byte) []byte {
	params := map[int]interface{}{
		0: mode,
		2: token, // PRIVET_AUTH_KEY_AUTH_CODE = 2 (key 1 is deprecated)
	}
	return PrivetRequest(APIAuth, RequestIDState, params)
}

// RequestDataRequest builds a requestData (read property) request.
// Wire format: {1:8, 2:4, 16:{0:<traitGroup>, 1:<propertyId>}}
func RequestDataRequest(traitGroup int, propertyID int) []byte {
	params := map[int]interface{}{
		0: traitGroup,
		1: propertyID,
	}
	return PrivetRequest(APIData, RequestIDReadData, params)
}

// SaveDataRequest builds a saveData (write property) request.
// Wire format: {1:8, 2:7, 16:{0:<traitGroup>, 1:<propertyId>, 2:{0:<value>, 1:<userId>}}}
// userId is a 16-byte user identifier; pass nil to omit (not recommended).
func SaveDataRequest(traitGroup int, propertyID int, value interface{}, userId []byte) []byte {
	valueMap := map[int]interface{}{0: value}
	if userId != nil {
		valueMap[1] = userId
	}
	params := map[int]interface{}{
		0: traitGroup,
		1: propertyID,
		2: valueMap,
	}
	return PrivetRequest(APIData, RequestIDWriteData, params)
}

// StateRequest builds a requestLockState request.
// Wire format: {1:6, 2:3}
func StateRequest() []byte {
	return PrivetRequest(APIState, RequestIDState, nil)
}

// AccessControlClaimRequest builds a requestAccessControlClaim request.
// Wire format: {1:24, 2:4, 16:{...}}
func AccessControlClaimRequest(params map[int]interface{}) []byte {
	return PrivetRequest(APIAccessClaim, RequestIDReadData, params)
}

// ConfirmAccessControlRequest builds a confirmAccessControl request.
// Wire format: {1:25, 2:5, 16:{0:<cat_bytes>}}
func ConfirmAccessControlRequest(catBytes []byte) []byte {
	params := map[int]interface{}{
		0: catBytes,
	}
	return PrivetRequest(APIAccessConfirm, RequestIDConfirmAccess, params)
}

// ---------------------------------------------------------------------------
// Access code request builders
// ---------------------------------------------------------------------------

// AddAccessCodeRequest builds a request to add an access code.
// uuid: 16-byte UUID for the code, name: label, codeNum: PIN as integer, blocked: false for active.
// Wire format: {1:8, 2:3, 16:{0:4, 1:0, 2:{0:uuid, 1:name, 2:codeNum, 5:blocked}}}
func AddAccessCodeRequest(uuid []byte, name string, codeNum int64, blocked bool) []byte {
	blockedVal := 0
	if blocked {
		blockedVal = 1
	}
	params := map[int]interface{}{
		0: TraitAccessCodes,
		1: AccessCodeOpAdd,
		2: map[int]interface{}{
			AccessCodeKeyUUID:    uuid,
			AccessCodeKeyName:    name,
			AccessCodeKeyCode:    codeNum,
			AccessCodeKeyBlocked: blockedVal,
		},
	}
	return PrivetRequest(APIData, 3, params) // reqType 3
}

// RemoveAccessCodeRequest builds a request to delete an access code by PIN.
// Wire format: {1:8, 2:2, 16:{0:4, 1:1, 2:{2:codeNum}}}
func RemoveAccessCodeRequest(codeNum int64) []byte {
	params := map[int]interface{}{
		0: TraitAccessCodes,
		1: AccessCodeOpDelete,
		2: map[int]interface{}{
			AccessCodeKeyCode: codeNum,
		},
	}
	return PrivetRequest(APIData, 2, params) // reqType 2
}

// DeleteAllAccessCodesRequest builds a request to delete all access codes.
// Wire format: {1:8, 2:5, 16:{0:4, 1:2}}
func DeleteAllAccessCodesRequest() []byte {
	params := map[int]interface{}{
		0: TraitAccessCodes,
		1: AccessCodeOpDeleteAll,
	}
	return PrivetRequest(APIData, 5, params) // reqType 5
}

// ListAccessCodesCheckRequest builds a "check" request to get the count of access codes.
// Wire format: {1:8, 2:3, 16:{0:4, 1:6, 2:{0:0}}}
func ListAccessCodesCheckRequest() []byte {
	params := map[int]interface{}{
		0: TraitAccessCodes,
		1: AccessCodeOpCheck,
		2: map[int]interface{}{
			0: 0,
		},
	}
	return PrivetRequest(APIData, 3, params) // reqType 3
}

// ListAccessCodesReadRequest builds a "read" request to fetch access codes.
// Wire format: {1:8, 2:4, 16:{0:4, 1:5}}
func ListAccessCodesReadRequest() []byte {
	params := map[int]interface{}{
		0: TraitAccessCodes,
		1: AccessCodeOpRead,
	}
	return PrivetRequest(APIData, 4, params) // reqType 4
}

// ---------------------------------------------------------------------------
// Settings request builders
// ---------------------------------------------------------------------------

// WriteSettingRequest builds a saveData request to write a lock setting.
// Settings use TraitLockConfig (trait 5) with the property key as the property ID.
func WriteSettingRequest(propertyKey int, value interface{}, userId []byte) []byte {
	return SaveDataRequest(TraitLockConfig, propertyKey, value, userId)
}

// ReadSettingRequest builds a requestData request to read a lock setting.
func ReadSettingRequest(propertyKey int) []byte {
	return RequestDataRequest(TraitLockConfig, propertyKey)
}

// ReadDeviceInfoRequest builds a requestData request to read a device info property.
// Device info uses TraitLockData (trait 1).
func ReadDeviceInfoRequest(propertyKey int) []byte {
	return RequestDataRequest(TraitLockData, propertyKey)
}

// ---------------------------------------------------------------------------
// History request builders
// ---------------------------------------------------------------------------

// HistoryCheckRequest builds a "check" request to get the count of history entries.
// Wire format: {1:8, 2:2, 16:{0:3, 1:0, 2:{0:0}}}
func HistoryCheckRequest() []byte {
	params := map[int]interface{}{
		0: TraitHistory,
		1: 0,
		2: map[int]interface{}{
			0: 0,
		},
	}
	return PrivetRequest(APIData, 2, params) // reqType 2
}

// HistoryReadRequest builds a "read" request to fetch a batch of history entries.
// batchSize is how many entries to request per call (app uses 5).
// Wire format: {1:8, 2:3, 16:{0:3, 1:batchSize}}
func HistoryReadRequest(batchSize int) []byte {
	params := map[int]interface{}{
		0: TraitHistory,
		1: batchSize,
	}
	return PrivetRequest(APIData, 3, params) // reqType 3
}

// ---------------------------------------------------------------------------
// Response data types
// ---------------------------------------------------------------------------

// AccessCode represents a single configured access code.
type AccessCode struct {
	UUID    []byte // 16-byte UUID
	Name    string // user label
	Code    int64  // PIN digits as integer
	Blocked bool   // true if code is disabled
}

// LockSettings holds the current lock configuration.
type LockSettings struct {
	AutoLockTime     int  // seconds, 0=off
	BeeperEnabled    bool // keypress beep
	LockAndLeave     bool // one-touch locking
	AlarmMode        int  // alarm mode
	AlarmSensitivity int  // alarm sensitivity
}

// DeviceInfo holds read-only device information.
type DeviceInfo struct {
	ModelNumber    string
	SerialNumber   string
	BatteryLevel   int
	LockTime       int // unix timestamp
	MainFirmware   string
	KeypadFirmware string
	Manufacturer   string
	LockName       string
}

// HistoryEvent represents a single lock event from the history log.
type HistoryEvent struct {
	Type      int    // LockEvent* constant
	Timestamp int    // unix timestamp
	UserIndex int    // access code slot or -1 if N/A
	UserName  string // user name if applicable
}

// LockEventName returns a human-readable name for a lock event type ID.
func LockEventName(eventType int) string {
	switch eventType {
	case LockEventLockedByCode:
		return "locked_by_code"
	case LockEventUnlockedByCode:
		return "unlocked_by_code"
	case LockEventLockedByThumbturn:
		return "locked_by_thumbturn"
	case LockEventUnlockedByThumbturn:
		return "unlocked_by_thumbturn"
	case LockEventLockedByOneTouch:
		return "locked_by_one_touch"
	case LockEventLockedByBLE:
		return "locked_by_ble"
	case LockEventUnlockedByBLE:
		return "unlocked_by_ble"
	case LockEventLockedByAutoLock:
		return "locked_by_auto_lock"
	case LockEventUnlockedByAutoLock:
		return "unlocked_by_auto_lock"
	case LockEventJammed:
		return "jammed"
	case LockEventKeypadDisabled:
		return "keypad_disabled"
	case LockEventAlarmTriggered:
		return "alarm_triggered"
	case LockEventAccessCodeAdded:
		return "access_code_added"
	case LockEventAccessCodeDeleted:
		return "access_code_deleted"
	case LockEventMobileUserAdded:
		return "mobile_user_added"
	case LockEventMobileUserDeleted:
		return "mobile_user_deleted"
	case LockEventAdminAdded:
		return "admin_added"
	case LockEventAdminDeleted:
		return "admin_deleted"
	case LockEventFirmwareUpdated:
		return "firmware_updated"
	case LockEventLowBattery:
		return "low_battery"
	case LockEventBatteriesReplaced:
		return "batteries_replaced"
	case LockEventForcedEntryAlarmOff:
		return "forced_entry_alarm_silenced"
	case LockEventDoorSensorError:
		return "door_sensor_error"
	case LockEventFDRFailed:
		return "factory_reset_failed"
	case LockEventCriticalBattery:
		return "critical_battery"
	case LockEventAllCodesDeleted:
		return "all_codes_deleted"
	case LockEventFirmwareUpdateFailed:
		return "firmware_update_failed"
	case LockEventBLEFWDownloadFailed:
		return "ble_fw_download_failed"
	case LockEventWiFiFWDownloadFailed:
		return "wifi_fw_download_failed"
	case LockEventKeypadDisconnected:
		return "keypad_disconnected"
	case LockEventCloudCommError:
		return "cloud_comm_error"
	case LockEventCloudConnected:
		return "cloud_connected"
	case LockEventAccessCodeAddFailed:
		return "access_code_add_failed"
	case LockEventLockedBySchedule:
		return "locked_by_schedule"
	case LockEventUnlockedByInsideButton:
		return "unlocked_by_inside_button"
	case LockEventLockedByInsideButton:
		return "locked_by_inside_button"
	case LockEventActivityAlarm:
		return "activity_alarm"
	case LockEventUnlockedByAppleHomeKey:
		return "unlocked_by_apple_home_key"
	case LockEventLockedByAppleHomeKey:
		return "locked_by_apple_home_key"
	case LockEventInternalMalfunction1, LockEventInternalMalfunction2, LockEventInternalMalfunction3:
		return "internal_malfunction"
	case LockEventThreadDisconnect:
		return "thread_disconnect"
	case LockEventThreadConnect:
		return "thread_connect"
	case LockEventLockedByUWB:
		return "locked_by_uwb"
	case LockEventUnlockedByUWB:
		return "unlocked_by_uwb"
	case LockEventUWBAntennaDisconnected:
		return "uwb_antenna_disconnected"
	case LockEventLostAccurateTime:
		return "lost_accurate_time"
	default:
		return fmt.Sprintf("unknown_%d", eventType)
	}
}

// DoorStateString returns a human-readable name for a door state value.
func DoorStateString(ds int) string {
	switch ds {
	case DoorStateOpen:
		return "OPEN"
	case DoorStateClosed:
		return "CLOSED"
	case DoorStateFaulty:
		return "FAULTY"
	default:
		return "UNKNOWN"
	}
}

// FormatPIN formats an access code integer as a zero-padded string.
// codeLength is the lock's configured PIN length (4-8); if < 4, defaults to 4.
func FormatPIN(code int64, codeLength int) string {
	if codeLength < 4 {
		codeLength = 4
	}
	return fmt.Sprintf("%0*d", codeLength, code)
}
