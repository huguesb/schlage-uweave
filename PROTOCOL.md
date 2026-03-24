# Schlage Sense BLE Protocol Specification

Reverse-engineered protocol specification for Schlage Sense-series BLE locks
using the Google Weave (uWeave) transport layer.

> **Tested hardware:** Schlage Arrive BE459 (model `be459wb`) running firmware
> `00.09.044544`. The protocol is believed to be shared across the Schlage Sense
> family (BE459, BE479, etc.) but has only been validated against this specific
> model and firmware version. Behavior on other models may differ — known
> differences are noted inline (e.g., history batch size).

## Transport Layer

All commands use CBOR encoding over a uWeave BLE GATT service:
- **Service UUID**: `883f45ec-14cb-46aa-9864-9a4e782b33d0`
- **RX Char** (client→lock): `ff530c78-cd50-4bb9-bbd4-0712f32b3796` (Write)
- **TX Char** (lock→client): `26002998-e001-4812-8c08-5cd2afda0830` (Indicate)

Messages are fragmented into BLE packets with a 1-byte header.

## Privet RPC Envelope

All commands and responses use integer-keyed CBOR maps.

### Request Format
```
{
  1: <api_id>,      // API endpoint
  2: <req_type>,    // Request type / command type
  16: {<params>}    // Optional parameters map (key 0x10)
}
```

### Response Format
```
{
  2: <req_type>,    // Echoed request type
  3: {4: <code>, 5: <message>},  // Error (only if error occurred)
  17: <result>      // Result data (key 0x11)
}
```

Response navigation: `ParsePrivetResponse` extracts key 17 → `resp.Result`.
For data commands, `resp.Result` contains `{4: <error_code>, 17: <data>}`.
The actual data is at `resp.Result[17]`.

### Privet RPC Keys
| Key | Name | Description |
|-----|------|-------------|
| 1 | API_ID | API endpoint identifier |
| 2 | REQUEST_ID | Request type / command type |
| 3 | ERROR | Error map |
| 4 | ERROR_CODE | Error code within error map |
| 5 | ERROR_MSG | Error message within error map |
| 16 (0x10) | PARAMS | Request parameters |
| 17 (0x11) | RESULT | Response result |

### uWeave Status Codes (Error Codes)

Defined in `libuweave/uweave/status.h`. These appear in privet error responses at key 3→4.

> **Note:** Only codes marked ✓ have been observed on real hardware. Others are from
> the uWeave source and are included for completeness.

| Code | Name | Observed | Description |
|------|------|----------|-------------|
| 0 | Success | ✓ | |
| 1 | NotFound | | |
| 2 | InvalidInput | ✓ | e.g., history batch size > 1 on BE459 |
| 3 | TooLong | | |
| 4 | InvalidArgument | | |
| 5 | CommandNotFound | ✓ | e.g., requestData on unsupported property |
| 10 | DeviceCryptoNoKeys | | |
| 11 | AuthenticationRequired | | |
| 12 | AuthenticationFailed | | |
| 13 | InsufficientRole | | |
| 14 | PairingRequired | | |
| 15 | VerificationFailed | | |
| 17 | SessionExpired | | |
| 18 | CryptoIncomingMessageInvalid | | |
| 21 | EncryptionRequired | | |
| 50 | PrivetNotFound | | |
| 51 | PrivetInvalidParam | | |
| 52 | PrivetParseError | | |
| 53 | PrivetResponseTooLarge | | |
| 140 | PairingPinCodeTypeUnsupported | | |
| 141 | PairingEmbeddedCodeTypeUnsupported | | |
| 142 | PairingPinCodeGenerationFailed | | |
| 143 | PairingEmbeddedCodeProviderFailed | | |
| 144 | PairingEmbeddedCodeAppendFailed | | |
| 110 | ? (unknown) | ✓ | Returned when reading a write-only property via requestData (observed on DST times 0x12) |
| 145 | PairingResetRequired | ✓ | Device already paired; factory reset needed to re-pair |

---

## API Endpoints

| API ID | Name | Tested | Description |
|--------|------|--------|-------------|
| 2 | /pairing/start | ✓ | Begin SPAKE pairing |
| 3 | /pairing/confirm | ✓ | Confirm SPAKE pairing |
| 5 | /auth | ✓ | Send CAT/SAT authentication |
| 6 | /state | ✓ | Request lock state |
| 8 | /data | ✓ | Read/write data (multi-purpose) |
| 24 (0x18) | /access/claim | ✓ | Request access control claim |
| 25 (0x19) | /access/confirm | ✓ | Confirm access control |

> **Note:** The uWeave spec defines API 0 (/info) and API 9 (/setup) but the
> official Schlage Home app never sends either. All device info and setup
> operations are done through API 8 (/data) instead.

---

## Trait Groups

Used as `params[0]` in API 8 (/data) commands.

| Trait | Name | Description |
|-------|------|-------------|
| 1 | LockData | Lock state, device info, time, battery |
| 3 | History / DeviceMgmt | Event log; also factory reset (sub-cmd 3) |
| 4 | AccessCodes | Keypad PIN management |
| 5 | LockConfig | Settings, timezone, operating mode |
| 6 | WiFi | WiFi provisioning, scanning, status |

---

## API 6: Lock State (/state)

### Request
```
{1:6, 2:3}
```
No params.

### Response
Deeply nested:
```
resp.Result[1][0][0][1] → trait state map
```

Trait state map keys:
| Key | Name | Type | Tested | Description |
|-----|------|------|--------|-------------|
| 0x00 | LOCK_STATUS | int | ✓ | Lock state enum |
| 0x0C | BATTERY_STATE | int | ✓ | Battery state enum |
| 0x0E | ALARM_ENABLED | int | ✓ | Alarm state |
| 0x15 | BATTERY_LEVEL | int | ✓ | Battery percentage (0-100) |
| 0x19 | DOOR_STATE | int | | Door state enum (see note below) |

### Lock State Enum
| Value | Name | Tested | Description |
|-------|------|--------|-------------|
| 0 | UNLOCKED | ✓ | Bolt retracted |
| 1 | LOCKED | ✓ | Bolt extended normally |
| 2 | JAMMED | ✓ | Bolt extended with difficulty (still locked) |
| 3 | UNKNOWN | | Unknown state |
| 4 | MOTOR_JAMMED | | Motor stalled, bolt position uncertain |
| 5 | PASSAGE_MODE | | Bolt always retracted |
| 6 | DEADLOCKED | | Bolt fully extended, extra secure |

### Door State Enum

> **Untested:** The BE459 does not appear to have a door sensor; this field has only
> been observed returning UNKNOWN (0). Values 1–3 are from the app.

| Value | Name |
|-------|------|
| 0 | UNKNOWN |
| 1 | OPEN |
| 2 | CLOSED |
| 3 | FAULTY |

---

## API 8: Data Operations (/data)

### requestData (Read Property)
```
{1:8, 2:4, 16:{0:<trait>, 1:<property>}}
```
Response: `resp.Result[17]` = property value

### saveData (Write Property)
```
{1:8, 2:7, 16:{0:<trait>, 1:<property>, 2:{0:<value>, 1:<userId_bytes>}}}
```
Note: `userId` is a 16-byte user identifier.
Response: `resp.Result[17]` = updated state map

---

## Lock/Unlock Commands

Uses `saveData` on Trait 1 (LockData), Property 0 (LOCK_STATUS).

### Lock
```
{1:8, 2:7, 16:{0:1, 1:0, 2:{0:1, 1:<userId>}}}
```
Value 1 = LOCKED ordinal.

### Unlock
```
{1:8, 2:7, 16:{0:1, 1:0, 2:{0:0, 1:<userId>}}}
```
Value 0 = UNLOCKED ordinal.

---

## Device Info / Lock Data (Trait 1)

Read: `requestData(1, <property>)` → `{1:8, 2:4, 16:{0:1, 1:<property>}}`
Write: `saveData(1, <property>, <value>)` → `{1:8, 2:7, 16:{0:1, 1:<property>, 2:{0:<value>, 1:<userId>}}}`

### Probe Results (BE459, firmware 00.09.044544)

Full `requestData` sweep of trait 1 property IDs 0x00–0x0F. Trait 1 follows
the same write=N/read=N+1 pattern as trait 5 for time (write=0x06, read=0x07).

| Write | Read | Name | BE459 Read | Notes |
|-------|------|------|------------|-------|
| 0x00 | 0x01 | Lock Status | OK: int 1 | Write=lock/unlock; read=current state (0=unlocked, 1=locked) |
| 0x02 | 0x03 | Manufacturer / Model | "be459wb" | 0x02 also returns "Schlage" (manufacturer) |
| — | 0x04 | Serial Number | (serial string) | Read-only |
| — | 0x05 | Main Firmware Version | "00.09.044544" | Read-only |
| 0x06 | 0x07 | Current Time | (unix timestamp) | Write sets clock; read returns current time |
| — | 0x08 | Keypad Firmware | "1.1" | Read-only |
| — | 0x09 | ? | error 5 | Unknown / not supported on BE459 |
| — | 0x0A | Manufacturer | "Schlage" | Read-only |
| — | 0x0B | Lock Name | "Schlage Mode" | Read-only; model/mode label |
| — | 0x0C | Battery Level | 99 | Read-only; percentage |
| — | 0x0D | ? | error 5 | Unknown / not supported on BE459 |
| — | 0x0E | ? | error 5 | Unknown / not supported on BE459 |
| — | 0x0F | Firmware Manifest | (large map) | Read-only; multi-component version info |

Gaps: 0x09, 0x0D, 0x0E return error 5.

### Firmware Manifest (Property 0x0F)

Property 0x0F returns a rich firmware version manifest with multiple components:

```
{
  0: "00.09.044544",   // Main firmware
  1: "1.1",            // Keypad firmware
  2: "4.4",            // Component 2
  3: "0.1",            // Component 3
  4: "",               // Component 4 (empty)
  5: "1.3"             // Component 5
}
```

### Known Read Properties

| Property | Confirmed Value | Description |
|----------|----------------|-------------|
| 0x01 | 1 | Lock state (0=unlocked, 1=locked) |
| 0x03 | "be459wb" | Model number |
| 0x04 | (serial) | Serial number |
| 0x05 | "00.09.044544" | Main firmware version |
| 0x07 | (unix timestamp) | Current time |
| 0x08 | "1.1" | Keypad firmware |
| 0x0A | "Schlage" | Manufacturer |
| 0x0B | "Schlage Mode" | Lock name / model name |
| 0x0C | 99 | Battery level (percentage) |
| 0x0F | (firmware manifest map) | Multi-component version info |

### Set Time (Write Property 0x06)

Sets the lock's internal clock. Uses `saveData` on trait 1, property 6.

```
{1:8, 2:7, 16:{0:1, 1:6, 2:{0:<unix_timestamp>, 1:<userId>}}}
```

Should be called during pairing/claim flow and periodically to keep the lock's
clock accurate (the lock has no NTP or other time source).

---

## Settings (Trait 5: LockConfig)

Read: `requestData(5, <property>)` → `{1:8, 2:4, 16:{0:5, 1:<property>}}`
Write: `saveData(5, <property>, <value>)` → `{1:8, 2:7, 16:{0:5, 1:<property>, 2:{0:<value>, 1:<userId>}}}`

### Probe Results (BE459, firmware 00.09.044544)

Full `requestData` sweep of trait 5 property IDs 0x00–0x20. This confirms the
write=N/read=N+1 pattern across all properties. Write IDs return error 2
(InvalidInput) when read via `requestData` — they require `saveData` format.

| Write | Read | Name | BE459 Read | Notes |
|-------|------|------|------------|-------|
| — | 0x01 | ? (unknown) | OK: 3-byte string `\xed\xd4\x05` | Read-only, stable, not CBOR. Possibly hw capability bitmap or config fingerprint |
| 0x02 | 0x03 | Beeper | 1 | 0=off, 1=on |
| 0x04 | 0x05 | Auto-Lock Time | 0 | Seconds; 0=off |
| 0x06 | 0x07 | Access Point Params | 0 | Purpose unclear |
| 0x08 | 0x09 | Alarm Mode | 0 | Alarm selection |
| 0x0A | 0x0B | Alarm Sensitivity | 0 | Sensitivity level |
| 0x0C | 0x0D | Lock-and-Leave | 1 | 0=off, 1=on |
| 0x0E | 0x0F | Access Code Length | 6 | 4-8 digits; write uses special reqType 2 |
| 0x12 | 0x13 | DST Times | {0:0, 1:[0,0,0,1], 2:[0,0,0,1]} | Write uses reqType 1; read returns structured map |
| 0x14 | 0x15 | Timezone | 0 | UTC offset in minutes |
| 0x18 | 0x19 | ? (unknown) | 0 | Undocumented write/read pair |
| 0x1A | 0x1B | Simultaneous / Op Mode | error 5 | Not supported on BE459; Encode/Walton WiFi only |
| — | 0x1C | Max User Codes | error 5 | Needs `saveLockConfigGroup(28, 1)`, not `requestData` |

Gaps: 0x00 (error 5), 0x10–0x11 (error 5), 0x16–0x17 (error 5), 0x1D–0x20 (error 5).

Error 110 was observed when reading the DST write property (0x12) — an undocumented
uWeave status code, distinct from error 2 (InvalidInput) returned by other write-only properties.

### Standard Settings

Read: `requestData(5, <readID>)` → `{1:8, 2:4, 16:{0:5, 1:<readID>}}`
Write: `saveData(5, <writeID>, <value>)` → `{1:8, 2:7, 16:{0:5, 1:<writeID>, 2:{0:<value>, 1:<userId>}}}`

| Setting | Write ID | Read ID | Type | Values |
|---------|----------|---------|------|--------|
| Beeper | 0x02 | 0x03 | int | 0=off, 1=on |
| Auto-Lock Time | 0x04 | 0x05 | int | 0=off, otherwise seconds (app offers 15/30/60/120/240/360/600 but arbitrary values work) |
| Access Point Params | 0x06 | 0x07 | int | Unknown purpose; reads as 0 on BE459 |
| Alarm Mode | 0x08 | 0x09 | int | Alarm selection |
| Alarm Sensitivity | 0x0A | 0x0B | int | Sensitivity level |
| Lock-and-Leave | 0x0C | 0x0D | int | 0=off, 1=on (one-touch locking) |
| Timezone | 0x14 | 0x15 | int | UTC offset in minutes (e.g., -300 for EST) |
| ? (unknown) | 0x18 | 0x19 | int | Reads as 0 on BE459; purpose unknown |

### Special-Format Properties

These follow the write=N/read=N+1 pattern but use non-standard wire formats for writes.

| Setting | Write ID | Read ID | Type | Notes |
|---------|----------|---------|------|-------|
| Access Code Length | 0x0E | 0x0F | int (4-8) | Write: reqType 2, no userId |
| DST Times | 0x12 | 0x13 | map | Write: reqType 1; read confirmed on BE459 |
| Simultaneous Mode | 0x1A | 0x1B | int | BE459: error 5. Encode/Walton WiFi only |
| Max User Codes | — | 0x1C | int | Read via `saveLockConfigGroup(28, 1)`; BE459: error 5 via requestData |

### Set Access Code Length

Sets the PIN length for keypad access codes (4-8 digits). Sent during commissioning
before the first access code is added.

```
{1:8, 2:2, 16:{0:5, 1:14, 2:{0:<length>}}}
```
No userId needed.

> **Observed behavior:** Setting the code length does NOT retroactively validate
> existing codes. A lock configured with 4-digit codes will continue to accept
> them after the length is changed to 6. Leading zeros are ignored during keypad
> entry — the lock matches against the integer value (e.g., `001234` matches a
> code stored as `1234`). Even zero-padding beyond the configured length limit
> (e.g., 10+ digits with leading zeros for a 4-digit code) is accepted.

### DST Times

Sets daylight saving time transition timestamps. Sent during commissioning after
timezone is set.

Write:
```
{1:8, 2:1, 16:{0:5, 1:18, 2:{0:1, 1:<dst_start_bytes>, 2:<dst_end_bytes>}}}
```
- Key 0: integer — DST enabled flag (1=enabled, 0=disabled)
- Key 1: byte array — DST start transition time
- Key 2: byte array — DST end transition time

Read (confirmed on BE459):
```
{1:8, 2:4, 16:{0:5, 1:19}}
```
Response: `{0: <enabled_flag>, 1: <start_bytes>, 2: <end_bytes>}`

Default (unset) values: `{0:0, 1:[0,0,0,1], 2:[0,0,0,1]}` — DST disabled,
both timestamps set to `[0x00, 0x00, 0x00, 0x01]`.

> **Note:** The app never reads DST times, but the firmware responds to
> `requestData(5, 19)`. Error 110 is returned if you try to `requestData(5, 18)`
> (the write property) — this is a previously-undocumented uWeave status code.

### Operating Mode / Simultaneous Mode

The lock can operate in different modes:

| Mode | Value (API) | Value (BLE read) | Description |
|------|-------------|-------------------|-------------|
| Schlage | 1 | 0 | Standard Schlage BLE only |
| HomeKit | 2 | — | Apple HomeKit mode |
| Simultaneous | 3 | 1 | Schlage BLE + Matter protocol |

Read current mode: `requestLockConfigGroup(27)` — `{1:8, 2:4, 16:{0:5, 1:27}}`
Enable simultaneous (Matter): `saveLockConfigGroup(26, 1)` — `{1:8, 2:7, 16:{0:5, 1:26, 2:{0:1, 1:<userId>}}}`

> **Note:** Simultaneous mode enables the Matter smart home protocol alongside
> Schlage BLE. It does NOT allow multiple Schlage BLE clients — it's about
> protocol coexistence (e.g., adding the lock to Apple Home/Google Home via Matter
> while keeping Schlage app control).
>
> **BE459 returns error 5** for both operating mode read (0x1B) and simultaneous
> mode write (0x1A). These properties are available only on Encode-family and
> Walton locks with WiFi capability. See the model support matrix below.

---

## Model Support Matrix

Device families and their capabilities, from decompiled APK analysis (`SenseDevice.java`,
`DeviceTypeUtilityKt.java`, `SenseDeviceUtilityKt.java`).

### Lock Families

| Family | Models | App Internal Name | Notes |
|--------|--------|-------------------|-------|
| **SENSE** | be479 | SENSE | BLE-only, oldest |
| **WKD** (Arrive) | be459, be459ble, be459wifi | WKD | Our test hardware |
| **WALTON** (Sense Pro) | be889, be889ble, be889wifi | WALTON | Feature-flagged in app |
| **DENALI** (Encode) | be489, be489ble, be489wifi, +McKinley variants | DENALI | Multiple generations |
| **JACKALOPE** (Encode Plus) | be499, be499ble, be499wifi, +McKinley variants | JACKALOPE | |
| **ENCODE LEVER** | fe789, fe789ble, fe789wifi, +McKinley variants | ENCODE_LEVER | Lever form factor |
| **SELENE** | gselent*, gselsec*, sselent*, sselsec* | SELENE | Gainsborough/Schlage variants |
| **BRIDGE** | br400 | BRIDGE | WiFi adapter, not a lock |

> **Note:** Models with `wifi` or `wb` suffix have an onboard WiFi module. Models
> with `ble` suffix are BLE-only variants of the same hardware. The BLE protocol
> is the same across variants; WiFi adds trait 6 operations.

### Feature Availability

| Feature | SENSE (be479) | WKD (be459) | Encode (be489/499/fe789) | WALTON (be889) |
|---------|---------------|-------------|--------------------------|----------------|
| Max access codes | 30 | 250 | 100 | 250 |
| Standard settings (beeper, auto-lock, alarm, lock-and-leave) | ? | ✓ | ✓ | ✓ |
| Timezone | ? | ✓ | ✓ | ✓ |
| Set access code length | ? | ✓ | ✓ | ✓ |
| Operating mode / simultaneous | No | **error 5** | ✓ (WiFi variants) | ✓ (WiFi variants) |
| WiFi (trait 6) | via Bridge | WiFi variant | WiFi variants | WiFi variant |
| History batch size | ? | 1 only | up to 5 | up to 5 |
| DST times | ? | ✓ (read/write) | untested | untested |
| Deadlock | No | ✓ | ✓ | ✓ |
| Passage mode | No | ✓ | ✓ | ✓ |

> **Observed:** BE459 (WKD BLE-only) returns privet error 5 (CommandNotFound) for
> operating mode read (property 0x1B) and is expected to do the same for
> simultaneous mode write (property 0x1A). Despite being classified as "WKD" in
> the app (same family as the WiFi-equipped be459wifi), the BLE-only variant does
> not support these properties. The app likely gates this on the WiFi device type check.

---

## Factory Reset (Trait 3, Sub-cmd 3)

Performs a factory default reset (FDR) of the lock, erasing all pairing data,
access codes, and settings.

```
{1:8, 2:2, 16:{0:3, 1:3}}
```
No additional parameters. Response is success/error only.

The app's flow after a successful BLE factory reset:
1. Disconnect from the lock
2. Remove cloud associations (`deleteLockAndAssociation`)
3. Clean up local caches

If the BLE reset fails, the app falls back to a cloud-side delete.

---

## Access Code Operations (Trait 4)

Access codes use their own CBOR command format,
NOT the generic `saveData`/`requestData` pattern.

### Maximum Access Codes (per model, from app `UsefulConstants` / `getMaxItemCountForAccessCode`)

| Lock Family | Models | Max Codes |
|---|---|---|
| Encode | WKD / Walton | 250 |
| Encode | Other | 100 |
| Sense (non-Encode) | BE459, etc. | 30 |

The lock may also report its own `maxUserCodes` via device attributes (trait 5, property 0x1C),
which the app reads before listing codes. Our implementation skips this and uses `moreAvailable`
to drive the read loop.

### Read Flow

The lock returns codes one at a time in a loop:

1. ✓ **Read code length**: `{1:8, 2:4, 16:{0:5, 1:15}}` (requestData trait=5, prop=0x0F) — returns int 4-8, used to zero-pad PINs on display
2. ✓ **Check available**: `{1:8, 2:3, 16:{0:4, 1:6, 2:{0:0}}}`
   - Response: `resp.Result[17]` = nonzero if codes exist (NOT the actual count — observed returning 1 when 3 codes are present)
3. ✓ **Read one code**: `{1:8, 2:4, 16:{0:4, 1:5}}`
   - Response: `resp.Result[17]` = flat code data map (see below)
   - Check `codeData[10]` (0x0A) for more: if > 0, send another read
4. ✓ Repeat step 3 until `codeData[10] == 0`

### Code Data Map (response at resp.Result[17])
| Key | Name | Type | Tested | Description |
|-----|------|------|--------|-------------|
| 0 | UUID | bytes | ✓ | 16-byte identifier (big-endian) |
| 1 | Name | string | ✓ | User label |
| 2 | Code | int64 | ✓ | PIN as integer (e.g. 1234) |
| 3 | Schedule1 | bytes | | Weekly schedule (optional) |
| 4 | Schedule2 | bytes | | Additional schedule (optional) |
| 5 | Blocked | int | ✓ | 0=active, 1=blocked |
| 6 | StartDate | int64 | | Start epoch seconds (0 if none) |
| 7 | EndDate | int64 | | End epoch seconds (0xFFFFFFFF if none) |
| 10 (0x0A) | MoreAvailable | int | ✓ | Count of remaining codes to read |

### Add Access Code
```
{1:8, 2:3, 16:{0:4, 1:0, 2:{0:<uuid_bytes>, 1:<name>, 2:<code_long>, 5:<blocked>}}}
```
- `params[1]` = 0 for add
- Optional keys 3, 4, 6, 7 for schedules/dates

### Update Access Code *(untested)*
```
{1:8, 2:3, 16:{0:4, 1:4, 2:{0:<uuid_bytes>, 1:<name>, 2:<code_long>, 5:<blocked>}}}
```
- `params[1]` = 4 for update (vs 0 for add)
- Not implemented; format is from app analysis

### Delete Access Code
```
{1:8, 2:2, 16:{0:4, 1:1, 2:{2:<code_long>}}}
```
Identifies code by PIN value at key 2.

### Delete All Access Codes
```
{1:8, 2:5, 16:{0:4, 1:2}}
```

---

## History Operations (Trait 3)

### Check Available
```
{1:8, 2:2, 16:{0:3, 1:0, 2:{0:0}}}
```
Response: `resp.Result[17]` = integer flag (>0 means logs exist).
This is NOT the total count — it's a boolean gate. The actual number of entries
is discovered by reading until `moreAvailable` (key 4) reaches 0.

### Read Entries
```
{1:8, 2:3, 16:{0:3, 1:<readLogsInGroupOf>}}
```
`params[1]` = number of entries per request.

- BE459: Always use batch size 1 (batch size > 1 returns privet error 2)
- Other models (e.g., Denali): May support batch sizes up to 5

When batch size > 1, the response may contain multiple entries at batch index keys
(0x0A–0x0E). When batch size == 1, the response is a single flat entry map.

> **Note:** Batch mode (batch > 1) is from app analysis and has **not been tested**.
> BE459 rejects batch sizes > 1 with privet error 2. The batch parsing code exists
> but has only been exercised in single-entry mode.

Response: `resp.Result[17]` = data map. Key `4` = more entries available (int, >0 means repeat).

**Batch mode** (if data map contains key `0x0A`):
Individual entries at keys `0x0A`–`0x0E` (LOG_0 through LOG_4), each a nested entry map.

**Single mode** (no key `0x0A`):
The data map itself is a single entry.

### Log Entry Structure
| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | LOG_ACCESSOR_KEY | bytes | 16-byte actor UUID |
| 1 | LOG_TIME_KEY | int | Unix timestamp |
| 2 | LOG_ACTION_KEY | int | Action enum |
| 3 | LOG_EVENTS_KEY | map | Event details (see below) |

Event details map (key 3):
| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | LOG_EVENTS_ACTION_KEY | int | Event type (see lock event constants) |
| 1 | LOG_EVENTS_ACTION_DEVICE_KEY | bytes | Related device UUID |

### Read Flow
1. Check available: send check request; if `Result[17]` == 0, no logs exist → stop
2. Read: `{1:8, 2:3, 16:{0:3, 1:<readLogsInGroupOf>}}`
3. Parse entries from response at `Result[17]` (single or batch mode)
4. Check `data[4]` — if >0 and `collected < maxEntries`, send another read
5. Repeat until `data[4] == 0` or maxEntries reached

### Batch Index Keys
| Key | Name |
|-----|------|
| 0x0A (10) | LOG_0_INDEX_KEY |
| 0x0B (11) | LOG_1_INDEX_KEY |
| 0x0C (12) | LOG_2_INDEX_KEY |
| 0x0D (13) | LOG_3_INDEX_KEY |
| 0x0E (14) | LOG_4_INDEX_KEY |

Batch mode is detected by checking for the presence of LOG_0_INDEX_KEY (0x0A).

---

## WiFi Operations (Trait 6)

WiFi provisioning and management. Used during commissioning to connect the lock
to a WiFi network. All commands use API 8 (/data) with trait 6.

> **Not implemented** in our codebase — documented from app analysis for completeness.

### Sub-commands

| Sub-cmd | ReqID | Name | Description |
|---------|-------|------|-------------|
| 0 | 4 | Configure WiFi | Send SSID/password/security type |
| 1 | 4 | Read AP Params | Read current access point SSID and security |
| 2 | 4 | Send Payload0 | Pre-configuration payload (opaque bytes) |
| 4 | 5 | JITR Status | Read WiFi commissioning status |
| 8 | 1 | Start WiFi Scan | Trigger scan for available networks |
| 9 | 3 | Read Scan Results | Read one network at a time (loop on key 3) |
| 10 | 6 | Read WiFi MAC | Read the lock's WiFi MAC address |

### Configure WiFi Credentials (sub-cmd 0)
```
{1:8, 2:4, 16:{0:6, 1:0, 2:{0:<ssid_text>, 1:<password_text>, 2:1}}}
```
- Key 0: SSID as CBOR text string
- Key 1: Password as CBOR text string
- Key 2: Security type integer (1 = WPA Personal)

### Read Access Point Params (sub-cmd 1)
```
{1:8, 2:4, 16:{0:6, 1:1}}
```
Response: `{0: <ssid_string>, 2: <security_type_int>}`

### Send Payload0 (sub-cmd 2)
```
{1:8, 2:4, 16:{0:6, 1:2, 2:{0:<payload_bytes>}}}
```
Opaque pre-configuration payload sent before WiFi credentials.

### JITR Status (sub-cmd 4)
```
{1:8, 2:5, 16:{0:6, 1:4}}
```
Response key 0 maps to `WifiCommissionStatus`:
| Value | Name |
|-------|------|
| 0 | STOPPED |
| 1 | STARTED |
| 2 | SUCCESS |
| 3 | AP_ERROR |
| 4 | HOST_ERROR |
| 5 | IP_ACQUIRED |
| 6 | AP_ERROR_WRONG_CREDENTIALS |

### Start WiFi Scan (sub-cmd 8)
```
{1:8, 2:1, 16:{0:6, 1:8}}
```
Response key 0: 0 = scan started, otherwise error.

### Read WiFi Scan Results (sub-cmd 9)
```
{1:8, 2:3, 16:{0:6, 1:9}}
```
Returns one network per call. Response:
- Key 0: Status (0=INFO_INCLUDED, 1=SCAN_IN_PROGRESS, 2=NO_INFO_PRESENT)
- Key 1: SSID string
- Key 2: RSSI integer
- Key 3: More records flag (1 = call again for next network)

### Read WiFi MAC Address (sub-cmd 10)
```
{1:8, 2:6, 16:{0:6, 1:10}}
```
Response: MAC address as string.

---

## Commissioning Flow

Steps marked ✓ are implemented and tested. Others are from app analysis.

1. ✓ SPAKE pairing (startPairing + confirm)
2. ✓ Token decryption (extract CAT/SAT)
3. ✓ Reconnect with `CryptoModeTokenSHA256`
4. ✓ SAT handshake → encrypted channel
5. ✓ Send CAT (`/auth`)
6. ✓ **Claim**: `{1:24, 2:4}` → response has CAT bytes at `result[0]`
7. ✓ **Confirm**: `{1:25, 2:5, 16:{0:<cat_bytes>}}`
8. ✓ **Set Timezone**: `saveData(5, 0x14, <offset_minutes>)`
   - `{1:8, 2:7, 16:{0:5, 1:20, 2:{0:<offset>, 1:<userId>}}}`
9. *(untested)* **Set DST Times**: `{1:8, 2:1, 16:{0:5, 1:18, 2:{0:1, 1:<start_bytes>, 2:<end_bytes>}}}`
10. ✓ Read serial number, model name, firmware version
11. Cloud registration (not BLE — out of scope)
12. ✓ Write first access code
13. *(untested)* Auto-handing: lock + unlock with door cracked open
