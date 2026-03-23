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

## Device Info (Read Properties on Trait 1)

Uses `requestData` with trait=1.

| Property | Confirmed Value | Description |
|----------|----------------|-------------|
| 3 | "be459wb" | Model number |
| 4 | (serial) | Serial number |
| 5 | "00.09.044544" | Main firmware version |
| 7 | (unix timestamp) | Current time |
| 8 | "1.1" | Keypad firmware |
| 10 | "Schlage" | Manufacturer |
| 11 | "Schlage Mode" | Lock name / model name |
| 12 (0x0C) | 99 | Battery level |

Properties 9 and 0x15 return error 5 on BE459.

---

## Settings (Trait 5: LockConfig)

Read: `requestData(5, <property>)` → `{1:8, 2:4, 16:{0:5, 1:<property>}}`
Write: `saveData(5, <property>, <value>)` → `{1:8, 2:7, 16:{0:5, 1:<property>, 2:{0:<value>, 1:<userId>}}}`

### Property IDs

Settings use **different property indices for read vs write**. Read index = write index + 1.

| Setting | Write ID | Read ID | Type | Tested | Values |
|---------|----------|---------|------|--------|--------|
| Beeper | 0x02 | 0x03 | int | ✓ R/W | 0=off, 1=on |
| Auto-Lock Time | 0x04 | 0x05 | int | ✓ R/W | 0=off, otherwise seconds (app offers 15/30/60/120/240/360/600 but arbitrary values work) |
| Alarm Mode | 0x08 | 0x09 | int | ✓ R/W | Alarm selection |
| Alarm Sensitivity | 0x0A | 0x0B | int | ✓ R/W | Sensitivity level |
| Lock-and-Leave | 0x0C | 0x0D | int | ✓ R/W | 0=off, 1=on (one-touch locking) |

Read flow (sequential):
```
requestLockConfigGroup(0x03) → beeper state
requestLockConfigGroup(0x05) → auto-lock time
requestLockConfigGroup(0x09) → alarm mode
requestLockConfigGroup(0x0B) → alarm sensitivity
requestLockConfigGroup(0x0D) → lock-and-leave state
```

### Other Trait 5 Properties

These use the same ID for read and write, and have their own request formats.

| Property | Hex | Name | Type | Tested | Notes |
|----------|-----|------|------|--------|-------|
| 14 | 0x0E | Set Access Code Length | int (4-8) | ✓ (write) | Write-only; `{1:8, 2:2, 16:{0:5, 1:14, 2:{0:<length>}}}` |
| 15 | 0x0F | Access Code Length | int (4-8) | ✓ (read) | Read-only |
| 18 | 0x12 | DST Times | bytes | | See commissioning flow |
| 20 | 0x14 | Timezone | int (UTC offset minutes) | ✓ (write) | |
| 21 | 0x15 | Timezone (read) | int | ✓ (read) | |
| 26 | 0x1A | Simultaneous Mode (write) | int | ✓ (write) | 1=enable Matter protocol alongside Schlage BLE (newer locks only) |
| 27 | 0x1B | Operating Mode (read) | int | ✓ (read) | 0=Schlage, 1=Simultaneous (when read via BLE) |
| 28 | 0x1C | Max User Codes | int | ✓ (read) | Read via `saveLockConfigGroup(28, 1)` |

### Set Access Code Length

Sets the PIN length for keypad access codes (4-8 digits). Sent during commissioning
before the first access code is added.

```
{1:8, 2:2, 16:{0:5, 1:14, 2:{0:<length>}}}
```
No userId needed.

### Set DST Times

Sets daylight saving time transition timestamps. Sent during commissioning after
timezone is set.

```
{1:8, 2:1, 16:{0:5, 1:18, 2:{0:1, 1:<dst_start_bytes>, 2:<dst_end_bytes>}}}
```
- Key 0: integer `1` (DST enabled flag)
- Key 1: byte array — DST start transition time
- Key 2: byte array — DST end transition time

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
> while keeping Schlage app control). Only available on newer "Walton" hardware.

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
