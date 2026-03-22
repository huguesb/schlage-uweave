# schlage-uweave

A Go library implementing the Schlage Sense BLE lock protocol, reverse-engineered from the Schlage Arrive (BE459) smart lock. It provides complete lock control over Bluetooth Low Energy using the Google Weave (uWeave) transport layer.

See [PROTOCOL.md](PROTOCOL.md) for the full reverse-engineered protocol specification.

## Features

- **Pairing** — SPAKE2 key exchange for secure initial setup
- **Lock/Unlock** — Remote lock control over BLE
- **Access Codes** — Create, list, and remove PIN codes
- **Device Info** — Read model, serial number, firmware version, and battery level
- **History** — Retrieve timestamped event logs
- **Settings** — Configure auto-lock time, beeper, alarms, and more
- **Encrypted Sessions** — AES-128-EAX authenticated encryption with HKDF-SHA256 key derivation

## Code Structure

| File | Description |
|------|-------------|
| `session.go` | Main API — pairing, authentication, lock operations, and credential management |
| `privet.go` | CBOR encoding/decoding and Privet RPC protocol (trait-based lock commands) |
| `crypto.go` | AES-128-EAX encryption, HKDF-SHA256 key derivation, AES-CMAC |
| `spake.go` | SPAKE2 key exchange over NIST P-224 for password-based pairing |
| `packet.go` | uWeave packet framing and BLE fragmentation/reassembly |
| `macaroon.go` | Macaroon (HMAC-SHA256 auth token) deserialization |
| `transport.go` | Abstract BLE GATT transport interface |

## Usage

```go
import "golang.betakappaphi.com/schlage-uweave"
```

Provide a `Transport` implementation for your BLE stack, then use `Session` to interact with the lock:

```go
s := schlage.NewSession(transport)

// First time: pair with the lock
creds, err := s.Pair(pairingCode)

// Subsequent connections: authenticate and control
err = s.Authenticate(creds)
err = s.Unlock()
err = s.Lock()
```

## Requirements

- Go 1.18+
- A BLE adapter and a compatible Schlage lock (tested on BE459, firmware 00.09.044544)

## License

MIT — see [LICENSE](LICENSE) for details.
