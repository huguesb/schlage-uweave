package schlage_uweave

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// staticUserID is a fixed 16-byte identifier sent in saveData commands.
// The lock uses this for history attribution only, not authentication.
// Spells "ble2mqtt-schlage" in ASCII.
var staticUserID = []byte("ble2mqtt-schlage")

// Session represents an active uWeave BLE session with a Schlage lock.
type Session struct {
	transport Transport

	conn       *ConnectionState
	fragmenter *Fragmenter
	assembler  *Assembler
	cipher     *SessionCipher // nil until encrypted session established

	// Crypto handshake state
	clientRandom []byte
	serverRandom []byte

	// Stored credentials
	credentials *StoredCredentials
}

// StoredCredentials holds the pairing tokens received from the lock.
type StoredCredentials struct {
	DeviceID     string `json:"device_id"`
	PairingToken []byte `json:"pairing_token"`
	SessionToken []byte `json:"session_token"`
}

// NewSession creates a new uWeave session using the given transport.
func NewSession(transport Transport) *Session {
	return &Session{
		transport: transport,
		assembler: NewAssembler(),
	}
}

// Connect performs the uWeave connection handshake (ConnectionRequest/Confirm).
// Use CryptoModePassthrough for initial pairing (no SAT yet),
// or CryptoModeTokenSHA256 for authenticated sessions.
func (s *Session) Connect(cryptoMode byte) error {
	log.Debug("session: sending ConnectionRequest")

	reqBytes, clientRandom := NewConnectionRequest(MaxDefaultPacketSize, cryptoMode)
	s.clientRandom = clientRandom
	log.WithField("hex", hex.EncodeToString(reqBytes)).Debug("session: ConnectionRequest bytes")
	if err := s.transport.Write(reqBytes); err != nil {
		return fmt.Errorf("session: failed to write ConnectionRequest: %w", err)
	}
	log.Debug("session: ConnectionRequest write acknowledged by lock")

	// Wait for ConnectionConfirm.
	log.Debug("session: waiting for ConnectionConfirm...")
	confirmData, err := s.transport.Receive()
	if err != nil {
		return fmt.Errorf("session: failed to receive ConnectionConfirm: %w", err)
	}

	log.WithField("hex", hex.EncodeToString(confirmData)).Debug("session: ConnectionConfirm raw bytes")

	version, packetSize, serverRandom, err := ParseConnectionConfirm(confirmData)
	if err != nil {
		return fmt.Errorf("session: failed to parse ConnectionConfirm: %w", err)
	}
	s.serverRandom = serverRandom

	log.WithFields(log.Fields{
		"version":      version,
		"packetSize":   packetSize,
		"serverRandom": hex.EncodeToString(serverRandom),
	}).Debug("session: connection established")

	s.conn = &ConnectionState{
		MaxPacketSize: packetSize,
		Version:       version,
		Counter:       1, // ConnectionRequest consumed counter 0
	}
	s.fragmenter = NewFragmenter(s.conn)
	s.assembler = NewAssembler()

	return nil
}

// ConnectDirect sets up the session without the uWeave transport handshake.
// Some lock firmware (e.g., Schlage Arrive) may skip the ConnectionRequest/Confirm
// exchange and go straight to the Privet RPC layer.
func (s *Session) ConnectDirect() {
	log.Debug("session: skipping uWeave transport handshake (direct mode)")
	s.conn = &ConnectionState{
		MaxPacketSize: MaxDefaultPacketSize,
		Version:       1,
	}
	s.fragmenter = NewFragmenter(s.conn)
	s.assembler = NewAssembler()
}

// Pair performs the SPAKE P224 pairing handshake using the lock's programming code.
// Returns the stored credentials on success.
func (s *Session) Pair(password string) (*StoredCredentials, error) {
	log.Debug("session: starting pairing flow")

	// Skip /info for now — go straight to pairing to minimize lock-side state

	// Step 2: Send PairingStartRequest
	startReq := PairingStartRequest(PairingTypeEmbedded, CryptoSPAKE_P224)
	startResp, err := s.sendRPC(startReq)
	if err != nil {
		return nil, fmt.Errorf("session: /pairing/start request failed: %w", err)
	}
	if startResp.Error != nil {
		return nil, fmt.Errorf("session: /pairing/start error: %w", startResp.Error)
	}
	log.Debug("session: /pairing/start response received")

	// Step 3: Extract sessionID and server's SPAKE commitment from the response
	// sessionID is an integer (int64 from CBOR), not bytes
	sessionID, ok := startResp.Result[0]
	if !ok {
		return nil, fmt.Errorf("session: /pairing/start missing session ID")
	}
	serverCommitment, ok2 := startResp.Result[1].([]byte)
	if !ok2 {
		return nil, fmt.Errorf("session: /pairing/start missing server commitment (got %T)", startResp.Result[1])
	}
	log.WithFields(log.Fields{
		"sessionID":        sessionID,
		"commitmentLen":    len(serverCommitment),
	}).Debug("session: got pairing session")

	// Step 4: Create SPAKE client
	spake, clientCommitment, err := NewSpakeClient(password)
	if err != nil {
		return nil, fmt.Errorf("session: SPAKE client creation failed: %w", err)
	}

	// Step 5: Compute shared secret from server's commitment
	sharedSecret, err := spake.ComputeSecret(serverCommitment)
	if err != nil {
		return nil, fmt.Errorf("session: SPAKE secret computation failed: %w", err)
	}
	log.Debug("session: SPAKE shared secret computed")

	// Step 6: Build encrypted timestamp (required by Schlage firmware).
	// AES-EAX key = first 16 bytes of the 56-byte SPAKE shared point.
	// Plaintext = CBOR map {0: unix_timestamp_seconds}.
	// Nonce = single byte 0x00, tag = 12 bytes, no AAD.
	pairingKey := sharedSecret[:16]
	timestampCBOR, err := cborEncodeMap(map[int]interface{}{0: int(time.Now().Unix())})
	if err != nil {
		return nil, fmt.Errorf("session: failed to encode timestamp CBOR: %w", err)
	}
	encryptedTimestamp, err := eaxEncrypt(pairingKey, []byte{0x00}, timestampCBOR, nil)
	if err != nil {
		return nil, fmt.Errorf("session: failed to encrypt timestamp: %w", err)
	}
	log.WithField("len", len(encryptedTimestamp)).Debug("session: encrypted timestamp built")

	// Step 7: Send PairingConfirmRequest with our commitment and timestamp
	confirmReq := PairingConfirmRequest(sessionID, clientCommitment, encryptedTimestamp)
	confirmResp, err := s.sendRPC(confirmReq)
	if err != nil {
		return nil, fmt.Errorf("session: /pairing/confirm request failed: %w", err)
	}
	if confirmResp.Error != nil {
		return nil, fmt.Errorf("session: /pairing/confirm error: %w", confirmResp.Error)
	}
	log.Debug("session: /pairing/confirm response received")

	// Step 8: Decrypt the encrypted tokens from the response.
	// Result key 0 = AES-EAX encrypted CBOR map {0: CAT macaroon, 1: SAT macaroon}.
	// Encrypted with the same pairing key, nonce = 0x01, tag = 12 bytes.
	encryptedTokens, ok := confirmResp.Result[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("session: /pairing/confirm missing encrypted tokens (got %T)", confirmResp.Result[0])
	}
	log.WithField("len", len(encryptedTokens)).Debug("session: decrypting tokens")

	tokensCBOR, err := eaxDecrypt(pairingKey, []byte{0x01}, encryptedTokens, nil)
	if err != nil {
		return nil, fmt.Errorf("session: failed to decrypt tokens: %w", err)
	}

	tokensMap, err := cborDecodeMap(tokensCBOR)
	if err != nil {
		return nil, fmt.Errorf("session: failed to decode tokens CBOR: %w", err)
	}

	// Key 0 = Client Authorization Token (CAT) macaroon
	// Key 1 = Server Authentication Token (SAT) macaroon
	catToken, ok := tokensMap[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("session: /pairing/confirm missing CAT token (got %T)", tokensMap[0])
	}
	satToken, ok := tokensMap[1].([]byte)
	if !ok {
		return nil, fmt.Errorf("session: /pairing/confirm missing SAT token (got %T)", tokensMap[1])
	}

	creds := &StoredCredentials{
		DeviceID:     strings.ReplaceAll(strings.ToUpper(s.transport.Addr()), ":", ""),
		PairingToken: catToken,
		SessionToken: satToken,
	}
	s.credentials = creds

	log.WithField("deviceID", creds.DeviceID).Info("session: pairing successful")
	return creds, nil
}

// Authenticate establishes an encrypted session using stored credentials.
// This must be called after Connect(CryptoModeTokenSHA256) which sets up
// the client/server random values needed for the SAT handshake.
//
// Flow:
//  1. Deserialize the SAT (Server Authentication Token)
//  2. Add an authentication_challenge caveat bound to the session nonce
//  3. Send serialized SAT' as a data message (transport-level, not Privet RPC)
//  4. Receive 16-byte MAC response from the lock
//  5. Derive session keys from [0x02, clientRandom, serverRandom, sat.mac_tag]
//  6. All further messages are encrypted
//  7. Send /auth Privet RPC with the CAT (Client Authorization Token)
func (s *Session) Authenticate(creds *StoredCredentials) error {
	log.Debug("session: authenticating with stored credentials")

	if s.clientRandom == nil || s.serverRandom == nil {
		return fmt.Errorf("session: missing client/server random (Connect with CryptoModeTokenSHA256 first)")
	}

	// Step 1: Deserialize the SAT
	sat, err := DeserializeMacaroon(creds.SessionToken)
	if err != nil {
		return fmt.Errorf("session: failed to deserialize SAT: %w", err)
	}
	log.WithField("caveats", len(sat.Caveats)).Debug("session: SAT deserialized")

	// Step 2: Build session nonce and extend SAT with authentication_challenge caveat.
	// The context for signing is [0x01, clientRandom(12), serverRandom(12)] = 25 bytes.
	sessionNonce := make([]byte, 25)
	sessionNonce[0] = 0x01
	copy(sessionNonce[1:13], s.clientRandom)
	copy(sessionNonce[13:25], s.serverRandom)

	challengeCaveat := CreateAuthChallengeCaveat()
	satPrime, err := ExtendMacaroon(sat, challengeCaveat, sessionNonce)
	if err != nil {
		return fmt.Errorf("session: failed to extend SAT: %w", err)
	}

	// Step 3: Serialize SAT' and send as data message
	satPrimeBytes, err := SerializeMacaroon(satPrime)
	if err != nil {
		return fmt.Errorf("session: failed to serialize SAT': %w", err)
	}
	log.WithField("len", len(satPrimeBytes)).Debug("session: sending SAT' for channel encryption handshake")

	if err := s.sendMessage(satPrimeBytes); err != nil {
		return fmt.Errorf("session: failed to send SAT': %w", err)
	}

	// Step 4: Receive 16-byte MAC response from the lock
	serverResponse, err := s.receiveMessage()
	if err != nil {
		return fmt.Errorf("session: failed to receive SAT handshake response: %w", err)
	}
	log.WithField("len", len(serverResponse)).Debug("session: SAT handshake response received")

	if len(serverResponse) != macaroonMACLen {
		return fmt.Errorf("session: SAT response length %d, expected %d", len(serverResponse), macaroonMACLen)
	}

	// Step 5: Derive session keys.
	// Key material = [0x02, clientRandom(12), serverRandom(12), sat_mac_tag(16)] = 41 bytes.
	// The MAC tag is from the ORIGINAL SAT (before adding the challenge caveat).
	keyMaterial := make([]byte, 41)
	keyMaterial[0] = 0x02
	copy(keyMaterial[1:13], s.clientRandom)
	copy(keyMaterial[13:25], s.serverRandom)
	copy(keyMaterial[25:41], sat.MACTag)

	keys, err := DeriveSessionKeys(keyMaterial)
	if err != nil {
		return fmt.Errorf("session: key derivation failed: %w", err)
	}

	// Step 6: Create session cipher (we are the client)
	s.cipher = NewSessionCipher(keys, true)
	log.Info("session: encrypted channel established")

	// Step 7: Send /auth Privet RPC with the CAT token.
	// Use AuthModePairing (1) since we're authenticating with pairing credentials.
	authReq := AuthRequest(AuthModePairing, creds.PairingToken)
	authResp, err := s.sendRPC(authReq)
	if err != nil {
		return fmt.Errorf("session: /auth request failed: %w", err)
	}
	if authResp.Error != nil {
		return fmt.Errorf("session: /auth error: %w", authResp.Error)
	}
	log.Debug("session: /auth response received")

	s.credentials = creds
	log.Info("session: authenticated session established")
	return nil
}

// Lock sends a lock command using saveData on trait 1, property 0.
func (s *Session) Lock() error {
	return s.sendLockCommand(LockStateLocked, "lock")
}

// Unlock sends an unlock command using saveData on trait 1, property 0.
func (s *Session) Unlock() error {
	return s.sendLockCommand(LockStateUnlocked, "unlock")
}

func (s *Session) sendLockCommand(lockState int, name string) error {
	log.Debugf("session: sending %s command", name)

	req := SaveDataRequest(TraitLockData, PropLockStatus, lockState, s.getUserID())
	resp, err := s.sendRPC(req)
	if err != nil {
		return fmt.Errorf("session: %s command failed: %w", name, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("session: %s command error: %w", name, resp.Error)
	}

	log.WithField("result", fmt.Sprintf("%+v", resp.Result)).Debugf("session: %s command response", name)
	log.Infof("session: %s command successful", name)
	return nil
}

// Claim performs the access control claim + confirm flow.
// This is required after pairing to fully provision the lock.
func (s *Session) Claim() error {
	log.Debug("session: sending access control claim request")

	// Step 1: Send claim request {1:24, 2:4}
	claimReq := AccessControlClaimRequest(nil)
	claimResp, err := s.sendRPC(claimReq)
	if err != nil {
		return fmt.Errorf("session: access control claim failed: %w", err)
	}
	if claimResp.Error != nil {
		return fmt.Errorf("session: access control claim error: %w", claimResp.Error)
	}

	log.WithField("result", fmt.Sprintf("%+v", claimResp.Result)).Debug("session: claim response")

	// Step 2: Extract mCat from response.
	// ParsePrivetResponse already extracts the outer 0x11, so CAT is at result[0].
	catVal, ok := claimResp.Result[0]
	if !ok {
		return fmt.Errorf("session: claim response missing CAT bytes (key 0), got: %+v", claimResp.Result)
	}
	catBytes, ok := catVal.([]byte)
	if !ok {
		return fmt.Errorf("session: claim response CAT is not bytes: %T", catVal)
	}

	log.WithField("cat_len", len(catBytes)).Debug("session: extracted CAT from claim response")

	// Step 3: Send confirm request {1:25, 2:5, 16:{0: catBytes}}
	confirmReq := ConfirmAccessControlRequest(catBytes)
	confirmResp, err := s.sendRPC(confirmReq)
	if err != nil {
		return fmt.Errorf("session: access control confirm failed: %w", err)
	}
	if confirmResp.Error != nil {
		return fmt.Errorf("session: access control confirm error: %w", confirmResp.Error)
	}

	log.WithField("result", fmt.Sprintf("%+v", confirmResp.Result)).Debug("session: confirm response")
	log.Info("session: access control claim/confirm complete")
	return nil
}

// SetTimezone writes the timezone offset to the lock.
// offset is the timezone offset in minutes from UTC (e.g., -300 for EST).
func (s *Session) SetTimezone(offsetMinutes int) error {
	log.WithField("offset", offsetMinutes).Debug("session: setting timezone")

	req := WriteSettingRequest(PropTimeZone, offsetMinutes, s.getUserID())
	resp, err := s.sendRPC(req)
	if err != nil {
		return fmt.Errorf("session: set timezone failed: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("session: set timezone error: %w", resp.Error)
	}

	log.Info("session: timezone set successfully")
	return nil
}

// SetTime writes the current time to the lock as a Unix timestamp.
// Uses saveData on trait 1 (LockData), property 6 (SetTime — the write property).
func (s *Session) SetTime(unixSeconds int64) error {
	log.WithField("time", unixSeconds).Debug("session: setting lock time")

	req := SaveDataRequest(TraitLockData, PropSetTime, unixSeconds, s.getUserID())
	resp, err := s.sendRPC(req)
	if err != nil {
		return fmt.Errorf("session: set time failed: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("session: set time error: %w", resp.Error)
	}

	log.Info("session: lock time set successfully")
	return nil
}

// GetState queries the lock's current state.
// Returns: locked (bool), battery (int, percentage), jammed (bool), doorState (int)
func (s *Session) GetState() (locked bool, battery int, jammed bool, doorState int, err error) {
	log.Debug("session: querying lock state")

	req := StateRequest()
	resp, err := s.sendRPC(req)
	if err != nil {
		return false, 0, false, DoorStateUnknown, fmt.Errorf("session: state request failed: %w", err)
	}
	if resp.Error != nil {
		return false, 0, false, DoorStateUnknown, fmt.Errorf("session: state request error: %w", resp.Error)
	}

	// Lock state response structure:
	//   result[1][0][0][1] → innerMap
	//   innerMap keys: 0x00=LOCK_STATUS, 0x0C=BATTERY_STATE, 0x0E=ALARM_ENABLED, 0x15=BATTERY_LEVEL

	// Navigate: result[1][0][0][1] → trait state properties
	traitState := extractTraitState(resp.Result)
	if traitState == nil {
		log.Warn("session: could not find trait state in /state response")
		return false, 0, false, DoorStateUnknown, nil
	}

	log.WithField("traitState", fmt.Sprintf("%+v", traitState)).Debug("session: trait state map")

	if v, ok := traitState[PropLockStatus]; ok {
		state := cborInt(v)
		// JAMMED means bolt extended with difficulty — still locked.
		// DEADLOCKED means bolt fully extended — also locked.
		// MOTOR_JAMMED means motor stalled — bolt position uncertain.
		locked = state == LockStateLocked || state == LockStateJammed || state == LockStateDeadlocked
		jammed = state == LockStateJammed || state == LockStateMotorJammed
	}
	if v, ok := traitState[PropBatteryLevel]; ok {
		battery = cborInt(v)
	}
	doorState = DoorStateUnknown
	if v, ok := traitState[PropDoorState]; ok {
		doorState = cborInt(v)
	}

	log.WithFields(log.Fields{
		"locked":    locked,
		"battery":   battery,
		"jammed":    jammed,
		"doorState": doorState,
	}).Debug("session: lock state received")

	return locked, battery, jammed, doorState, nil
}

// ---------------------------------------------------------------------------
// Access code management
// ---------------------------------------------------------------------------

// GetAccessCodeLength reads the configured PIN length from the lock (4-8 digits).
// Returns 0 if the lock hasn't been configured with any codes yet.
func (s *Session) GetAccessCodeLength() (int, error) {
	log.Debug("session: reading access code length")

	req := ReadSettingRequest(PropAccessCodeLength)
	resp, err := s.sendRPC(req)
	if err != nil {
		return 0, fmt.Errorf("session: read access code length failed: %w", err)
	}
	if resp.Error != nil {
		return 0, fmt.Errorf("session: read access code length error: %w", resp.Error)
	}

	length := 0
	if v, ok := resp.Result[privetKeyResult]; ok {
		length = cborInt(v)
	}

	log.WithField("length", length).Debug("session: access code length")
	return length, nil
}

// AddAccessCode adds a new keypad access code to the lock.
// code: 4-8 digit PIN string, name: human label.
func (s *Session) AddAccessCode(code string, name string) error {
	log.WithFields(log.Fields{
		"name": name,
		"code": "****", // don't log the actual PIN
	}).Debug("session: adding access code")

	// Generate random 16-byte UUID for this code
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		return fmt.Errorf("session: failed to generate UUID: %w", err)
	}

	// Convert PIN string to integer (e.g. "1234" → 1234)
	codeNum, err := strconv.ParseInt(code, 10, 64)
	if err != nil {
		return fmt.Errorf("session: invalid PIN code %q: %w", code, err)
	}

	req := AddAccessCodeRequest(uuid, name, codeNum, false)
	resp, err := s.sendRPC(req)
	if err != nil {
		return fmt.Errorf("session: add access code failed: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("session: add access code error: %w", resp.Error)
	}

	log.WithField("result", fmt.Sprintf("%+v", resp.Result)).Debug("session: add access code response")
	log.WithField("name", name).Info("session: access code added successfully")
	return nil
}

// RemoveAccessCode removes a keypad access code by PIN.
func (s *Session) RemoveAccessCode(code string) error {
	log.Debug("session: removing access code")

	codeNum, err := strconv.ParseInt(code, 10, 64)
	if err != nil {
		return fmt.Errorf("session: invalid PIN code %q: %w", code, err)
	}

	req := RemoveAccessCodeRequest(codeNum)
	resp, err := s.sendRPC(req)
	if err != nil {
		return fmt.Errorf("session: remove access code failed: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("session: remove access code error: %w", resp.Error)
	}

	log.WithField("result", fmt.Sprintf("%+v", resp.Result)).Debug("session: remove access code response")
	log.Info("session: access code removed successfully")
	return nil
}

// DeleteAllAccessCodes removes all keypad access codes.
func (s *Session) DeleteAllAccessCodes() error {
	log.Debug("session: deleting all access codes")

	req := DeleteAllAccessCodesRequest()
	resp, err := s.sendRPC(req)
	if err != nil {
		return fmt.Errorf("session: delete all access codes failed: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("session: delete all access codes error: %w", resp.Error)
	}

	log.WithField("result", fmt.Sprintf("%+v", resp.Result)).Debug("session: delete all access codes response")
	log.Info("session: all access codes deleted")
	return nil
}

// FactoryReset performs a factory default reset (FDR) of the lock.
// This erases all pairing data, access codes, and settings.
// The BLE connection will be dropped by the lock after this command.
func (s *Session) FactoryReset() error {
	log.Debug("session: sending factory reset command")

	req := FactoryResetRequest()
	resp, err := s.sendRPC(req)
	if err != nil {
		return fmt.Errorf("session: factory reset failed: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("session: factory reset error: %w", resp.Error)
	}

	log.WithField("result", fmt.Sprintf("%+v", resp.Result)).Debug("session: factory reset response")
	log.Info("session: factory reset successful — lock will disconnect")
	return nil
}

// ListAccessCodes retrieves all configured access codes from the lock.
// Uses a check+read-loop pattern:
//  1. Check: {1:8, 2:3, 16:{0:4, 1:6, 2:{0:0}}} → nonzero if codes exist
//  2. Read one: {1:8, 2:4, 16:{0:4, 1:5}} → get one code + moreAvailable
//  3. Repeat until moreAvailable (key 0x0A in code data) == 0
func (s *Session) ListAccessCodes() ([]AccessCode, error) {
	log.Debug("session: listing access codes")

	// Step 1: Check/count
	checkReq := ListAccessCodesCheckRequest()
	checkResp, err := s.sendRPC(checkReq)
	if err != nil {
		return nil, fmt.Errorf("session: list access codes check failed: %w", err)
	}
	if checkResp.Error != nil {
		return nil, fmt.Errorf("session: list access codes check error: %w", checkResp.Error)
	}
	log.WithField("result", fmt.Sprintf("%+v", checkResp.Result)).Debug("session: access codes check response")

	// Check response: resp.Result[17] is nonzero if codes exist.
	// Note: this value is NOT the actual count of codes — it appears to be
	// a boolean or page indicator. The real count comes from reading codes
	// one at a time and checking the moreAvailable field (key 0x0A).
	available := 0
	if v, ok := checkResp.Result[privetKeyResult]; ok {
		available = cborInt(v)
	}
	if available == 0 {
		log.Info("session: no access codes configured")
		return nil, nil
	}
	log.WithField("available", available).Debug("session: access codes available")

	// Step 2: Read codes one at a time, stopping when moreAvailable == 0.
	// Safety cap at 250 — the highest limit across all Schlage models:
	//   Encode WKD/Walton: 250, Encode other: 100, Sense (e.g. BE459): 30.
	// The loop always terminates early on moreAvailable == 0.
	const maxCodes = 250
	var codes []AccessCode
	for i := 0; i < maxCodes; i++ {
		readReq := ListAccessCodesReadRequest()
		readResp, err := s.sendRPC(readReq)
		if err != nil {
			return codes, fmt.Errorf("session: list access codes read failed: %w", err)
		}
		if readResp.Error != nil {
			return codes, fmt.Errorf("session: list access codes read error: %w", readResp.Error)
		}
		log.WithField("result", fmt.Sprintf("%+v", readResp.Result)).Debug("session: access code read response")

		// Code data is at resp.Result[17] (privetKeyResult) as a flat map
		codeDataVal, ok := readResp.Result[privetKeyResult]
		if !ok {
			log.Debug("session: no code data in read response")
			break
		}
		codeData, ok := codeDataVal.(map[int]interface{})
		if !ok {
			log.WithField("type", fmt.Sprintf("%T", codeDataVal)).Debug("session: code data is not a map")
			break
		}

		ac := parseAccessCodeData(codeData)
		codes = append(codes, ac)

		// Check key 0x0A (10) for more available
		moreAvailable := 0
		if v, ok := codeData[AccessCodeKeyMoreAvailable]; ok {
			moreAvailable = cborInt(v)
		}
		if moreAvailable <= 0 {
			break
		}
	}

	log.WithField("count", len(codes)).Info("session: access codes retrieved")
	return codes, nil
}

// parseAccessCodeData extracts an AccessCode from a code data map.
func parseAccessCodeData(m map[int]interface{}) AccessCode {
	ac := AccessCode{}
	if v, ok := m[AccessCodeKeyUUID]; ok {
		if b, ok := v.([]byte); ok {
			ac.UUID = b
		}
	}
	if v, ok := m[AccessCodeKeyName]; ok {
		if str, ok := v.(string); ok {
			ac.Name = str
		}
	}
	if v, ok := m[AccessCodeKeyCode]; ok {
		ac.Code = int64(cborInt(v))
	}
	if v, ok := m[AccessCodeKeyBlocked]; ok {
		ac.Blocked = cborInt(v) != 0
	}
	return ac
}

// ---------------------------------------------------------------------------
// Lock settings management
// ---------------------------------------------------------------------------

// SetAutoLockTime configures the auto-lock delay in seconds.
// Use 0 to disable auto-lock. Valid values: 0, 15, 30, 60, 120, 240, 360, 600.
func (s *Session) SetAutoLockTime(seconds int) error {
	log.WithField("seconds", seconds).Debug("session: setting auto-lock time")
	return s.writeSetting(SettingWriteAutoLockTime, seconds, "auto-lock time")
}

// SetBeeperEnabled enables or disables the keypress beep.
func (s *Session) SetBeeperEnabled(enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	log.WithField("enabled", enabled).Debug("session: setting beeper")
	return s.writeSetting(SettingWriteBeeperEnabled, val, "beeper")
}

// SetLockAndLeave enables or disables one-touch (lock-and-leave) locking.
func (s *Session) SetLockAndLeave(enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	log.WithField("enabled", enabled).Debug("session: setting lock-and-leave")
	return s.writeSetting(SettingWriteLockAndLeave, val, "lock-and-leave")
}

// SetAlarmMode configures the alarm mode.
func (s *Session) SetAlarmMode(mode int) error {
	log.WithField("mode", mode).Debug("session: setting alarm mode")
	return s.writeSetting(SettingWriteAlarmMode, mode, "alarm mode")
}

// SetAlarmSensitivity configures the alarm sensitivity level.
func (s *Session) SetAlarmSensitivity(sensitivity int) error {
	log.WithField("sensitivity", sensitivity).Debug("session: setting alarm sensitivity")
	return s.writeSetting(SettingWriteAlarmSensitivity, sensitivity, "alarm sensitivity")
}

// SetAccessCodeLength sets the PIN length for keypad access codes (4-8 digits).
// This should be called during commissioning before the first access code is added.
func (s *Session) SetAccessCodeLength(length int) error {
	log.WithField("length", length).Debug("session: setting access code length")

	req := SetAccessCodeLengthRequest(length)
	resp, err := s.sendRPC(req)
	if err != nil {
		return fmt.Errorf("session: set access code length failed: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("session: set access code length error: %w", resp.Error)
	}

	log.Info("session: access code length set successfully")
	return nil
}

// GetTimezone reads the lock's timezone offset in minutes from UTC.
func (s *Session) GetTimezone() (int, error) {
	log.Debug("session: reading timezone")

	req := ReadSettingRequest(PropTimezoneRead)
	resp, err := s.sendRPC(req)
	if err != nil {
		return 0, fmt.Errorf("session: read timezone failed: %w", err)
	}
	if resp.Error != nil {
		return 0, fmt.Errorf("session: read timezone error: %w", resp.Error)
	}

	offset := 0
	if v, ok := resp.Result[privetKeyResult]; ok {
		offset = cborInt(v)
	}

	log.WithField("offset", offset).Debug("session: timezone offset")
	return offset, nil
}

// SetDSTTimes sets daylight saving time transition timestamps.
// dstStart and dstEnd are opaque byte arrays representing the transition times.
func (s *Session) SetDSTTimes(dstStart, dstEnd []byte) error {
	log.Debug("session: setting DST times")

	req := SetDSTTimesRequest(dstStart, dstEnd)
	resp, err := s.sendRPC(req)
	if err != nil {
		return fmt.Errorf("session: set DST times failed: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("session: set DST times error: %w", resp.Error)
	}

	log.Info("session: DST times set successfully")
	return nil
}

// GetDSTTimes reads the daylight saving time configuration from the lock.
func (s *Session) GetDSTTimes() (*DSTTimes, error) {
	log.Debug("session: reading DST times")

	req := ReadSettingRequest(PropDSTTimesRead)
	resp, err := s.sendRPC(req)
	if err != nil {
		return nil, fmt.Errorf("session: read DST times failed: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("session: read DST times error: %w", resp.Error)
	}

	dst := &DSTTimes{}
	if v, ok := resp.Result[privetKeyResult]; ok {
		if m, ok := v.(map[int]interface{}); ok {
			if val, ok := m[0]; ok {
				dst.Enabled = cborInt(val)
			}
			if val, ok := m[1].([]byte); ok {
				dst.Start = val
			}
			if val, ok := m[2].([]byte); ok {
				dst.End = val
			}
		}
	}

	log.WithFields(log.Fields{
		"enabled": dst.Enabled,
		"start":   fmt.Sprintf("%x", dst.Start),
		"end":     fmt.Sprintf("%x", dst.End),
	}).Debug("session: DST times")
	return dst, nil
}

// SetSimultaneousMode enables or disables simultaneous mode (Matter protocol
// alongside Schlage BLE). Only available on newer "Walton" hardware.
func (s *Session) SetSimultaneousMode(enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	log.WithField("enabled", enabled).Debug("session: setting simultaneous mode")
	return s.writeSetting(PropSimultaneousMode, val, "simultaneous mode")
}

// GetOperatingMode reads the lock's operating mode.
// Returns 0 for Schlage (BLE only) or 1 for Simultaneous (BLE + Matter).
func (s *Session) GetOperatingMode() (int, error) {
	log.Debug("session: reading operating mode")

	req := ReadSettingRequest(PropOpMode)
	resp, err := s.sendRPC(req)
	if err != nil {
		return 0, fmt.Errorf("session: read operating mode failed: %w", err)
	}
	if resp.Error != nil {
		return 0, fmt.Errorf("session: read operating mode error: %w", resp.Error)
	}

	mode := 0
	if v, ok := resp.Result[privetKeyResult]; ok {
		mode = cborInt(v)
	}

	log.WithField("mode", mode).Debug("session: operating mode")
	return mode, nil
}

// GetMaxUserCodes reads the maximum number of access codes the lock supports.
func (s *Session) GetMaxUserCodes() (int, error) {
	log.Debug("session: reading max user codes")

	req := GetMaxUserCodesRequest(s.getUserID())
	resp, err := s.sendRPC(req)
	if err != nil {
		return 0, fmt.Errorf("session: read max user codes failed: %w", err)
	}
	if resp.Error != nil {
		return 0, fmt.Errorf("session: read max user codes error: %w", resp.Error)
	}

	maxCodes := 0
	if v, ok := resp.Result[privetKeyResult]; ok {
		maxCodes = cborInt(v)
	}

	log.WithField("maxCodes", maxCodes).Debug("session: max user codes")
	return maxCodes, nil
}

// ProbeProperty sends a raw requestData for the given trait and property,
// returning the full PrivetResponse for inspection.
func (s *Session) ProbeProperty(trait, property int) (*PrivetResponse, error) {
	req := RequestDataRequest(trait, property)
	return s.sendRPC(req)
}

// GetSettings reads all configurable lock settings.
func (s *Session) GetSettings() (*LockSettings, error) {
	log.Debug("session: reading lock settings")

	settings := &LockSettings{}

	// Read each setting individually
	type settingRead struct {
		key  int
		name string
	}
	reads := []settingRead{
		{SettingReadBeeperEnabled, "beeper_enabled"},
		{SettingReadAutoLockTime, "auto_lock_time"},
		{SettingReadAlarmMode, "alarm_mode"},
		{SettingReadAlarmSensitivity, "alarm_sensitivity"},
		{SettingReadLockAndLeave, "lock_and_leave"},
		{PropTimezoneRead, "timezone"},
		{PropOpMode, "operating_mode"},
	}

	for _, r := range reads {
		req := ReadSettingRequest(r.key)
		resp, err := s.sendRPC(req)
		if err != nil {
			log.WithFields(log.Fields{
				"setting": r.name,
				"error":   err,
			}).Warn("session: failed to read setting, skipping")
			continue
		}
		if resp.Error != nil {
			log.WithFields(log.Fields{
				"setting": r.name,
				"error":   resp.Error,
			}).Warn("session: setting read returned error, skipping")
			continue
		}

		log.WithFields(log.Fields{
			"setting": r.name,
			"result":  fmt.Sprintf("%+v", resp.Result),
		}).Debug("session: setting read response")

		// Extract value from result. The response structure is:
		// {4: errorCode, 17: actualValue} (nested privetKeyResult).
		val, ok := resp.Result[privetKeyResult]
		if !ok {
			log.WithField("setting", r.name).Warn("session: no value in setting response")
			continue
		}

		switch r.key {
		case SettingReadAutoLockTime:
			settings.AutoLockTime = cborInt(val)
		case SettingReadBeeperEnabled:
			settings.BeeperEnabled = cborInt(val) != 0
		case SettingReadLockAndLeave:
			settings.LockAndLeave = cborInt(val) != 0
		case SettingReadAlarmMode:
			settings.AlarmMode = cborInt(val)
		case SettingReadAlarmSensitivity:
			settings.AlarmSensitivity = cborInt(val)
		case PropTimezoneRead:
			settings.TimezoneOffset = cborInt(val)
		case PropOpMode:
			settings.OperatingMode = cborInt(val)
		}
	}

	log.WithFields(log.Fields{
		"autoLock":         settings.AutoLockTime,
		"beeper":           settings.BeeperEnabled,
		"lockAndLeave":     settings.LockAndLeave,
		"alarmMode":        settings.AlarmMode,
		"alarmSensitivity": settings.AlarmSensitivity,
		"timezone":         settings.TimezoneOffset,
		"operatingMode":    settings.OperatingMode,
	}).Info("session: lock settings retrieved")

	// Code length (best-effort, separate read pattern)
	if codeLen, err := s.GetAccessCodeLength(); err == nil {
		settings.CodeLength = codeLen
	}

	// DST times (best-effort)
	if dst, err := s.GetDSTTimes(); err == nil {
		settings.DST = dst
	}

	return settings, nil
}

// writeSetting is a helper that sends a single setting write command.
func (s *Session) writeSetting(propertyKey int, value interface{}, name string) error {
	req := WriteSettingRequest(propertyKey, value, s.getUserID())
	resp, err := s.sendRPC(req)
	if err != nil {
		return fmt.Errorf("session: write %s failed: %w", name, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("session: write %s error: %w", name, resp.Error)
	}

	log.WithField("result", fmt.Sprintf("%+v", resp.Result)).Debugf("session: write %s response", name)
	log.Infof("session: %s updated successfully", name)
	return nil
}

// ---------------------------------------------------------------------------
// Device info
// ---------------------------------------------------------------------------

// GetDeviceInfo reads all device information properties.
func (s *Session) GetDeviceInfo() (*DeviceInfo, error) {
	log.Debug("session: reading device info")

	info := &DeviceInfo{}

	type infoRead struct {
		key  int
		name string
	}
	reads := []infoRead{
		{DeviceInfoKeyModelNumber, "model_number"},
		{DeviceInfoKeySerialNumber, "serial_number"},
		{DeviceInfoKeyFirmwareVer, "firmware_version"},
		{DeviceInfoKeyCurrentTime, "current_time"},
		{DeviceInfoKeyKeypadFirmware, "keypad_firmware"},
		{DeviceInfoKeyManufacturer, "manufacturer"},
		{DeviceInfoKeyLockName, "lock_name"},
		{DeviceInfoKeyBatteryLevel, "battery_level"},
	}

	for _, r := range reads {
		req := ReadDeviceInfoRequest(r.key)
		resp, err := s.sendRPC(req)
		if err != nil {
			log.WithFields(log.Fields{
				"property": r.name,
				"error":    err,
			}).Warn("session: failed to read device info property, skipping")
			continue
		}
		if resp.Error != nil {
			log.WithFields(log.Fields{
				"property": r.name,
				"error":    resp.Error,
			}).Warn("session: device info read returned error, skipping")
			continue
		}

		log.WithFields(log.Fields{
			"property": r.name,
			"result":   fmt.Sprintf("%+v", resp.Result),
		}).Debug("session: device info read response")

		// Extract value from result. The response structure is:
		// {4: errorCode, 17: actualValue} (nested privetKeyResult).
		val, ok := resp.Result[privetKeyResult]
		if !ok {
			log.WithField("property", r.name).Warn("session: no value in device info response")
			continue
		}

		switch r.key {
		case DeviceInfoKeyModelNumber:
			if str, ok := val.(string); ok {
				info.ModelNumber = str
			}
		case DeviceInfoKeySerialNumber:
			if str, ok := val.(string); ok {
				info.SerialNumber = str
			}
		case DeviceInfoKeyFirmwareVer:
			if str, ok := val.(string); ok {
				info.MainFirmware = str
			}
		case DeviceInfoKeyBatteryLevel:
			info.BatteryLevel = cborInt(val)
		case DeviceInfoKeyCurrentTime:
			info.LockTime = cborInt(val)
		case DeviceInfoKeyKeypadFirmware:
			if str, ok := val.(string); ok {
				info.KeypadFirmware = str
			}
		case DeviceInfoKeyManufacturer:
			if str, ok := val.(string); ok {
				info.Manufacturer = str
			}
		case DeviceInfoKeyLockName:
			if str, ok := val.(string); ok {
				info.LockName = str
			}
		}
	}

	log.WithFields(log.Fields{
		"model":    info.ModelNumber,
		"serial":   info.SerialNumber,
		"battery":  info.BatteryLevel,
		"firmware": info.MainFirmware,
	}).Info("session: device info retrieved")

	return info, nil
}

// ---------------------------------------------------------------------------
// Lock history / event log
// ---------------------------------------------------------------------------

// GetHistory retrieves lock event history using the check+batched-read pattern.
//  1. Check: {1:8, 2:2, 16:{0:3, 1:0, 2:{0:0}}} → get count at Result[17]
//  2. Read batch: {1:8, 2:3, 16:{0:3, 1:batchSize}} → entries at Result[17]
//     - If batch: individual entries at keys 0x0A–0x0E
//     - If single: entry data is flat in the map
//     - Key 4 in data = more available (>0 means repeat read)
//  3. Repeat until moreAvailable==0 or maxEntries reached
func (s *Session) GetHistory(maxEntries int) ([]HistoryEvent, error) {
	log.Debug("session: retrieving lock history")

	// Step 1: Check — get count of history entries
	checkReq := HistoryCheckRequest()
	checkResp, err := s.sendRPC(checkReq)
	if err != nil {
		return nil, fmt.Errorf("session: history check failed: %w", err)
	}
	if checkResp.Error != nil {
		return nil, fmt.Errorf("session: history check error: %w", checkResp.Error)
	}

	log.WithField("result", fmt.Sprintf("%+v", checkResp.Result)).Debug("session: history check response")

	// Check response: Result[17] > 0 means logs exist (boolean gate, not total count).
	available := 0
	if v, ok := checkResp.Result[privetKeyResult]; ok {
		available = cborInt(v)
	}
	if available == 0 {
		log.Info("session: no history entries")
		return nil, nil
	}

	log.Debug("session: history entries available, starting read loop")

	// Step 2: Read entries in batches until moreAvailable==0 or maxEntries reached
	if maxEntries <= 0 {
		maxEntries = 200 // safety cap
	}
	var events []HistoryEvent
	for len(events) < maxEntries {
		// readLogsInGroupOf: BE459 uses 1 (SenseBleDeviceService),
		// other models (Denali etc.) may support up to HistoryBatchSize (5).
		readReq := HistoryReadRequest(1)
		readResp, err := s.sendRPC(readReq)
		if err != nil {
			return events, fmt.Errorf("session: history read failed: %w", err)
		}
		if readResp.Error != nil {
			return events, fmt.Errorf("session: history read error: %w", readResp.Error)
		}

		log.WithField("result", fmt.Sprintf("%+v", readResp.Result)).Debug("session: history read response")

		// Data is at resp.Result[17] (privetKeyResult) as a map
		dataVal, ok := readResp.Result[privetKeyResult]
		if !ok {
			log.Debug("session: no data in history read response")
			break
		}
		dataMap, ok := dataVal.(map[int]interface{})
		if !ok {
			log.WithField("type", fmt.Sprintf("%T", dataVal)).Debug("session: history data is not a map")
			break
		}

		// Extract entries — batch mode (keys 0x0A–0x0E) or single flat entry
		batch := extractHistoryBatch(dataMap)
		events = append(events, batch...)

		// Check key 4 for more available
		moreAvailable := 0
		if v, ok := dataMap[HistoryEntryKeyMoreAvailable]; ok {
			moreAvailable = cborInt(v)
		}
		if moreAvailable <= 0 {
			break
		}
	}

	log.WithField("totalEvents", len(events)).Info("session: lock history retrieved")
	return events, nil
}

// extractHistoryBatch extracts HistoryEvents from a history read response data map.
// If the map contains batch index keys (0x0A–0x0E),
// each value is a nested entry map (used when readLogsInGroupOf > 1).
// Otherwise the map itself is a single entry (readLogsInGroupOf == 1).
func extractHistoryBatch(dataMap map[int]interface{}) []HistoryEvent {
	// Check for batch mode: presence of LOG_0_INDEX_KEY (0x0A)
	if _, isBatch := dataMap[HistoryBatchLog0]; isBatch {
		var events []HistoryEvent
		for _, key := range []int{HistoryBatchLog0, HistoryBatchLog1, HistoryBatchLog2, HistoryBatchLog3, HistoryBatchLog4} {
			v, ok := dataMap[key]
			if !ok {
				continue
			}
			entryMap, ok := v.(map[int]interface{})
			if !ok {
				continue
			}
			events = append(events, parseHistoryEntry(entryMap))
		}
		return events
	}

	// Single entry mode — the map itself is the entry
	return []HistoryEvent{parseHistoryEntry(dataMap)}
}

// parseHistoryEntry extracts a HistoryEvent from a single history entry map.
//
//	0: [uuid]       — actor UUID (LOG_ACCESSOR_KEY)
//	1: timestamp    — unix timestamp (LOG_TIME_KEY)
//	2: int          — action enum (LOG_ACTION_KEY)
//	3: map          — event details (LOG_EVENTS_KEY): {0: event_type, 1: [device_uuid]}
func parseHistoryEntry(m map[int]interface{}) HistoryEvent {
	ev := HistoryEvent{
		UserIndex: -1,
	}

	if v, ok := m[HistoryEntryKeyTimestamp]; ok {
		ev.Timestamp = cborInt(v)
	}

	// Event type is nested inside the events detail map at key 3
	if details, ok := m[HistoryEntryKeyEvents]; ok {
		if dm, ok := details.(map[int]interface{}); ok {
			if v, ok := dm[HistoryEventKeyType]; ok {
				ev.Type = cborInt(v)
			}
		}
	}

	return ev
}

// getUserID returns the 16-byte user ID for saveData commands.
// This is a static value — the lock uses it only for history attribution.
func (s *Session) getUserID() []byte {
	return staticUserID
}

// extractTraitState navigates the Weave /state response structure to find
// the lock trait state properties map.
// Path: result[1][0][0][1] → map of trait property keys to values.
func extractTraitState(result map[int]interface{}) map[int]interface{} {
	// result[1] = components
	components, ok := result[1].(map[int]interface{})
	if !ok {
		return nil
	}
	// components[0] = first component
	comp0, ok := components[0].(map[int]interface{})
	if !ok {
		return nil
	}
	// comp0[0] = traits
	traits, ok := comp0[0].(map[int]interface{})
	if !ok {
		return nil
	}
	// traits[1] = lock trait state
	traitState, ok := traits[1].(map[int]interface{})
	if !ok {
		return nil
	}
	return traitState
}

// sendMessage sends a complete message (handles fragmentation and optional encryption).
func (s *Session) sendMessage(data []byte) error {
	payload := data

	// Encrypt if we have an active cipher
	if s.cipher != nil {
		encrypted, err := s.cipher.Encrypt(data)
		if err != nil {
			return fmt.Errorf("session: encryption failed: %w", err)
		}
		payload = encrypted
		log.WithField("len", len(encrypted)).Debug("session: encrypted message")
	}

	// Fragment the message into BLE-sized packets
	packets := s.fragmenter.Fragment(payload)
	log.WithField("packets", len(packets)).Debug("session: fragmented message")

	// Write each packet via the transport
	for i, pkt := range packets {
		log.WithFields(log.Fields{
			"pkt":  fmt.Sprintf("%d/%d", i+1, len(packets)),
			"hex":  hex.EncodeToString(pkt),
			"len":  len(pkt),
		}).Debug("session: writing packet")
		if err := s.transport.Write(pkt); err != nil {
			return fmt.Errorf("session: failed to write packet %d/%d: %w", i+1, len(packets), err)
		}
	}

	return nil
}

// receiveMessage waits for a complete message from the lock.
func (s *Session) receiveMessage() ([]byte, error) {
	data, err := s.transport.Receive()
	if err != nil {
		return nil, fmt.Errorf("session: receive failed: %w", err)
	}

	// Decrypt if we have an active cipher
	if s.cipher != nil {
		plaintext, err := s.cipher.Decrypt(data)
		if err != nil {
			return nil, fmt.Errorf("session: decryption failed: %w", err)
		}
		log.WithField("len", len(plaintext)).Debug("session: decrypted message")
		return plaintext, nil
	}

	return data, nil
}

// sendRPC sends a Privet RPC request and waits for the response.
func (s *Session) sendRPC(requestBytes []byte) (*PrivetResponse, error) {
	err := s.sendMessage(requestBytes)
	if err != nil {
		return nil, err
	}

	responseBytes, err := s.receiveMessage()
	if err != nil {
		return nil, err
	}

	resp, err := ParsePrivetResponse(responseBytes)
	if err != nil {
		return nil, fmt.Errorf("session: failed to parse response: %w", err)
	}

	log.WithField("requestID", resp.RequestID).Debug("session: RPC response received")
	return resp, nil
}
