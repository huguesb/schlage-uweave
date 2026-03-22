package schlage_uweave

// Transport abstracts the BLE GATT transport layer for the uWeave protocol.
// Implementations handle writing to the lock's RX characteristic and receiving
// assembled messages from the lock's TX characteristic (indications).
//
// This interface decouples the protocol implementation from any specific BLE
// library, making it possible to use the protocol code as a standalone library.
type Transport interface {
	// Write sends raw bytes to the lock's RX characteristic.
	Write(data []byte) error

	// Receive waits for the next complete assembled message from the lock.
	// Implementations should block until a message is available, the connection
	// is lost, or the context is cancelled. Returns an error on timeout or
	// disconnect.
	Receive() ([]byte, error)

	// Addr returns the device address (e.g., MAC address) as a string.
	Addr() string

	// ExchangeMTU negotiates a larger ATT MTU with the device.
	// Returns the negotiated MTU value.
	ExchangeMTU(mtu int) (int, error)
}
