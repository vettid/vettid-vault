package vectors

// Seeds and other fixed inputs. Values given by VAULT-MESSAGING §16 are
// marked (spec); the rest are chosen here and recorded in the JSON.
const (
	SeedVaultIK    byte = 0x04 // (spec)
	SeedVaultKEM   byte = 0x05 // (spec)
	SeedETK        byte = 0x06
	RandSealed     byte = 0x07 // (spec) §4.3 encapsulation randomness
	KeySession     byte = 0x08 // (spec) k_i2r
	NonceSession   byte = 0x09 // (spec)
	SeedInitIK     byte = 0x0a // (spec)
	SeedInitKEM    byte = 0x0b // (spec)
	SeedInitEph    byte = 0x0c // (spec)
	RandInit       byte = 0x0d // (spec)
	RandResp       byte = 0x0e // (spec)
	NonceFin       byte = 0x0f
	SeedVaultRelay byte = 0x10
	SeedInitRelay  byte = 0x11
	RandUnlock     byte = 0x13
	KeyBundle      byte = 0x14
	NonceBundle    byte = 0x15
	NonceSASI      byte = 0x16 // (spec 0.10.3) n_I
	NonceSASR      byte = 0x17 // (spec 0.10.3) n_R

	SeedManifestKey byte = 0x21 // (spec) §11.10.1 manifest key, P-256 scalar
	SeedDeviceKey   byte = 0x22 // (spec) §11.10.3 Android device attestation key

	// §11.11.2 recovery code seal (recovery.json).
	SeedBrowserKey   byte = 0x23 // the portal's P-256 key, private scalar
	SeedRecEph       byte = 0x24 // the code's ephemeral scalar
	NonceRec         byte = 0x25
	SeedRecEphNoCred byte = 0x26 // the no_credential refusal's ephemeral scalar
	NonceRecNoCred   byte = 0x27
	RecCodeBytes     byte = 0x28 // the code's 20 bytes

	SessionSenderKid    byte = 0x02
	SessionRecipientKid byte = 0x01

	RelayURL = "https://relay.vettid.org"

	HSInviteID = "01JB2Z6V9K3M4N5P6Q7R8S9T0V"
	HSInitID   = "01JB2Z6V9K3M4N5P6Q7R8S9T10"
	HSRespID   = "01JB2Z6V9K3M4N5P6Q7R8S9T11"
	HSFinID    = "01JB2Z6V9K3M4N5P6Q7R8S9T12"
	// The connection handshake's tokens are request tokens since 0.10.3
	// (dummy strings; the values are those of the earlier standing
	// tokens), and it carries no reconnect tokens.
	HSTokenInit = "v4.public.VEVTVC1PTkxZLWluaXQtc3RhbmRpbmc"
	HSTokenResp = "v4.public.VEVTVC1PTkxZLXJlc3Atc3RhbmRpbmc"

	InviteOpenToken = "v4.public.VEVTVC1PTkxZLW9wZW4"
	InviteClaimID   = "testclaimidaaaaaaaaaaaaaaa"

	ACInstanceID      = "i-test-0001"
	ACRelease         = "abababababababababababababababababababababababababababababababababababababababababababababababab"
	ACNotAfter        = "2026-10-02T12:00:00Z"
	ACEnrollRequestID = "01JB2Z6V9K3M4N5P6Q7R8S9T20"
	ACUnlockRequestID = "01JB2Z6V9K3M4N5P6Q7R8S9T21"
	ACVaultID         = "test-vault-0001"
	ACUserGUID        = "test-user-0001"
	ACPIN             = "123456"
	ACToken           = "v4.public.VEVTVC1PTkxZLWFwcA"
	// ACApprovalRequestID is the unlock that carries a release approval
	// (spec §16).
	ACApprovalRequestID = "01JB2Z6V9K3M4N5P6Q7R8S9T22"
	// RecRecoveryID is the recovery's id (the queue message's request_id,
	// §11.11.1) for ACVaultID.
	RecRecoveryID = "01JB2Z6V9K3M4N5P6Q7R8S9T30"
)
