// Package enclave is the enclave side of the alternate channel
// (VAULT-MESSAGING §11): the enclave transport key (ETK) and its attested
// descriptors (§11.2), request decryption, binding and replay protection
// (§11.6), enrollment (§11.3), unlock (§11.4) with device attestation
// (§11.7), backoff (§11.8) and failure handling (§11.9), release updates
// (§11.10) and sealing per release with the sealing-key policy check
// (§11.10.7).
//
// Hardware and AWS are behind interfaces: NSM (the Nitro Security Module)
// and KMS (AWS KMS with Recipient attestation). Phase V3a runs them
// in-process with the TEST-ONLY fakes in internal/enclavetest; the vsock
// parent, the enclave's own TLS and SigV4 KMS client, and the status-list
// fetch are phase V3b.
//
// Nothing here logs. Errors are sentinels; secrets never reach errors,
// lifecycle events or responses outside sealed envelopes.
package enclave
