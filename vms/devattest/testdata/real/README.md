# Real key attestation chains

`TestRealAndroidChains` (`vms/devattest/real_test.go`) runs the chain rules
of `checkAndroidChain` against every `*.pem` file in this directory, with
the Google roots the release pins (`pins.GoogleAttestationRoots`). With no
file here the test is skipped. The other tests use a test PKI that is made
to satisfy the rules; these files are what shows that real hardware does.
Run it with the chains of the test phones before a release:

    go test -p 2 -count=1 -run TestRealAndroidChains -v ./vms/devattest/

## Format

One file per chain, named `<device>-<what>.pem` (for example
`pixel10pro-grapheneos-strongbox.pem`):

- only PEM blocks of type `CERTIFICATE`, without headers, and nothing after
  the last one;
- in the order `KeyStore.getCertificateChain(alias)` returns them: the
  leaf first (the certificate of the attested key, with the attestation
  extension 1.3.6.1.4.1.11129.2.1.17), then the device's attestation
  certificate, the intermediates, and the Google root last;
- 2 to 10 certificates; the root must be one the release pins.

These are the same certificates, in the same order, as the base64 DER
entries of `device_attest.chain` (VAULT-MESSAGING §11.7): each entry is
one certificate, so `base64 -d | openssl x509 -inform DER` on each entry,
concatenated, gives the file.

What is checked: the signatures up to the pinned root, the attestation
extension on the leaf only, CA certificates above the attestation
certificate, path lengths, and that the key description parses. Validity
periods, the challenge, the package, the signer and the boot state are
not: they depend on the day, the app and the device.

## Do not commit a member's chain

A chain is a stable identifier of a device (the attestation certificate's
serial number, and for a remotely provisioned key a certificate of that
one device). `*.pem` is ignored here (`.gitignore`); a chain of a test
phone can be added with `git add -f` if it is to be kept.

# Real App Attest objects (iOS)

`TestRealIOSAttestations` (`vms/devattest/real_ios_test.go`) runs
`verifyIOS` and `verifyIOSAssertion` against every `*.ios.json` file in
this directory, with the Apple App Attestation root the release pins
(`pins.AppleAppAttestRoot`) and the production environment only. With no
file here the test is skipped:

    go test -p 1 -count=1 -run TestRealIOSAttestations -v ./vms/devattest/

## Format

One file per App Attest key, named `<device>-<build>.ios.json` (for
example `iphone15-devstack.ios.json`), one JSON object with exactly these
members (binary values in standard base64 with padding):

    {
      "app_id": "3X25CJ86MV.com.vettid.app.devstack",
      "attested_at": "2026-10-20T14:03:11Z",
      "key_id": "<the keyId generateKey returned: 32 bytes>",
      "attestation": "<the attestation object attestKey returned>",
      "challenge": "<the clientDataHash given to attestKey: 32 bytes>",
      "assertions": [
        {"client_data_hash": "<32 bytes>", "assertion": "<generateAssertion's result>"}
      ]
    }

- `app_id` is `<team id>.<bundle id>` of the build that made the key: one
  of `3X25CJ86MV.com.vettid.app`, `.staging`, `.dev` or `.devstack`. The
  build must use the production App Attest environment (the vault refuses
  the development one).
- `attested_at` is when `attestKey` ran (RFC 3339): the credential
  certificate is short-lived, so the chain is checked at that time.
- `assertions` are one or more, in the order they were generated (each
  counter must exceed the one before), with the key of `key_id`.

These are the same bytes as `device_attest.key_id`, `device_attest.attestation`
and `device_assertion.assertion` (VAULT-MESSAGING §11.7). Export them only
from a DevStack build on a test iPhone, never from a Release or Staging
build.

What is checked: the chain to the pinned Apple root at `attested_at`, the
nonce, the key id, the App ID, the counter 0 and the production aaguid of
the attestation, and each assertion's signature, App ID and increasing
counter; and that the same attestation is refused under another App ID.

## Do not commit a member's attestation

An App Attest key id and its attestation are stable identifiers of an
installation on a device. `*.ios.json` is ignored here (`.gitignore`); a
test iPhone's file can be added with `git add -f` if it is to be kept.
