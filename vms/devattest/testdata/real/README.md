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
