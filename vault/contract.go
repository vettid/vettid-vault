package vault

// ServiceContract is the major.minor of VAULT-SERVICE-CONTRACT this image
// implements (VAULT-MESSAGING 0.90.10, §10.8 `contract`): a constant of the
// image, measured with it, never read from the channel file. It is sent in
// every profile.update to a service connection and never to a person
// connection. Informational only: nothing selects behavior or relaxes a
// check by it (VAULT-SERVICE-CONTRACT §1, §5.2).
const ServiceContract = "1.0"
