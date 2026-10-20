package enclave

// ReleaseConfigFor exposes releaseConfigFor to the external tests.
var ReleaseConfigFor = releaseConfigFor

// HostOf exposes an instance's host to the external tests.
func HostOf(in *Instance) Host { return in.host }
