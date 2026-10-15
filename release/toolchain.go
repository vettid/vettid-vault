// Package release embeds release/enclave-kernel, so that the enclave
// binary knows which enclave kernel the EIF toolchain pins and its
// self-test can require it (docs/KERNEL.md). Like the release constants,
// the values come from a committed file, not from build flags; the file
// holds nothing else, so other toolchain changes leave the binary alone.
package release

import (
	_ "embed"
	"strings"
)

//go:embed enclave-kernel
var enclaveKernel string

// Kernel returns kernel_release (the release the blob set's kernel
// reports) and whether kernel_hardened is true (the hardened kernel built
// from source by release/kernel).
func Kernel() (release string, hardened bool) {
	return kernel(enclaveKernel)
}

func kernel(lock string) (release string, hardened bool) {
	for _, line := range strings.Split(lock, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		switch k {
		case "kernel_release":
			release = v
		case "kernel_hardened":
			hardened = v == "true"
		}
	}
	return release, hardened
}
