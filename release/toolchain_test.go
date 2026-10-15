package release

import (
	"regexp"
	"testing"
)

func TestKernel(t *testing.T) {
	r, _ := Kernel()
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(r) {
		t.Fatalf("eif-toolchain.lock kernel_release %q", r)
	}
	r, h := kernel("# kernel_release=1.2.3\nkernel_release=6.6.158\nkernel_hardened=true\n")
	if r != "6.6.158" || !h {
		t.Fatalf("got %q %v", r, h)
	}
	if _, h := kernel("kernel_release=6.6.79\nkernel_hardened=false\n"); h {
		t.Fatal("hardened")
	}
}
