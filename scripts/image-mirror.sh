#!/usr/bin/env bash
# Pull digest-pinned upstream images from a mirror of the same digests.
#
#   scripts/image-mirror.sh ref IMAGE            the reference to pull
#   scripts/image-mirror.sh contexts DOCKERFILE  docker build arguments, one per line
#
# The locks and Dockerfiles name each image upstream, by digest
# (release/eif-toolchain.lock base_image, release/kernel/kernel.lock
# nix_image, Dockerfile.enclave): that is what an independent rebuild
# pulls, and it is unchanged. CI sets VETTID_IMAGE_MIRROR=ghcr.io/vettid/mirror
# (vettid.org .github/mirror: the same images copied byte for byte), and
# then
#   REGISTRY/PATH/NAME:TAG@sha256:D  ->  $VETTID_IMAGE_MIRROR/NAME@sha256:D
# The digest is the same, so the content is the same (the client checks
# it); only the host the bytes come from changes. "contexts" maps each
# digest-pinned FROM of DOCKERFILE that way with --build-context, so the
# Dockerfile itself stays as it is.
#
# With VETTID_IMAGE_MIRROR unset: "ref" prints IMAGE and "contexts" prints
# nothing.
set -euo pipefail

mirror="${VETTID_IMAGE_MIRROR:-}"
mirror="${mirror%/}"

mirrored() {
  local ref="$1"
  if [ -z "$mirror" ]; then
    printf '%s\n' "$ref"
    return
  fi
  if [[ ! "$ref" =~ ^[^@]+/([a-z0-9._-]+)(:[A-Za-z0-9._-]+)?@(sha256:[0-9a-f]{64})$ ]]; then
    echo "image-mirror: $ref is not REGISTRY/.../NAME[:TAG]@sha256:DIGEST; only digest-pinned images come from the mirror" >&2
    exit 1
  fi
  printf '%s/%s@%s\n' "$mirror" "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}"
}

case "${1:-}" in
  ref)
    mirrored "${2:?usage: image-mirror.sh ref IMAGE}"
    ;;
  contexts)
    f="${2:?usage: image-mirror.sh contexts DOCKERFILE}"
    [ -n "$mirror" ] || exit 0
    grep -E '^FROM[[:space:]]' "$f" | while read -r _ a b _; do
      ref="$a"
      case "$a" in --platform=*) ref="$b" ;; esac
      case "$ref" in *@sha256:*) ;; *) continue ;; esac
      m="$(mirrored "$ref")"
      printf -- '--build-context\n%s=docker-image://%s\n' "$ref" "$m"
    done
    ;;
  *)
    echo "usage: image-mirror.sh ref IMAGE | contexts DOCKERFILE" >&2
    exit 2
    ;;
esac
