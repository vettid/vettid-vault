#!/usr/bin/env bash
# Is the pinned enclave kernel the newest point release of its longterm
# series (docs/KERNEL.md, "Keeping it current")? Reads kernel.lock, asks
# kernel.org's releases.json and GitHub for AWS's newest bootstrap
# release, and writes a Markdown report.
#
#   release/kernel/check-current.sh REPORT_MD
#
# Exit 0: current. Exit 10: a newer point release exists (the report says
# which, with its kernel.org SHA-256 to put in kernel.lock after build.sh
# has verified its signature). Exit 11: the series is no longer on
# kernel.org's list (end of life) or is marked end of life. Exit 1: the
# check itself failed, or kernel.org's answer is not what it should be
# (never "current" on an answer it cannot read). MAX_DAYS_BEHIND (default
# 30): exit 12 instead of 10 when the first newer release is older than
# that. Exit 13: the kernel
# is current but AWS's recipe has new commits.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
lock="$here/kernel.lock"
report="${1:?usage: release/kernel/check-current.sh REPORT_MD}"
max_days="${MAX_DAYS_BEHIND:-30}"

# KERNEL_VERSION: check this version instead of kernel.lock's (the release
# workflow checks the kernel release/eif-toolchain.lock pins).
pinned="${KERNEL_VERSION:-$(sed -n 's/^kernel_version=//p' "$lock")}"
aws_commit="$(sed -n 's/^aws_bootstrap_commit=//p' "$lock")"
series="${pinned%.*}"
patch="${pinned##*.}"
if ! [[ "$pinned" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "check: kernel_version $pinned is not X.Y.Z" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/releases.json" https://www.kernel.org/releases.json

entry="$(jq -c --arg s "$series." '[.releases[] | select(.moniker == "longterm" and (.version | startswith($s)))] | first // empty' "$tmp/releases.json")"
status=0
{
  echo "### Enclave kernel: pinned Linux $pinned"
  echo
  if [ -z "$entry" ]; then
    echo "**Linux $series is not on kernel.org's longterm list** (https://www.kernel.org/releases.json): end of life. Move to a maintained longterm series (docs/KERNEL.md)."
    status=11
  else
    newest="$(jq -r .version <<<"$entry")"
    released="$(jq -r .released.isodate <<<"$entry")"
    iseol="$(jq -r .iseol <<<"$entry")"
    newest_patch="${newest##*.}"
    if ! [[ "$newest" =~ ^${series//./\\.}\.[0-9]+$ ]] || ! [[ "$released" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
      echo "check: kernel.org lists $series as \"$newest\" released \"$released\": not understood" >&2
      exit 1
    fi
    if [ "$iseol" = true ]; then
      echo "**kernel.org marks Linux $series end of life.**"
      status=11
    fi
    if [ "$newest_patch" -gt "$patch" ]; then
      behind=$((newest_patch - patch))
      # The first release after the pin: its date from the v6.x index.
      major="${series%%.*}"
      curl -fsSL --retry 3 -o "$tmp/index.html" "https://cdn.kernel.org/pub/linux/kernel/v$major.x/"
      next="$series.$((patch + 1))"
      first_date="$(grep -o "linux-$next\.tar\.xz</a> *[0-9]*-[A-Za-z]*-[0-9]*" "$tmp/index.html" | awk '{print $NF}' | head -1)"
      days=""
      if [ -n "$first_date" ]; then
        days=$((($(date -u +%s) - $(date -u -d "$first_date" +%s)) / 86400))
      fi
      curl -fsSL --retry 3 -o "$tmp/sha256sums.asc" "https://cdn.kernel.org/pub/linux/kernel/v$major.x/sha256sums.asc"
      new_sha="$(awk -v f="linux-$newest.tar.xz" '$2 == f {print $1}' "$tmp/sha256sums.asc")"
      echo "**Linux $newest is out** ($released), $behind point release(s) after the pinned $pinned; the first of them, $next, came out ${first_date:-on an unknown date}${days:+ ($days days ago)}."
      echo
      echo "To pick it up (docs/KERNEL.md, \"A new point release\"): in release/kernel/kernel.lock set"
      echo
      echo '```'
      echo "kernel_version=$newest"
      echo "kernel_url=https://cdn.kernel.org/pub/linux/kernel/v$major.x/linux-$newest.tar.xz"
      echo "kernel_sha256=${new_sha:-<not in sha256sums.asc yet>}"
      echo '```'
      echo
      echo "then let the enclave-kernel workflow verify the signature, rebuild twice and compare; check that both patches still apply and are still needed, and review the system call table diff."
      if [ "$status" = 0 ]; then
        status=10
        if [ -n "$days" ] && [ "$days" -gt "$max_days" ]; then status=12; fi
      fi
    else
      echo "Linux $pinned is the newest $series release on kernel.org ($released)."
    fi
  fi
  echo
  # AWS's own blob builds: a new release there is the signal to compare
  # configs and patches with ours.
  # The GitHub API can answer 200 with an error object (rate limits): a
  # missing field is "unknown", never a change.
  aws="$(curl -fsSL --retry 3 https://api.github.com/repos/aws/aws-nitro-enclaves-sdk-bootstrap/releases/latest |
    jq -r 'if (.tag_name | type) == "string" then .tag_name + " (" + (.published_at // "?") + ")" else "unknown" end' 2>/dev/null || echo unknown)"
  aws_head="$(curl -fsSL --retry 3 https://api.github.com/repos/aws/aws-nitro-enclaves-sdk-bootstrap/commits/HEAD | jq -r '.sha // "unknown"' 2>/dev/null || echo unknown)"
  if ! [[ "$aws_head" =~ ^[0-9a-f]{40}$ ]]; then aws_head=unknown; fi
  echo "aws-nitro-enclaves-sdk-bootstrap: newest release $aws; HEAD $aws_head; our recipe follows $aws_commit."
  if [ "$aws_head" != unknown ] && [ "$aws_head" != "$aws_commit" ]; then
    echo
    echo "**AWS's recipe has changed since $aws_commit**: compare its kernel config, patches, init and linuxkit with release/kernel/aws."
    if [ "$status" = 0 ]; then status=13; fi
  fi
} >"$report"
cat "$report"
exit "$status"
