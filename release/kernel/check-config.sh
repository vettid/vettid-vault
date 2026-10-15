#!/usr/bin/env bash
# Require every setting of a Kconfig fragment to hold in a resolved
# .config: CONFIG_X=v must appear as that exact line, "# CONFIG_X is not
# set" means no CONFIG_X= line at all (Kconfig writes an option whose
# dependencies are missing as absent, which is also "off").
#
#   check-config.sh FRAGMENT DOTCONFIG
set -euo pipefail

fragment="${1:?usage: check-config.sh FRAGMENT DOTCONFIG}"
config="${2:?usage: check-config.sh FRAGMENT DOTCONFIG}"
bad=0
n=0
while IFS= read -r line; do
  case "$line" in
    CONFIG_*=*)
      n=$((n + 1))
      if ! grep -qxF -- "$line" "$config"; then
        have="$(grep -E "^(# )?${line%%=*}[= ]" "$config" || echo "absent")"
        echo "check-config: want $line, have $have" >&2
        bad=1
      fi
      ;;
    "# CONFIG_"*" is not set")
      n=$((n + 1))
      opt="${line#\# }"
      opt="${opt%% *}"
      if grep -q "^${opt}=" "$config"; then
        echo "check-config: want $opt off, have $(grep "^${opt}=" "$config")" >&2
        bad=1
      fi
      ;;
  esac
done <"$fragment"
if [ "$bad" != 0 ]; then
  echo "check-config: $fragment does not hold in $config" >&2
  exit 1
fi
echo "check-config: all $n settings of $(basename "$fragment") hold"
