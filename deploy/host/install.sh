#!/usr/bin/env bash
# install.sh: run once, as root, by vettid.org's release AMI build (EC2
# Image Builder, VAULT-RELEASES §8.3) from a staging directory holding the
# files of deploy/host/SHA256SUMS at the release's source commit, after
# they passed `sha256sum -c`. The component has already installed
# aws-nitro-enclaves-cli and amazon-cloudwatch-agent, and the release's
# /opt/vettid/vault-enclave.eif and /opt/vettid/bin/vault-parent.
# Idempotent. Enables the units but starts nothing (image build).
set -euo pipefail

cd "$(dirname "$0")"
[[ $(id -u) == 0 ]] || {
	echo "install.sh: must run as root" >&2
	exit 1
}

for f in /opt/vettid/vault-enclave.eif /opt/vettid/bin/vault-parent; do
	[[ -s $f ]] || {
		echo "install.sh: $f is missing (installed from the release assets first)" >&2
		exit 1
	}
done
chmod 0755 /opt/vettid/bin/vault-parent
command -v nitro-cli >/dev/null || {
	echo "install.sh: nitro-cli is not installed" >&2
	exit 1
}

install -d -m 0755 /opt/vettid /opt/vettid/bin /opt/vettid/etc /etc/vettid /etc/nitro_enclaves
install -d -m 0750 /var/log/vettid
install -m 0755 vault-host-config vault-lifecycle /opt/vettid/bin/
install -m 0644 amazon-cloudwatch-agent.json.tmpl /opt/vettid/etc/
install -m 0644 allocator.yaml /etc/nitro_enclaves/allocator.yaml
install -m 0644 vettid.logrotate /etc/logrotate.d/vettid
install -m 0644 vault-host-config.service vault-parent.service vault-enclave.service vault-lifecycle.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable nitro-enclaves-allocator.service vault-host-config.service vault-enclave.service \
	vault-parent.service vault-lifecycle.service
# vault-host-config starts the CloudWatch agent once its configuration is
# rendered.
systemctl disable amazon-cloudwatch-agent.service 2>/dev/null || true

# The host's DNS firewall blocks the package repositories: no background
# metadata refreshes or automatic updates (updates come as a new AMI).
for t in dnf-makecache.timer dnf-automatic.timer dnf-automatic-install.timer \
	dnf-automatic-download.timer dnf-automatic-notifyonly.timer; do
	systemctl disable --now "$t" 2>/dev/null || true
	systemctl mask "$t"
done

echo "install.sh: installed; units enabled (not started)"
