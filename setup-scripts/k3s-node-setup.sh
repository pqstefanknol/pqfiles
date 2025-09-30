#!/usr/bin/env bash
# k3s-node-setup.sh
# Debian 12 node prep + optional k3s (HA-ready) install.
# - Interactive prompts by default
# - Non-interactive via flags or env:
#   ROLE=server|agent HOSTNAME=... TZ=Europe/Amsterdam K3S_VERSION=v1.30.4+k3s1 \
#   API_VIP=10.0.0.10 CLUSTER_INIT=true SERVER_URL=https://10.0.0.10:6443 \
#   TOKEN=xxxx sh ./k3s-node-setup.sh --yes

set -euo pipefail
IFS=$'\n\t'

########################
# Helpers & defaults
########################
log() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*" >&2; }
ask() {
  local prompt="$1" var="$2" def="${3:-}"
  if [ "${ASSUME_YES:-false}" = "true" ]; then
    # non-interactive: keep existing or default
    eval "export $var=\"\${$var:-$def}\""
    return
  fi
  local current; current="$(eval "printf '%s' \"\${$var:-}\"")"
  local show="${current:-$def}"
  read -rp "$prompt [${show}]: " ans || true
  ans="${ans:-$show}"
  eval "export $var=\"$ans\""
}

need_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    err "Please run as root (sudo -i)."
    exit 1
  fi
}

confirm() {
  [ "${ASSUME_YES:-false}" = "true" ] && return 0
  read -rp "$1 [y/N]: " _c || true
  [[ "${_c,,}" =~ ^y(es)?$ ]]
}

validate_role() {
  case "${ROLE:-}" in
    server|agent) ;;
    *) err "ROLE must be 'server' or 'agent'"; exit 2;;
  esac
}

non_empty() { [ -n "${1:-}" ]; }

########################
# Parse args
########################
ASSUME_YES=false
while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) ASSUME_YES=true;;
    -h|--help)
      cat <<EOF
Usage: $0 [--yes]

Environment variables (optional):
  ROLE=server|agent
  HOSTNAME=<node-hostname>
  TZ=Europe/Amsterdam
  K3S_VERSION=<e.g. v1.30.4+k3s1>  (optional)
  # For ROLE=server
  CLUSTER_INIT=true|false          (true only on first server)
  SERVER_URL=https://<VIP>:6443    (on joiners)
  API_VIP=<VIP IPv4>               (used for convenience/logging)
  TOKEN=<shared cluster token>     (server join or agent join)
  # For ROLE=agent
  SERVER_URL=https://<VIP>:6443
  TOKEN=<shared cluster token>

Examples:
  ROLE=server CLUSTER_INIT=true HOSTNAME=server-1 $0 --yes
  ROLE=server SERVER_URL=https://10.0.0.10:6443 TOKEN=abc HOSTNAME=server-2 $0 --yes
  ROLE=agent  SERVER_URL=https://10.0.0.10:6443 TOKEN=abc HOSTNAME=worker-1  $0 --yes
EOF
      exit 0
      ;;
  esac
  shift
done

########################
# Start
########################
need_root

# OFFLINE bundle support
# Usage at deploy time:
#   scp k3s-offline-...tar.gz <node>:/root/
#   ssh <node> "sudo ./k3s-node-setup.sh --yes OFFLINE_BUNDLE=/root/k3s-offline-...tar.gz ROLE=server CLUSTER_INIT=true ..."
OFFLINE_BUNDLE="${OFFLINE_BUNDLE:-}"
if [[ -n "$OFFLINE_BUNDLE" && -f "$OFFLINE_BUNDLE" ]]; then
  log "Using offline bundle: $OFFLINE_BUNDLE"
  TMPDIR="$(mktemp -d)"
  tar -C "$TMPDIR" -xzf "$OFFLINE_BUNDLE"

  install -m 0755 "$TMPDIR/k3s" /usr/local/bin/k3s

  mkdir -p /var/lib/rancher/k3s/agent/images
  cp "$TMPDIR"/k3s-images-*.tar /var/lib/rancher/k3s/agent/images/
  # import all addon images automatically on first k3s start:
  cp "$TMPDIR/addons/"*.tar /var/lib/rancher/k3s/agent/images/ 2>/dev/null || true

  # Auto-applied manifests (server-only path; harmless on agents)
  mkdir -p /var/lib/rancher/k3s/server/manifests
  cp -r "$TMPDIR/server-manifests/." /var/lib/rancher/k3s/server/manifests/ 2>/dev/null || true

  # Tell the upstream get.k3s.io script to skip downloads (we already staged files)
  export INSTALL_K3S_SKIP_DOWNLOAD=true
else
  log "Offline bundle not provided; will use online install."
fi

# Basic OS check
if ! grep -qi 'debian' /etc/os-release || ! grep -q 'VERSION_CODENAME=bookworm' /etc/os-release; then
  warn "This script targets Debian 12 (Bookworm). Continuing anyway."
fi

# Ask for basics
ask "Hostname to set" HOSTNAME "$(hostname)"
ask "Timezone" TZ "${TZ:-Europe/Amsterdam}"
ask "Node role (server/agent)" ROLE "${ROLE:-server}"
validate_role

# Optional cluster fields
if [ "${ROLE}" = "server" ]; then
  ask "API VIP (for reference; e.g. 10.0.0.10)" API_VIP "${API_VIP:-}"
  ask "Is this the first server? (true/false)" CLUSTER_INIT "${CLUSTER_INIT:-true}"
  if [ "${CLUSTER_INIT}" != "true" ]; then
    ask "Server URL (e.g. https://${API_VIP:-10.0.0.10}:6443)" SERVER_URL "${SERVER_URL:-}"
    ask "Shared cluster TOKEN" TOKEN "${TOKEN:-}"
  fi
else
  ask "Server URL (e.g. https://10.0.0.10:6443)" SERVER_URL "${SERVER_URL:-}"
  ask "Shared cluster TOKEN" TOKEN "${TOKEN:-}"
fi

log "Summary:
  Hostname:     ${HOSTNAME}
  Timezone:     ${TZ}
  Role:         ${ROLE}
  K3s version:  ${K3S_VERSION:-(default latest)}
  API VIP:      ${API_VIP:-n/a}
  First server: ${CLUSTER_INIT:-n/a}
  Server URL:   ${SERVER_URL:-n/a}
  Token set:    $( [ -n "${TOKEN:-}" ] && echo yes || echo no )
"

if ! confirm "Proceed with setup?"; then
  err "Aborted."
  exit 1
fi

########################
# Prep System
########################
log "Updating packages & installing prerequisites..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y full-upgrade

# core tools
apt-get -y install --no-install-recommends \
  curl jq ca-certificates gnupg lvm2 nfs-common open-iscsi chrony conntrack \
  iptables arptables ebtables kmod apt-transport-https

# Optional: install the right guest tools for the detected hypervisor
if command -v systemd-detect-virt >/dev/null 2>&1; then
  VIRT="$(systemd-detect-virt || true)"
  case "$VIRT" in
    kvm|qemu|bochs|kvm*)   # Proxmox/KVM etc.
      apt-get -y install qemu-guest-agent || true
      # On some images the unit has no [Install] section; just start it if present.
      systemctl start qemu-guest-agent 2>/dev/null || true
      ;;
    vmware)
      apt-get -y install open-vm-tools || true
      systemctl enable --now open-vm-tools 2>/dev/null || true
      ;;
    microsoft)  # Hyper-V
      apt-get -y install linux-cloud-tools-common linux-cloud-tools-$(uname -r) || true
      ;;
    oracle)     # VirtualBox
      apt-get -y install virtualbox-guest-utils || true
      ;;
    *)
      # Unknown or 'none' (bare metal) — do nothing.
      :
      ;;
  esac
else
  # Fallback: try both, best-effort
  apt-get -y install qemu-guest-agent open-vm-tools || true
  systemctl start qemu-guest-agent 2>/dev/null || true
  systemctl enable --now open-vm-tools 2>/dev/null || true
fi


log "Setting hostname and timezone..."
hostnamectl set-hostname "${HOSTNAME}"
timedatectl set-ntp true
timedatectl set-timezone "${TZ}"

log "Disabling swap (Kubernetes requirement)..."
swapoff -a || true
sed -ri '/\sswap\s/s/^/#/' /etc/fstab || true

log "Ensuring nftables-backed iptables alternatives..."
update-alternatives --set iptables  /usr/sbin/iptables-nft  || true
update-alternatives --set ip6tables /usr/sbin/ip6tables-nft || true
update-alternatives --set arptables /usr/sbin/arptables-nft || true
update-alternatives --set ebtables  /usr/sbin/ebtables-nft  || true

log "Loading container networking kernel modules..."
cat >/etc/modules-load.d/k8s.conf <<'EOF'
overlay
br_netfilter
EOF
modprobe overlay || true
modprobe br_netfilter || true

log "Applying sysctl tuning for Kubernetes..."
cat >/etc/sysctl.d/99-kubernetes.conf <<'EOF'
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
vm.swappiness = 0
fs.inotify.max_user_watches = 1048576
fs.inotify.max_user_instances = 1024
net.netfilter.nf_conntrack_max = 524288
EOF
sysctl --system

log "Enabling iSCSI (Longhorn prerequisite)..."
systemctl enable --now iscsid

########################
# Install k3s (optional)
########################
if confirm "Install k3s now on this node (role=${ROLE})?"; then
  log "Preparing /root/cluster.env for reuse..."
  cat >/root/cluster.env <<EOF
# Saved by k3s-node-setup.sh on $(date -Iseconds)
ROLE=${ROLE}
HOSTNAME=${HOSTNAME}
TZ=${TZ}
K3S_VERSION=${K3S_VERSION:-}
API_VIP=${API_VIP:-}
CLUSTER_INIT=${CLUSTER_INIT:-}
SERVER_URL=${SERVER_URL:-}
TOKEN=${TOKEN:-}
EOF
  chmod 600 /root/cluster.env

  log "Installing k3s (${ROLE})..."
  K3S_INSTALL_SH_URL="https://get.k3s.io"
  export INSTALL_K3S_VERSION="${K3S_VERSION:-}"

  if [ "${ROLE}" = "server" ]; then
    if [ "${CLUSTER_INIT:-}" = "true" ]; then
      # First control-plane: embedded etcd, no join token needed yet
      export INSTALL_K3S_EXEC="server --cluster-init --write-kubeconfig-mode=0644 --disable traefik"
      curl -sfL "${K3S_INSTALL_SH_URL}" | sh -s -
    else
      # Join another server
      if ! non_empty "${SERVER_URL:-}" || ! non_empty "${TOKEN:-}"; then
        err "SERVER_URL and TOKEN are required to join a server."
        exit 1
      fi
      export K3S_URL="${SERVER_URL}"
      export K3S_TOKEN="${TOKEN}"
      export INSTALL_K3S_EXEC="server --write-kubeconfig-mode=0644 --disable traefik"
      curl -sfL "${K3S_INSTALL_SH_URL}" | sh -s -
    fi
    systemctl enable --now k3s
  else
    # Agent node
    if ! non_empty "${SERVER_URL:-}" || ! non_empty "${TOKEN:-}"; then
      err "SERVER_URL and TOKEN are required for agent."
      exit 1
    fi
    export K3S_URL="${SERVER_URL}"
    export K3S_TOKEN="${TOKEN}"
    curl -sfL "${K3S_INSTALL_SH_URL}" | K3S_URL="${K3S_URL}" K3S_TOKEN="${K3S_TOKEN}" sh -s - agent
    systemctl enable --now k3s-agent
  fi

  log "k3s installed. Binaries: /usr/local/bin/k3s, kubectl symlink => k3s kubectl"
  if [ "${ROLE}" = "server" ]; then
    log "Kubeconfig: /etc/rancher/k3s/k3s.yaml  (owner: root)."
    log "Tip: copy it to your user:  mkdir -p ~/.kube && sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config && sudo chown \$USER:\$USER ~/.kube/config"
  fi

else
  warn "Skipped k3s installation. Node is prepped and ready."
fi

########################
# Post hints
########################
cat <<'EONOTE'

Next steps (HA control-plane):
1) On first server, if not set up:
     sudo ROLE=server CLUSTER_INIT=true HOSTNAME=server-1 ./k3s-node-setup.sh --yes
   Then retrieve the join token:
     sudo cat /var/lib/rancher/k3s/server/node-token

2) On additional servers:
     sudo ROLE=server CLUSTER_INIT=false SERVER_URL=https://<API-VIP>:6443 TOKEN=<token> HOSTNAME=server-2 ./k3s-node-setup.sh --yes

3) On agents (workers):
     sudo ROLE=agent SERVER_URL=https://<API-VIP>:6443 TOKEN=<token> HOSTNAME=worker-1 ./k3s-node-setup.sh --yes

VIP & Ingress:
- For a single API VIP on control-plane nodes, consider kube-vip (ARP) as a static pod.
- For service LoadBalancers, install MetalLB and reserve a small IP pool.

Longhorn:
- Ensure iSCSI is running (this script enabled it). Optionally mount a dedicated disk at /var/lib/longhorn.

Uninstall:
  /usr/local/bin/k3s-uninstall.sh      # server
  /usr/local/bin/k3s-agent-uninstall.sh# agent
EONOTE

log "Done."
