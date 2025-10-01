#!/usr/bin/env bash
# k3s-node-setup.sh  (base-image + optional k3s install + template prep)
# Usage (interactive):
#   sudo ./k3s-node-setup.sh
# Non-interactive examples:
#   PHASE=base ASSUME_YES=true HOSTNAME=base-img TZ=Europe/Amsterdam sudo -E ./k3s-node-setup.sh
#   PHASE=k3s  ROLE=server CLUSTER_INIT=true API_VIP=10.0.0.10 ASSUME_YES=true sudo -E ./k3s-node-setup.sh
#   PHASE=all  ROLE=server CLUSTER_INIT=false SERVER_URL=https://10.0.0.10:6443 TOKEN=xxxx API_VIP=10.0.0.10 ASSUME_YES=true sudo -E ./k3s-node-setup.sh
# Template prep (after base prep, before cloning):
#   TEMPLATE_PREP=true ASSUME_YES=true sudo -E ./k3s-node-setup.sh
#
# Optional k3s offline bundle:
#   OFFLINE_BUNDLE=/root/k3s-offline-*.tar.gz

set -euo pipefail
IFS=$'\n\t'

################################
# Helpers / defaults
################################
log()  { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*" >&2; }
trap 'err "Failed at line $LINENO"; exit 1' ERR

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

non_empty() { [ -n "${1:-}" ]; }

# Build flag arrays cleanly
add_flag_if_set() { # usage: add_flag_if_set VAR FLAG ARRAY_NAME
  local var="$1" flag="$2" arr="$3"
  if [ -n "${!var:-}" ]; then
    eval "$arr+=(\"$flag\" \"${!var}\")"
  fi
}

# Value prompt (with optional validation list)
ask_value() { # ask_value "Prompt" VAR default_value [valid_values...]
  local prompt="$1" var="$2" def="${3:-}" val
  shift 3
  local valid_values=("$@")

  if [ "${ASSUME_YES:-false}" = "true" ]; then
    val="${!var:-$def}"
    eval "export $var=\"$val\""
    return
  fi

  local current; current="$(eval "printf '%s' \"\${$var:-}\"")"
  local show="${current:-$def}"

  if [ ${#valid_values[@]} -gt 0 ]; then
    local options="[${valid_values[*]}]"
    read -rp "$prompt $options [${show}]: " ans || true
    ans="${ans:-$show}"

    local valid=false
    for valid_value in "${valid_values[@]}"; do
      if [ "$ans" = "$valid_value" ]; then
        valid=true
        break
      fi
    done
    if [ "$valid" = "false" ]; then
      echo "Invalid value. Must be one of: ${valid_values[*]}"
      ask_value "$prompt" "$var" "$def" "${valid_values[@]}"
      return
    fi
  else
    read -rp "$prompt [${show}]: " ans || true
    ans="${ans:-$show}"
  fi

  eval "export $var=\"$ans\""
}

# yes/no helper (default=no unless ASSUME_YES true)
parse_bool() { local s="${1,,}"; [[ "$s" =~ ^(y|yes|true|1)$ ]]; }
ask_bool() {
  local prompt="$1" var="$2" def="${3:-false}" show ans
  [ "${ASSUME_YES:-false}" = "true" ] && { eval "export $var=$def"; return; }
  show=$([ "$def" = "true" ] && echo "yes" || echo "no")
  read -rp "$prompt [${show}]: " ans || true
  ans="${ans:-$show}"
  if parse_bool "$ans"; then eval "export $var=true"; else eval "export $var=false"; fi
}

# Read a token without echoing input (for ENDPOINT_TOKEN)
ask_secret() {
  local prompt="$1" var="$2" def="${3:-}"
  if [ "${ASSUME_YES:-false}" = "true" ] && [ -n "${!var:-}" ]; then return; fi
  local current; current="$(eval "printf '%s' \"\${$var:-}\"")"
  local show="${current:-$def}"
  read -rsp "$prompt [hidden, Enter to keep default${show:+: $show}]: " ans || true
  echo
  ans="${ans:-$show}"
  eval "export $var=\"$ans\""
}

gen_hex()  { openssl rand -hex 32; }             # 64 hex chars
gen_pass() { openssl rand -base64 32 | tr -d '\n' | cut -c1-32; }

ensure_db_creds() {
  POSTGRES_USER="${POSTGRES_USER:-bns_admin}"
  POSTGRES_DB="${POSTGRES_DB:-bns}"
  POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(gen_pass)}"
  export POSTGRES_USER POSTGRES_DB POSTGRES_PASSWORD
  log "DB creds ready (user=${POSTGRES_USER}, db=${POSTGRES_DB}). Password stored in env only."
}

################################
# Installers
################################
install_helm() {
  if ! command -v helm >/dev/null 2>&1; then
    log "Installing Helm..."
    curl -fsSL https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
  fi
}

# Install/upgrade ingress-nginx and bind external ports via hostPorts.
# EXTERNAL_HTTPS_PORT defaults to 443; EXTERNAL_HTTP_PORT defaults to 80.
# Set EXTERNAL_TLS=false to run plain HTTP only (no TLS listener).
install_ingress_nginx() {
  local ns="ingress-nginx"
  local EXTERNAL_HTTPS_PORT="${EXTERNAL_HTTPS_PORT:-443}"
  local EXTERNAL_HTTP_PORT="${EXTERNAL_HTTP_PORT:-80}"
  local EXTERNAL_TLS="${EXTERNAL_TLS:-true}"   # true|false

  kubectl create ns "$ns" 2>/dev/null || true
  install_helm
  helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null
  helm repo update >/dev/null

  # Base args: DaemonSet + hostPorts + ClusterIP service (no extra IPs)
  local ARGS=(
    --set controller.kind=DaemonSet
    --set controller.hostNetwork=false
    --set controller.hostPort.enabled=true
    --set controller.service.type=ClusterIP
    --set controller.metrics.enabled=true
  )

  # HTTP port (optional)
  if [ "${EXTERNAL_HTTP_PORT}" != "off" ]; then
    ARGS+=(--set controller.hostPort.http="${EXTERNAL_HTTP_PORT}")
  else
    # disable HTTP listener entirely
    ARGS+=(--set controller.enableHttp=false)
  fi

  # HTTPS / TLS listener
  if [ "${EXTERNAL_TLS}" = "true" ]; then
    ARGS+=(--set controller.hostPort.https="${EXTERNAL_HTTPS_PORT}")
  else
    # disable HTTPS; serve plain HTTP only
    ARGS+=(--set controller.enableHttps=false)
  fi

  helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx -n "$ns" "${ARGS[@]}"
  log "ingress-nginx ready. External ports -> HTTP:${EXTERNAL_HTTP_PORT:-off} HTTPS:${EXTERNAL_TLS:+$EXTERNAL_HTTPS_PORT}"
  log "Ingress still routes to Service on port 3001 inside the cluster."
}

install_longhorn() {
  log "Installing Longhorn (replicated PVs)..."
  kubectl create ns longhorn-system 2>/dev/null || true
  install_helm
  helm repo add longhorn https://charts.longhorn.io >/dev/null
  helm repo update >/dev/null
  helm upgrade --install longhorn longhorn/longhorn -n longhorn-system
  log "Longhorn installed. Ensure open-iscsi is running (script already enabled it)."
}

install_timescaledb_ha() {
  local ns="${1:-data}"
  local sc="${2:-longhorn}"
  log "Installing TimescaleDB-HA (Patroni-backed) into namespace: $ns"

  kubectl create ns "$ns" 2>/dev/null || true
  install_helm
  helm repo add timescale https://charts.timescale.com >/dev/null
  helm repo update >/dev/null

  # Ensure creds exist (and exported) before install
  ensure_db_creds

  helm upgrade --install tsdb timescale/timescaledb-single -n "$ns" \
    --set replicaCount=3 \
    --set storageClass="$sc" \
    --set volumePermissions.enabled=true \
    --set resources.requests.cpu=500m \
    --set resources.requests.memory=1Gi \
    --set credentials.username="${POSTGRES_USER}" \
    --set credentials.password="${POSTGRES_PASSWORD}" \
    --set credentials.database="${POSTGRES_DB}"

  # Optional: create extension at init (if your chart supports it via initdbScripts)
  # kubectl -n "$ns" create configmap tsdb-init --from-literal init.sql='CREATE EXTENSION IF NOT EXISTS timescaledb;' \
  #   --dry-run=client -o yaml | kubectl apply -f -
  # and then add: --set initdbScriptsConfigMap=tsdb-init
}

install_redis_sentinel() {
  local ns="${1:-data}"
  local sc="${2:-longhorn}"

  kubectl create ns "$ns" 2>/dev/null || true
  install_helm
  helm repo add bitnami https://charts.bitnami.com/bitnami >/dev/null
  helm repo update >/dev/null

  REDIS_PASSWORD="${REDIS_PASSWORD:-$(openssl rand -base64 32 | tr -d '\n' | cut -c1-32)}"

  helm upgrade --install redis bitnami/redis -n "$ns" \
    --set architecture=replication \
    --set replica.replicaCount=2 \
    --set sentinel.enabled=true \
    --set sentinel.usePassword=true \
    --set sentinel.masterSet=mymaster \
    --set auth.password="${REDIS_PASSWORD}" \
    --set master.persistence.size=10Gi \
    --set replica.persistence.size=10Gi \
    --set master.persistence.storageClass="$sc" \
    --set replica.persistence.storageClass="$sc"

  log "Redis (Sentinel) installed with password; master: redis-master.${ns}.svc.cluster.local, sentinel: redis.${ns}.svc.cluster.local:26379"
}

apply_bns_minimal_config() {
  local ns="blueraven-network-server"
  kubectl create ns "$ns" 2>/dev/null || true

  # ----- generated secrets -----
  API_TOKEN="${API_TOKEN:-$(gen_hex)}"
  POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(gen_pass)}"  # will keep existing from ensure_db_creds
  REDIS_PASSWORD="${REDIS_PASSWORD:-$(gen_pass)}"

  # Provided during install
  ask_secret "Enter ENDPOINT_TOKEN (from BlueRaven)" ENDPOINT_TOKEN "${ENDPOINT_TOKEN:-}"

  # ----- Redis mode: USE_SENTINEL=true|false (default true). If REDIS_URL set, it overrides both. -----
  USE_SENTINEL="${USE_SENTINEL:-true}"
  REDIS_URL="${REDIS_URL:-}"

  # Base app (HTTP behind ingress; set SSL_PORT=3001 so the app won’t do TLS itself)
  cat >/tmp/bns-app.env <<'CFG'
PORT=3001
SSL_PORT=3001
POSTGRES_HOST=tsdb-timescaledb.data.svc.cluster.local
POSTGRES_PORT=5432
POSTGRES_USER=bns_admin
POSTGRES_DB=bns
BNS_NAME=BNS
VERSION=5.0.0
CFG

  if [ -n "$REDIS_URL" ]; then
    # C) URL-driven override
    cat >>/tmp/bns-app.env <<CFG
REDIS_URL=${REDIS_URL}
CFG
  elif [ "${USE_SENTINEL,,}" = "true" ]; then
    # B) Sentinel-aware (default)
    cat >>/tmp/bns-app.env <<'CFG'
REDIS_SENTINEL=true
REDIS_MASTER_SET=mymaster
# Single Kubernetes headless name works; Sentinel picks up all pods
REDIS_SENTINELS=redis.data.svc.cluster.local:26379
CFG
  else
    # A) Simple, not Sentinel-aware
    cat >>/tmp/bns-app.env <<'CFG'
REDIS_SENTINEL=false
REDIS_HOST=redis-master.data.svc.cluster.local
REDIS_PORT=6379
CFG
  fi

  kubectl -n "$ns" create configmap bns-config \
    --from-env-file=/tmp/bns-app.env \
    --dry-run=client -o yaml | kubectl apply -f -

  cat >/tmp/bns-secrets.env <<SEC
API_TOKEN=${API_TOKEN}
ENDPOINT_TOKEN=${ENDPOINT_TOKEN}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
SEC

  kubectl -n "$ns" create secret generic bns-secrets \
    --from-env-file=/tmp/bns-secrets.env \
    --dry-run=client -o yaml | kubectl apply -f -

  rm -f /tmp/bns-app.env /tmp/bns-secrets.env

  log "BNS minimal ConfigMap/Secret applied (ns: $ns)."
  log "Generated API_TOKEN, POSTGRES_PASSWORD, REDIS_PASSWORD."
}

deploy_blueraven() {
  local ns="blueraven-network-server"
  log "Deploying BlueRaven Network Server (minimal prod) ..."
  kubectl create ns "$ns" 2>/dev/null || true

  cat <<'YAML' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blueraven-network-server
  namespace: blueraven-network-server
spec:
  replicas: 3
  selector:
    matchLabels: { app: blueraven-network-server }
  template:
    metadata:
      labels: { app: blueraven-network-server }
    spec:
      containers:
      - name: app
        image: blueraven-network-server:<version>
        ports:
        - containerPort: 3001
        envFrom:
        - configMapRef: { name: bns-config }
        - secretRef:    { name: bns-secrets }
---
apiVersion: v1
kind: Service
metadata:
  name: blueraven-network-server
  namespace: blueraven-network-server
spec:
  selector: { app: blueraven-network-server }
  ports:
  - name: http
    port: 3001
    targetPort: 3001
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: blueraven-network-server
  namespace: blueraven-network-server
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
spec:
  ingressClassName: nginx
  rules:
  - host: blueraven-network-server.localtest.me
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: blueraven-network-server
            port: { number: 3001 }
YAML

  log "BlueRaven deployed. Browse https://blueraven-network-server.localtest.me (TLS at ingress)."
}



################################
# Arg parsing (just -y/--yes)
################################
ASSUME_YES="${ASSUME_YES:-false}"
while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) ASSUME_YES=true;;
    -h|--help)
      cat <<'EOF'
Usage: k3s-node-setup.sh [--yes]

Environment:
  PHASE=base|k3s|all              (default: base)
  ASSUME_YES=true|false           (default: false)
  TEMPLATE_PREP=true|false        (default: false)  # scrub IDs/keys/logs for VM template

  # Base phase (optional)
  HOSTNAME=<node-hostname>
  TZ=Europe/Amsterdam

  # k3s (server or agent)
  ROLE=server|agent
  K3S_VERSION=<e.g. v1.30.4+k3s1> (optional)
  API_VIP=<VIP IPv4>              (optional, used in --tls-san)
  CLUSTER_INIT=true|false         (true on first server)
  SERVER_URL=https://<VIP>:6443   (joiners/agents)
  TOKEN=<cluster token>           (joiners/agents)
  NODE_IP=<ip>                    (optional, pin advertise IP)
  API_FQDN=<dns>                  (optional, extra TLS SAN)

  # k3s offline bundle
  OFFLINE_BUNDLE=/root/k3s-offline-...tar.gz

Examples:
  PHASE=base ASSUME_YES=true HOSTNAME=img-base TZ=Europe/Amsterdam ./k3s-node-setup.sh
  PHASE=k3s  ROLE=server CLUSTER_INIT=true API_VIP=10.0.0.10 ASSUME_YES=true ./k3s-node-setup.sh
  PHASE=all  ROLE=agent SERVER_URL=https://10.0.0.10:6443 TOKEN=abc ASSUME_YES=true ./k3s-node-setup.sh
  TEMPLATE_PREP=true ASSUME_YES=true ./k3s-node-setup.sh
EOF
      exit 0;;
  esac
  shift
done

################################
# Start
################################
need_root

# Record whether PHASE was provided by env, then set defaults
if [ -z "${PHASE+x}" ]; then PHASE_ENV_SET=false; else PHASE_ENV_SET=true; fi
PHASE="${PHASE:-base}"               # base | k3s | all
TEMPLATE_PREP="${TEMPLATE_PREP:-false}"

# Conflict guard: TEMPLATE_PREP + PHASE=k3s/all is not allowed
if [ "${TEMPLATE_PREP,,}" = "true" ] && [ "${PHASE}" != "base" ]; then
  if [ "${ASSUME_YES:-false}" = "true" ]; then
    err "TEMPLATE_PREP=true conflicts with PHASE=${PHASE}. Use PHASE=base or unset TEMPLATE_PREP."
    exit 2
  else
    warn "TEMPLATE_PREP=true conflicts with PHASE=${PHASE}."
    if confirm "Switch to PHASE=base and run template prep only?"; then
      PHASE="base"
    else
      TEMPLATE_PREP="false"
    fi
  fi
fi

# OS guardrail (Debian 12/13)
if [ -r /etc/os-release ]; then
  . /etc/os-release
  if [ "${ID,,}" != "debian" ] || { [ "$VERSION_CODENAME" != "bookworm" ] && [ "$VERSION_CODENAME" != "trixie" ]; }; then
    warn "This script targets Debian 12 (Bookworm) or Debian 13 (Trixie). Continuing anyway."
  fi
else
  warn "/etc/os-release not found; proceeding cautiously."
fi

################################
# OFFLINE k3s bundle (if supplied)
################################
OFFLINE_BUNDLE="${OFFLINE_BUNDLE:-}"
if [[ -n "$OFFLINE_BUNDLE" && -f "$OFFLINE_BUNDLE" ]]; then
  log "Staging k3s offline bundle: $OFFLINE_BUNDLE"
  TMPDIR="$(mktemp -d)"
  tar -C "$TMPDIR" -xzf "$OFFLINE_BUNDLE"
  install -m 0755 "$TMPDIR/k3s" /usr/local/bin/k3s
  mkdir -p /var/lib/rancher/k3s/agent/images
  cp "$TMPDIR"/k3s-images-*.tar /var/lib/rancher/k3s/agent/images/
  cp "$TMPDIR"/addons/*.tar /var/lib/rancher/k3s/agent/images/ 2>/dev/null || true
  mkdir -p /var/lib/rancher/k3s/server/manifests
  cp -r "$TMPDIR/server-manifests/." /var/lib/rancher/k3s/server/manifests/ 2>/dev/null || true
  export INSTALL_K3S_SKIP_DOWNLOAD=true
fi

################################
# Phase: BASE
################################
base_prep() {
  log "=== BASE PREP ==="

  ask_value "Hostname to set" HOSTNAME "$(hostname)"
  ask_value "Timezone" TZ "${TZ:-Europe/Amsterdam}"

  log "Updating packages & installing prerequisites..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get -y full-upgrade

  apt-get -y install --no-install-recommends \
    curl jq ca-certificates gnupg lvm2 nfs-common open-iscsi chrony conntrack \
    iptables arptables ebtables kmod apt-transport-https \
    htop vim net-tools tcpdump git unzip rsync

  # Guest tools (hypervisor-aware)
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    VIRT="$(systemd-detect-virt || true)"
    case "$VIRT" in
      kvm|qemu|bochs|kvm*)
        apt-get -y install qemu-guest-agent || true
        systemctl enable --now qemu-guest-agent 2>/dev/null || true ;;
      vmware)
        apt-get -y install open-vm-tools || true
        systemctl enable --now open-vm-tools 2>/dev/null || true ;;
      microsoft)
        apt-get -y install linux-cloud-tools-common "linux-cloud-tools-$(uname -r)" || true ;;
      oracle)
        apt-get -y install virtualbox-guest-utils || true ;;
      *) : ;;
    esac
  fi

  log "Setting hostname and timezone..."
  hostnamectl set-hostname "${HOSTNAME}"
  timedatectl set-ntp true
  timedatectl set-timezone "${TZ}"

  log "Disabling swap (Kubernetes requirement)..."
  swapoff -a || true
  sed -ri '/\sswap\s/s/^/#/' /etc/fstab || true

  log "Ensure iptables-nft alternatives..."
  update-alternatives --set iptables  /usr/sbin/iptables-nft  || true
  update-alternatives --set ip6tables /usr/sbin/ip6tables-nft || true
  update-alternatives --set arptables /usr/sbin/arptables-nft || true
  update-alternatives --set ebtables  /usr/sbin/ebtables-nft  || true

  log "Loading container networking modules..."
  cat >/etc/modules-load.d/k8s.conf <<'EOF'
overlay
br_netfilter
EOF
  modprobe overlay || true
  modprobe br_netfilter || true

  log "Applying sysctl tuning..."
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

  # Reboot hint when kernel or core libs updated
  if [ -f /var/run/reboot-required ]; then
    warn "A reboot is required (kernel or core packages updated). Consider rebooting before installing k3s."
  fi

  log "Enable iSCSI (Longhorn prerequisite)..."
  systemctl enable --now iscsid

  log "Saving /root/base.env snapshot..."
  cat >/root/base.env <<EOF
# Saved by k3s-node-setup.sh on $(date -Iseconds)
HOSTNAME=${HOSTNAME}
TZ=${TZ}
EOF
  chmod 600 /root/base.env

  log "BASE PREP complete."

  # If PHASE wasn't provided via env, offer simple yes/no flow
  if [ "$PHASE_ENV_SET" = "false" ]; then
    ask_bool "Set this machine up as a reusable template?" TEMPLATE_PREP false
    if [ "$TEMPLATE_PREP" != "true" ]; then
      ask_bool "Install k3s after base prep?" RUN_K3S_AFTER_BASE false
    fi
  fi
}

################################
# Phase: K3S
################################
k3s_install() {
  log "=== K3S INSTALL ==="

  # Inputs
  ask_value "Node role (server/agent)" ROLE "server" "server" "agent"

  # Optional extras from env:
  #   NODE_IP=10.0.0.x            (pin advertise IP on multi-NIC)
  #   API_FQDN=cluster.example.com (extra TLS SAN)
  #   DISABLE_TRAEFIK=true|false   (default true)
  #   DISABLE_SERVICELB=true|false (default true)
  DISABLE_TRAEFIK="${DISABLE_TRAEFIK:-true}"
  DISABLE_SERVICELB="${DISABLE_SERVICELB:-true}"

  if [ "${ROLE}" = "server" ]; then
    ask_value "API VIP (for --tls-san; e.g. 10.0.0.10)" API_VIP "${API_VIP:-}"
    ask_value "Is this the first server? (true/false)" CLUSTER_INIT "true" "true" "false"
    if [ "${CLUSTER_INIT}" != "true" ]; then
      ask_value "Server URL (e.g. https://${API_VIP:-10.0.0.10}:6443)" SERVER_URL "${SERVER_URL:-}"
      ask_value "Shared cluster TOKEN" TOKEN "${TOKEN:-}"
    fi

    # Build flags
    server_flags=(--write-kubeconfig-mode=0644)
    [ "$DISABLE_TRAEFIK" = "true" ]   && server_flags+=(--disable traefik)
    [ "$DISABLE_SERVICELB" = "true" ] && server_flags+=(--disable servicelb)
    add_flag_if_set API_VIP  --tls-san server_flags
    add_flag_if_set API_FQDN --tls-san server_flags
    add_flag_if_set NODE_IP  --node-ip  server_flags

    log "Summary:
    Role:         server
    K3s version:  ${K3S_VERSION:-(default latest)}
    API VIP:      ${API_VIP:-n/a}
    First server: ${CLUSTER_INIT}
    Server URL:   ${SERVER_URL:-n/a}
    Token set:    $( [ -n "${TOKEN:-}" ] && echo yes || echo no )
    Extra SAN:    ${API_FQDN:-n/a}
    NODE_IP:      ${NODE_IP:-auto}
    "
    if ! confirm "Proceed with k3s installation?"; then
      warn "Skipping k3s install."
      return 0
    fi

    log "Preparing /root/cluster.env..."
    cat >/root/cluster.env <<EOF
# Saved by k3s-node-setup.sh on $(date -Iseconds)
ROLE=server
HOSTNAME=${HOSTNAME:-$(hostname)}
TZ=${TZ:-$(timedatectl show -p Timezone --value || echo Europe/Amsterdam)}
K3S_VERSION=${K3S_VERSION:-}
API_VIP=${API_VIP:-}
API_FQDN=${API_FQDN:-}
NODE_IP=${NODE_IP:-}
CLUSTER_INIT=${CLUSTER_INIT:-}
SERVER_URL=${SERVER_URL:-}
TOKEN=${TOKEN:-}
EOF
    chmod 600 /root/cluster.env

    # Do the install (single place)
    K3S_INSTALL_SH_URL="https://get.k3s.io"
    export INSTALL_K3S_VERSION="${K3S_VERSION:-}"
        # --- kube-vip API VIP (first server only) ---
    # --- kube-vip API VIP (first server only) ---
    if [ "${CLUSTER_INIT}" = "true" ]; then
      if ! non_empty "${API_VIP:-}"; then
        err "API_VIP is required for first server (kube-vip)."
        exit 1
      fi

      KUBE_VIP_VER="${KUBE_VIP_VER:-v0.8.7}"
      IFACE="${IFACE:-$(ip -o -4 route show to default | awk '{print $5}' | head -n1)}"
      mkdir -p /var/lib/rancher/k3s/server/manifests

      log "Installing kube-vip RBAC/DaemonSet (VIP: ${API_VIP}, IFACE: ${IFACE})..."
      curl -fsSL https://kube-vip.io/manifests/rbac.yaml \
        -o /var/lib/rancher/k3s/server/manifests/kube-vip-rbac.yaml

      # DaemonSet (control-plane VIP only; no Service LBs)
      cat >/var/lib/rancher/k3s/server/manifests/kube-vip-ds.yaml <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-vip
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: kube-vip
  template:
    metadata:
      labels:
        app.kubernetes.io/name: kube-vip
    spec:
      hostNetwork: true
      tolerations:
      - key: "node-role.kubernetes.io/control-plane"
        operator: "Exists"
        effect: "NoSchedule"
      - key: "node-role.kubernetes.io/master"
        operator: "Exists"
        effect: "NoSchedule"
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: node-role.kubernetes.io/control-plane
                operator: Exists
      containers:
      - name: kube-vip
        image: ghcr.io/kube-vip/kube-vip:${KUBE_VIP_VER}
        args: ["manager"]
        env:
        - name: vip_arp
          value: "true"
        - name: address
          value: "${API_VIP}"
        - name: interface
          value: "${IFACE}"
        - name: cp_enable
          value: "true"
        - name: svc_enable
          value: "false"
        securityContext:
          capabilities:
            add: ["NET_ADMIN","NET_RAW"]
EOF

      export INSTALL_K3S_EXEC="server --cluster-init ${server_flags[*]}"
    else
      if ! non_empty "${SERVER_URL:-}" || ! non_empty "${TOKEN:-}"; then
        err "SERVER_URL and TOKEN are required to join a server."
        exit 1
      fi
      export K3S_URL="${SERVER_URL}"
      export K3S_TOKEN="${TOKEN}"
      export INSTALL_K3S_EXEC="server ${server_flags[*]}"
    fi

    curl -sfL "${K3S_INSTALL_SH_URL}" | sh -s -
    systemctl enable --now k3s

  else
    # agent
    ask_value "Server URL (e.g. https://10.0.0.10:6443)" SERVER_URL "${SERVER_URL:-}"
    ask_value "Shared cluster TOKEN" TOKEN "${TOKEN:-}"

    agent_flags=()
    add_flag_if_set NODE_IP --node-ip agent_flags

    log "Summary:
    Role:         agent
    K3s version:  ${K3S_VERSION:-(default latest)}
    Server URL:   ${SERVER_URL}
    Token set:    $( [ -n "${TOKEN:-}" ] && echo yes || echo no )
    NODE_IP:      ${NODE_IP:-auto}
"
    if ! confirm "Proceed with k3s installation?"; then
      warn "Skipping k3s install."
      return 0
    fi

    log "Preparing /root/cluster.env..."
    cat >/root/cluster.env <<EOF
# Saved by k3s-node-setup.sh on $(date -Iseconds)
ROLE=agent
HOSTNAME=${HOSTNAME:-$(hostname)}
TZ=${TZ:-$(timedatectl show -p Timezone --value || echo Europe/Amsterdam)}
K3S_VERSION=${K3S_VERSION:-}
NODE_IP=${NODE_IP:-}
SERVER_URL=${SERVER_URL:-}
TOKEN=${TOKEN:-}
EOF
    chmod 600 /root/cluster.env

    K3S_INSTALL_SH_URL="https://get.k3s.io"
    export INSTALL_K3S_VERSION="${K3S_VERSION:-}"
    if ! non_empty "${SERVER_URL:-}" || ! non_empty "${TOKEN:-}"; then
      err "SERVER_URL and TOKEN are required for agent."
      exit 1
    fi
    export K3S_URL="${SERVER_URL}"
    export K3S_TOKEN="${TOKEN}"
    export INSTALL_K3S_EXEC="agent ${agent_flags[*]}"
    curl -sfL "${K3S_INSTALL_SH_URL}" | sh -s -
    systemctl enable --now k3s-agent
  fi

  log "k3s installed. Kubectl: /usr/local/bin/kubectl (symlink via k3s)"
  if [ "${ROLE}" = "server" ]; then
    log "Kubeconfig: /etc/rancher/k3s/k3s.yaml"
    dest_user="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
    dest_home="$(getent passwd "$dest_user" | cut -d: -f6)"
    [ -z "$dest_home" ] && dest_home="/root"
    log "Tip: mkdir -p ${dest_home}/.kube && sudo cp /etc/rancher/k3s/k3s.yaml ${dest_home}/.kube/config && sudo chown ${dest_user}:${dest_user} ${dest_home}/.kube/config"
  fi

  if [ "${ROLE}" = "server" ] && [ "${CLUSTER_INIT}" = "true" ]; then

    ask_value "External HTTPS port to expose (e.g. 443 or 8443)" EXTERNAL_HTTPS_PORT "8443"
    EXTERNAL_HTTP_PORT="${EXTERNAL_HTTP_PORT:-off}" \
    EXTERNAL_HTTPS_PORT="${EXTERNAL_HTTPS_PORT}" \
    EXTERNAL_TLS="${EXTERNAL_TLS:-true}" \
    install_ingress_nginx

    install_longhorn
    ensure_db_creds
    install_timescaledb_ha data longhorn
    install_redis_sentinel  data longhorn

    # Generate + apply minimal BNS env (tokens/passwords), then deploy
    apply_bns_minimal_config
    deploy_blueraven
  fi

  cat <<EONOTE

Next steps (HA control-plane):
1) First server (if not done (should be at this point)):
     sudo ROLE=server CLUSTER_INIT=true ./k3s-node-setup.sh --yes PHASE=k3s
   Get join token:
     sudo cat /var/lib/rancher/k3s/server/node-token

2) Join servers:
     sudo ROLE=server CLUSTER_INIT=false SERVER_URL=https://<API-VIP>:6443 TOKEN=<token> ./k3s-node-setup.sh --yes PHASE=k3s

3) Join agents:
     sudo ROLE=agent SERVER_URL=https://<API-VIP>:6443 TOKEN=<token> ./k3s-node-setup.sh --yes PHASE=k3s

VIP/Ingress:
- kube-vip provides the API VIP; ingress-nginx binds your chosen hostPorts on each node (e.g., HTTPS on ${EXTERNAL_HTTPS_PORT}, HTTP ${EXTERNAL_HTTP_PORT:-off}) — no extra IPs.

Storage:
- Longhorn requires iSCSI (already enabled). Consider a dedicated disk at /var/lib/longhorn.

Uninstall:
  /usr/local/bin/k3s-uninstall.sh       # server
  /usr/local/bin/k3s-agent-uninstall.sh # agent
EONOTE
}

################################
# Template Prep (optional)
################################
template_prep() {
  log "=== TEMPLATE PREP (generalize VM) ==="
  if ! confirm "Proceed to scrub machine-specific IDs/keys/logs for cloning?"; then
    warn "Skipping template prep."
    return 0
  fi

  # Stop time sync to avoid noisy logs during cleanup
  systemctl stop chrony 2>/dev/null || true

  # Remove SSH host keys (will regenerate on next boot)
  rm -f /etc/ssh/ssh_host_* 2>/dev/null || true

  # Reset machine-id (systemd)
  : > /etc/machine-id
  rm -f /var/lib/dbus/machine-id 2>/dev/null || true
  ln -sf /etc/machine-id /var/lib/dbus/machine-id

  # Clean logs
  journalctl --rotate 2>/dev/null || true
  journalctl --vacuum-time=1s 2>/dev/null || true
  find /var/log -type f -exec truncate -s 0 {} \; || true

  # Clean DHCP leases
  rm -f /var/lib/NetworkManager/*lease* 2>/dev/null || true
  rm -f /var/lib/dhcp/* 2>/dev/null || true

  # Bash histories
  history -c || true
  rm -f /root/.bash_history 2>/dev/null || true
  if [ -n "${SUDO_USER:-}" ]; then
    rm -f "/home/${SUDO_USER}/.bash_history" 2>/dev/null || true
  fi

  # APT cleanup (keeps packages, drops caches)
  apt-get -y autoremove --purge || true
  apt-get -y clean || true
  rm -rf /var/lib/apt/lists/* 2>/dev/null || true

  # Fresh entropy seed; will be recreated on next boot
  rm -f /var/lib/systemd/random-seed 2>/dev/null || true

  # Cloud-init not used here, but if present, clean it
  if dpkg -s cloud-init >/dev/null 2>&1; then
    cloud-init clean --logs || true
  fi

  cat >/etc/systemd/system/ssh-regenerate-keys.service <<'EOF'
[Unit]
Description=Regenerate SSH host keys if missing
ConditionPathExistsGlob=!/etc/ssh/ssh_host_*_key

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A

[Install]
WantedBy=multi-user.target
EOF
  systemctl enable ssh-regenerate-keys.service

  log "Template prep complete. Shutdown and convert this VM into a template/clone."
}

################################
# Execute requested phases
################################
case "$PHASE" in
  base)
    base_prep
    ;;
  k3s)
    k3s_install
    ;;
  all)
    base_prep
    k3s_install
    ;;
  *)
    err "Unknown PHASE: $PHASE (use base|k3s|all)"
    exit 2
    ;;
esac

# Optional generalization (runs after the selected phase)
if [ "${TEMPLATE_PREP,,}" = "true" ]; then
  template_prep
fi

# Optional follow-on after base-only run
if [ "${RUN_K3S_AFTER_BASE:-false}" = "true" ] && [ "$PHASE" = "base" ] && [ "${TEMPLATE_PREP,,}" != "true" ]; then
  k3s_install
fi

log "Done."
