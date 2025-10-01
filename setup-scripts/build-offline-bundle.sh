#!/usr/bin/env bash
set -euo pipefail

# --------- Versions / knobs (pin these for reproducibility) ----------
# k3s
K3S_VERSION="${K3S_VERSION:-v1.30.4+k3s1}"
K3S_ARCH="${K3S_ARCH:-amd64}"   # amd64 | arm64

# Helm charts
INGRESS_NGINX_CHART="${INGRESS_NGINX_CHART:-4.10.0}"
LONGHORN_CHART="${LONGHORN_CHART:-1.6.1}"
TIMESCALE_SINGLE_CHART="${TIMESCALE_SINGLE_CHART:-0.22.0}"   # example
BITNAMI_REDIS_CHART="${BITNAMI_REDIS_CHART:-19.5.3}"        # example

# Ingress external ports (these are baked in the rendered manifests)
EXTERNAL_HTTP_PORT="${EXTERNAL_HTTP_PORT:-off}"   # off to disable, else 80/… 
EXTERNAL_HTTPS_PORT="${EXTERNAL_HTTPS_PORT:-8443}"
EXTERNAL_TLS="${EXTERNAL_TLS:-true}"              # true|false

# Timescale initial credentials (match your script’s defaults)
POSTGRES_USER="${POSTGRES_USER:-bns_admin}"
POSTGRES_DB="${POSTGRES_DB:-bns}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(openssl rand -base64 32 | tr -d '\n' | cut -c1-32)}"

# Redis config (match your script)
REDIS_PASSWORD="${REDIS_PASSWORD:-$(openssl rand -base64 32 | tr -d '\n' | cut -c1-32)}"
REDIS_MASTER_SET="${REDIS_MASTER_SET:-mymaster}"

# Output roots (copy these to your template VM at the same paths)
ROOT="${ROOT:-./offline_out}"
MANIFESTS_DIR="${ROOT}/opt/manifests"
IMAGES_DIR="${ROOT}/var/lib/rancher/k3s/agent/images"
BIN_DIR="${ROOT}/usr/local/bin"

mkdir -p "${MANIFESTS_DIR}"/{ingress-nginx,longhorn,timescaledb,redis} \
         "${IMAGES_DIR}" "${BIN_DIR}"

# --------- Requirements on builder ----------
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing '$1'"; exit 1; }; }
need helm; need yq; need docker; need curl

echo "[*] Helm repos: add/update"
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null
helm repo add longhorn https://charts.longhorn.io >/dev/null
helm repo add timescale https://charts.timescale.com >/dev/null
helm repo add bitnami https://charts.bitnami.com/bitnami >/dev/null
helm repo update >/dev/null

# --------- 1) Render OFFLINE MANIFESTS ----------
echo "[*] Rendering ingress-nginx manifests"
ING_ARGS=(
  --namespace ingress-nginx
  --version "${INGRESS_NGINX_CHART}"
  --set controller.kind=DaemonSet
  --set controller.hostNetwork=false
  --set controller.hostPort.enabled=true
  --set controller.service.type=ClusterIP
  --set controller.metrics.enabled=true
)
if [ "${EXTERNAL_HTTP_PORT}" = "off" ]; then
  ING_ARGS+=(--set controller.enableHttp=false)
else
  ING_ARGS+=(--set controller.hostPort.http="${EXTERNAL_HTTP_PORT}")
fi
if [ "${EXTERNAL_TLS}" = "true" ]; then
  ING_ARGS+=(--set controller.hostPort.https="${EXTERNAL_HTTPS_PORT}")
else
  ING_ARGS+=(--set controller.enableHttps=false)
fi
helm template ingress-nginx ingress-nginx/ingress-nginx "${ING_ARGS[@]}" \
  > "${MANIFESTS_DIR}/ingress-nginx/all.yaml"

echo "[*] Rendering Longhorn manifests"
helm template longhorn longhorn/longhorn \
  --namespace longhorn-system \
  --version "${LONGHORN_CHART}" \
  > "${MANIFESTS_DIR}/longhorn/all.yaml"

echo "[*] Rendering TimescaleDB Single manifests"
helm template tsdb timescale/timescaledb-single \
  --namespace data \
  --version "${TIMESCALE_SINGLE_CHART}" \
  --set replicaCount=3 \
  --set storageClass=longhorn \
  --set volumePermissions.enabled=true \
  --set resources.requests.cpu=500m \
  --set resources.requests.memory=1Gi \
  --set credentials.username="${POSTGRES_USER}" \
  --set credentials.password="${POSTGRES_PASSWORD}" \
  --set credentials.database="${POSTGRES_DB}" \
  > "${MANIFESTS_DIR}/timescaledb/all.yaml"

echo "[*] Rendering Redis (replication + Sentinel) manifests"
helm template redis bitnami/redis \
  --namespace data \
  --version "${BITNAMI_REDIS_CHART}" \
  --set architecture=replication \
  --set replica.replicaCount=2 \
  --set sentinel.enabled=true \
  --set sentinel.usePassword=true \
  --set sentinel.masterSet="${REDIS_MASTER_SET}" \
  --set auth.password="${REDIS_PASSWORD}" \
  --set master.persistence.size=10Gi \
  --set replica.persistence.size=10Gi \
  --set master.persistence.storageClass=longhorn \
  --set replica.persistence.storageClass=longhorn \
  > "${MANIFESTS_DIR}/redis/all.yaml"

# --------- 2) Collect image refs from the manifests ----------
echo "[*] Collecting image references from manifests"
collect_images() {
  local file="$1"
  yq -r '
    .. | select(
      has("template") and .template? and .template.spec?
    ) | [
      (.template.spec.initContainers // [] | .[].image?),
      (.template.spec.containers     // [] | .[].image?)
    ] | flatten | .[]' "$file" 2>/dev/null || true
}

IMAGELIST="${ROOT}/imagelist.txt"
: > "${IMAGELIST}"
for f in "${MANIFESTS_DIR}"/**/*.yaml; do
  collect_images "$f" >> "${IMAGELIST}" || true
done
# + You likely also need the BlueRaven app image:
echo "docker.allroundcustoms.nl/blueraven-network-server:latest" >> "${IMAGELIST}"

# De-duplicate and normalize
sort -u -o "${IMAGELIST}" "${IMAGELIST}"
echo "[*] Will pull/save $(wc -l < "${IMAGELIST}") image(s)"

# --------- 3) Pull & save images into K3s-importable tars ----------
# Strategy: one big tar (simplest). If you prefer per-component, split by folder.
BUNDLE_TAR="${IMAGES_DIR}/bundle-images-$(date +%Y%m%d-%H%M%S).tar"
echo "[*] Pulling images with Docker"
while read -r img; do
  [ -z "$img" ] && continue
  echo "  - $img"
  docker pull "$img"
done < "${IMAGELIST}"

echo "[*] Saving images into ${BUNDLE_TAR}"
docker save -o "${BUNDLE_TAR}" $(tr '\n' ' ' < "${IMAGELIST}")

# --------- 4) k3s airgap bits ----------
echo "[*] Downloading k3s binary and airgap images"
# Binary
curl -fsSL -o "${BIN_DIR}/k3s" "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}/k3s"
chmod +x "${BIN_DIR}/k3s"

# Airgap images tar (arch specific)
K3S_IMAGES_TAR="${IMAGES_DIR}/k3s-airgap-images-${K3S_ARCH}.tar"
curl -fsSL -o "${K3S_IMAGES_TAR}" \
  "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}/k3s-airgap-images-${K3S_ARCH}.tar"

echo
echo "================== DONE =================="
echo "Copy the following directories to the VM template at the SAME paths:"
echo "  ${ROOT}/opt        -> /opt"
echo "  ${ROOT}/usr        -> /usr"
echo "  ${ROOT}/var        -> /var"
echo
echo "Then run your installer with: OFFLINE_MODE=true ..."
