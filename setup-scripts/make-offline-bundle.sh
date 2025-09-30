#!/usr/bin/env bash
# make-offline-bundle.sh
# Usage: ./make-offline-bundle.sh v1.30.4+k3s1
set -euo pipefail

K3S_VER="${1:?k3s version required, e.g. v1.30.4+k3s1}"
ARCH="amd64" # change to arm64 if needed
OUT="k3s-offline-${K3S_VER}-${ARCH}.tar.gz"
WORK="$(mktemp -d)"

echo "[*] Download k3s binary and core images"
curl -fL -o "${WORK}/k3s" "https://github.com/k3s-io/k3s/releases/download/${K3S_VER}/k3s"
chmod +x "${WORK}/k3s"
curl -fL -o "${WORK}/k3s-images-${ARCH}.tar" \
  "https://github.com/k3s-io/k3s/releases/download/${K3S_VER}/k3s-images-${ARCH}.tar"

# Add-on images you plan to use (examples):
IMAGES=(
  # kube-vip + MetalLB (adjust versions as you standardize)
  "ghcr.io/kube-vip/kube-vip:v0.8.4"
  "quay.io/metallb/controller:v0.14.8"
  "quay.io/metallb/speaker:v0.14.8"
  # Longhorn (examples; pin your versions)
  "longhornio/longhorn-manager:v1.6.2"
  "longhornio/longhorn-engine:v1.6.2"
  "longhornio/longhorn-instance-manager:v1.6.2"
  "longhornio/longhorn-share-manager:v1.6.2"
  "longhornio/longhorn-ui:v1.6.2"
  # Ingress (pick one; k3s Traefik is disabled in your script)
  # "registry.k8s.io/ingress-nginx/controller:v1.11.2"
)

echo "[*] Pull & save addon images"
mkdir -p "${WORK}/addons"
docker pull --quiet busybox:stable || true # ensure docker works
docker rmi busybox:stable || true

# Save all images to a single tar (k3s will import any *.tar in images dir)
docker pull "${IMAGES[@]}"
docker save -o "${WORK}/addons/addon-images.tar" "${IMAGES[@]}"

# Manifests to auto-apply (server-only): put them in this folder
mkdir -p "${WORK}/server-manifests"

# kube-vip static pod example (ARP VIP on control-plane)
cat > "${WORK}/server-manifests/kube-vip.yaml" <<'EOF'
# Fill this with your pinned kube-vip DaemonSet/Manifest with your VIP and iface.
# Keep image tag identical to one saved above.
EOF

# MetalLB example (CRDs + controller/speaker). Pin versions and images.
cat > "${WORK}/server-manifests/metallb.yaml" <<'EOF'
# Fill this with your pinned MetalLB manifests + an IPAddressPool + L2Advertisement.
EOF

# Longhorn example: you can vendor their airgap manifests or Helm template output.
cat > "${WORK}/server-manifests/longhorn.yaml" <<'EOF'
# Fill with Longhorn offline install manifests (images must match addon-images.tar)
EOF

# Bundle it all
tar -C "${WORK}" -czf "${OUT}" \
  k3s \
  "k3s-images-${ARCH}.tar" \
  addons \
  server-manifests

echo "[*] Wrote ${OUT}"
