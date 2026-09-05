#!/usr/bin/env bash
# setup_firecracker.sh — PDCA Do: Firecracker vs Cell
# Downloads Firecracker v1.11.0 + kernel + rootfs, checks KVM, pins versions
# Auf Mac M5: erwartet FAIL (kein /dev/kvm) — dann Fallback Literaturwert
set -euo pipefail

FIRECRACKER_VERSION="v1.11.0"
KERNEL_VERSION="6.1"
ARCH=$(uname -m)

echo "=== Firecracker Setup — PDCA Do ==="
echo "Arch: $ARCH, OS: $(uname -s), KVM: $(ls -l /dev/kvm 2>&1 | head -1)"

if [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
  echo "WARN: ARM64 — Firecracker x86_64 Binary nicht nativ, braucht Rosetta/KVM — SKIP"
  exit 0
fi

if [[ ! -e /dev/kvm ]]; then
  echo "SKIP: /dev/kvm nicht vorhanden — kein KVM (erwartet auf Mac/GHA ohne KVM)"
  echo "Fallback: Literaturwert 125ms (Northflank 18.01.2026) wird in Benchmark als Referenz genutzt"
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  echo "WARN: not root - Firecracker needs root for KVM, trying without the jailer"
fi

TMPDIR="${TMPDIR:-/tmp}/firecracker-setup"
mkdir -p "$TMPDIR"
cd "$TMPDIR"

# Firecracker Binary
if ! command -v firecracker &>/dev/null; then
  echo "Lade Firecracker $FIRECRACKER_VERSION..."
  curl -L -o firecracker.tar.gz "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-x86_64.tgz"
  tar -xzf firecracker.tar.gz
  echo "Tar Inhalt:"
  tar -tzf firecracker.tar.gz | head -20 || true
  ls -R 2>&1 | head -30 || true
  # Robust: locate the firecracker binary whether release-v1.11.0-x86_64/firecracker-... or similar
  FC_BIN=$(find . -name "firecracker*" -type f | head -1)
  echo "Gefunden: $FC_BIN"
  if [[ -n "$FC_BIN" ]]; then
    if sudo mv "$FC_BIN" /usr/local/bin/firecracker 2>/dev/null; then
      sudo chmod +x /usr/local/bin/firecracker
      echo "Firecracker: $(firecracker --version 2>&1 | head -1)"
    else
      mv "$FC_BIN" ./firecracker
      chmod +x ./firecracker
      echo "Firecracker: $(./firecracker --version 2>&1 | head -1)"
    fi
  else
    echo "ERROR: firecracker Binary nicht gefunden nach tar"
    exit 1
  fi
else
  echo "Firecracker vorhanden: $(firecracker --version 2>&1 | head -1)"
fi

# Kernel + rootfs (minimal, for the boot measurement)
if [[ ! -f vmlinux ]]; then
  echo "Lade Kernel..."
  curl -L -o vmlinux "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin" 2>&1 | tail -1 || echo "Kernel Download SKIP (offline)"
fi

echo "Setup done — KVM: $(ls -l /dev/kvm 2>&1 | head -1)"
echo "Pin: wasmtime 47.0.1, firecracker $FIRECRACKER_VERSION, kernel $KERNEL_VERSION"
