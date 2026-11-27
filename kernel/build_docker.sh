#!/usr/bin/env bash
set -euo pipefail

KERNEL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$KERNEL_DIR")"
MODULE_DIR="$REPO_ROOT/module"
KO_INSTALL_DIR="$MODULE_DIR/ko"

DEFAULT_KMIS=(
    android12-5.10
    android13-5.10
    android13-5.15
    android14-5.15
    android14-6.1
    android15-6.6
    android16-6.12
    android17-6.18
)

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "Usage: $(basename "$0") [KMI ...]"
    echo "Example: $(basename "$0") android16-6.12"
    echo "Env overrides:"
    echo "  DDK_IMAGE_REPO  Image prefix (default: ghcr.io/ylarod/ddk)"
    echo "  DDK_IMAGE       Exact image tag for single-KMI build"
    exit 0
fi

if [[ "$#" -gt 0 ]]; then
    KMIS=("$@")
else
    KMIS=("${DEFAULT_KMIS[@]}")
fi


DDK_IMAGE_REPO="${DDK_IMAGE_REPO:-ghcr.io/ylarod/ddk}"

if [[ -n "${DDK_IMAGE:-}" && "${#KMIS[@]}" -gt 1 ]]; then
    echo "Error: DDK_IMAGE can only be used when building a single KMI." >&2
    exit 1
fi

rm -rf "$KO_INSTALL_DIR"
mkdir -p "$KO_INSTALL_DIR"

for kmi in "${KMIS[@]}"; do
    if [[ ! "$kmi" =~ ^android[0-9]+-[0-9]+\.[0-9]+$ ]]; then
        echo "Error: invalid KMI '$kmi' (expected format like android16-6.12)" >&2
        exit 1
    fi

    image="${DDK_IMAGE:-${DDK_IMAGE_REPO}:${kmi}}"
    echo "==> Building for $kmi using $image"

    docker run --rm \
        -u "$(id -u):$(id -g)" \
        -v "$REPO_ROOT:/work" \
        -w /work/kernel \
        "$image" \
        /bin/sh -ec "
            export KDIR=\"\$KERNEL_SRC\"
            make -f Makefile.ddk clean
            make -f Makefile.ddk modules
            llvm-strip -d fgetpriority.ko
            cp fgetpriority.ko \"/work/module/ko/${kmi}_arm64_fgetpriority.ko\"
            make -f Makefile.ddk clean
        "
done

if command -v zip >/dev/null 2>&1; then
    cd "$MODULE_DIR"
    VERSION="$(grep '^version=' module.prop | cut -d= -f2)"
    rm -f fgetpriority*.zip
    zip -r "fgetpriority_${VERSION}.zip" ./*
    echo "==> Packaged: $MODULE_DIR/fgetpriority_${VERSION}.zip"
else
    echo "==> Built .ko files in $KO_INSTALL_DIR (install 'zip' to package module archive)"
fi
