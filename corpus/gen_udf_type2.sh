#!/usr/bin/env bash
# Generate real Type 2 UDF test images with mkudffs (udftools) on Linux.
# These are PURE UDF (no ISO 9660 bridge) — the real-world BD / packet-CD case.
# Output: udf_vat.img (Virtual/VAT, NSR02), udf_spar.img (Sparable, NSR03).
# Run on Linux, or via: podman run --rm -v "$PWD":/out debian:stable-slim bash gen_udf_type2.sh
set -e
export DEBIAN_FRONTEND=noninteractive
command -v mkudffs >/dev/null || { apt-get update -qq && apt-get install -y -qq udftools; }
# media-type MUST precede udfrev. Virtual partition + VAT (write-once optical):
dd if=/dev/zero of=udf_vat.img  bs=2048 count=16384 status=none
mkudffs --media-type=cdr   --udfrev=1.50 udf_vat.img
# Sparable partition (rewritable optical, defect management):
dd if=/dev/zero of=udf_spar.img bs=2048 count=16384 status=none
mkudffs --media-type=dvdrw --udfrev=2.01 udf_spar.img
# NOTE: mkudffs does NOT produce a Metadata partition (UDF 2.50+); a real
# Blu-ray data image or Windows-authored UDF 2.50 disc is required for that.
echo "generated udf_vat.img (Virtual/VAT) + udf_spar.img (Sparable)"
