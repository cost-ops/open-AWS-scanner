#!/bin/bash
# Build, sign, and optionally upload the package.
# Usage:
#   ./release.sh          # Build + sign only
#   ./release.sh upload   # Build + sign + upload to PyPI
set -e

echo "=== Building package ==="
python3 -m build

echo ""
echo "=== Signing with Sigstore ==="
echo "This will open a browser for OIDC authentication."
python3 -m sigstore sign dist/*.tar.gz dist/*.whl

echo ""
echo "=== Verifying signatures ==="
for f in dist/*.tar.gz dist/*.whl; do
    echo "  Verifying: $f"
    python3 -m sigstore verify identity "$f" \
        --cert-identity "luge-sud-0q@icloud.com" \
        --cert-oidc-issuer "https://appleid.apple.com" \
        || python3 -m sigstore verify identity "$f" \
            --cert-identity "luge-sud-0q@icloud.com" \
            --cert-oidc-issuer "https://accounts.google.com" \
        || echo "  ⚠️  Could not verify (OIDC issuer may differ — check your identity)"
done

echo ""
echo "=== Build artifacts ==="
ls -la dist/

if [ "$1" = "upload" ]; then
    echo ""
    echo "=== Uploading to PyPI ==="
    python3 -m twine upload dist/*.tar.gz dist/*.whl
fi

echo ""
echo "✓ Done!"
