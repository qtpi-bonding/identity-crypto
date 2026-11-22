#!/usr/bin/env bash
set -euo pipefail

SLOT="${CARGO_SLOT:-$(command -v cargo-slot || true)}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== step 1: fmt check"
$SLOT cargo fmt --all -- --check

echo "== step 2: clippy all-features"
$SLOT cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "== step 3: clippy no-default-features"
$SLOT cargo clippy --workspace --all-targets --no-default-features -- -D warnings

echo "== step 4: test workspace all-features"
$SLOT cargo test --workspace --all-features

echo "== step 5: per-crate tests"
$SLOT cargo test -p identity-crypto
$SLOT cargo test -p identity-keyfile
$SLOT cargo test -p identity-request-auth
$SLOT cargo test -p identity-request-auth --features tonic
$SLOT cargo test -p identity-request-auth --features client

echo "== step 6: doc tests (compile_fail docs)"
$SLOT cargo test --doc --workspace --all-features

echo "== step 7: purity (no tokio in identity-crypto; no fs/time outside clock.rs)"
if $SLOT cargo tree -p identity-crypto -e normal -i tokio >/dev/null 2>&1; then
  echo "FAIL: tokio is a normal dependency of identity-crypto" >&2
  exit 1
fi
hits="$(grep -rn 'std::fs\|SystemTime' src/ | grep -v '^src/clock.rs' || true)"
if [ -n "$hits" ]; then
  echo "$hits" >&2
  echo "FAIL: std::fs or SystemTime used outside src/clock.rs" >&2
  exit 1
fi
echo "purity OK"

echo "== step 8: the environment is read only in machine.rs"
# The error texts and the lib.rs re-export may name the variable; nothing but machine.rs may read it.
hits="$(grep -rln 'env::var' identity-keyfile/src | grep -v 'machine.rs' || true)"
if [ -n "$hits" ]; then
  echo "$hits" >&2
  echo "FAIL: the environment is read outside machine.rs" >&2
  exit 1
fi
echo "machine dir OK"

echo "== step 9: identity-keyfile must not depend on coded-error"
if $SLOT cargo tree -p identity-keyfile -e normal -i coded-error >/dev/null 2>&1; then
  echo "FAIL: identity-keyfile depends on coded-error" >&2
  exit 1
fi
echo "keyfile coded-error free OK"

echo "== step 10: coded-error must not be duplicated in identity-request-auth"
tree_out="$($SLOT cargo tree -p identity-request-auth --all-features -e normal -d)"
echo "$tree_out"
count="$(printf '%s\n' "$tree_out" | grep -c '^coded-error v' || true)"
if [ "$count" -gt 1 ]; then
  echo "FAIL: coded-error appears $count times" >&2
  exit 1
fi
echo "coded-error duplicates OK"

echo "== step 11: identity-request-signer tests and no service names"
$SLOT cargo test -p identity-request-signer
w1="gr""org"; w2="multi""matrix"; w3="access""-control"
if grep -rniE "$w1|$w2|$w3" identity-request-signer/src identity-request-signer/Cargo.toml; then
  echo "FAIL: a service name or access-control appears in identity-request-signer" >&2
  exit 1
fi
echo "signer clean OK"

echo "== all checks passed"
