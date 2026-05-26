#!/usr/bin/env bash
set -euo pipefail

crate_wasm="target/wasm32-unknown-unknown/wasm-speed/fedi_credential_sdk_wasm.wasm"
bindgen_version="$(awk '
  $0 == "[[package]]" { in_package = 1; name = ""; version = ""; next }
  in_package && $1 == "name" && $3 == "\"wasm-bindgen\"" { name = "wasm-bindgen"; next }
  in_package && $1 == "version" { gsub(/"/, "", $3); version = $3; next }
  in_package && name == "wasm-bindgen" && version != "" { print version; exit }
' Cargo.lock)"

find_wasm_bindgen() {
  local cache_dir
  for cache_dir in \
    "${WASM_PACK_CACHE:-}" \
    "${XDG_CACHE_HOME:-}/.wasm-pack" \
    "$HOME/Library/Caches/.wasm-pack" \
    "$HOME/.cache/.wasm-pack"
  do
    [[ -n "$cache_dir" ]] || continue

    if [[ -x "$cache_dir/wasm-bindgen-cargo-install-$bindgen_version/wasm-bindgen" ]]; then
      printf '%s\n' "$cache_dir/wasm-bindgen-cargo-install-$bindgen_version/wasm-bindgen"
      return 0
    fi
  done

  return 1
}

rm -rf pkg

wasm-pack build crates/wasm --scope fedibtc --target bundler --out-dir ../../pkg --no-opt
cargo build -p fedi-credential-sdk-wasm --target wasm32-unknown-unknown --profile wasm-speed

if ! wasm_bindgen="$(find_wasm_bindgen)"; then
  echo "Could not find wasm-bindgen $bindgen_version in the wasm-pack cache." >&2
  exit 1
fi

"$wasm_bindgen" "$crate_wasm" --target bundler --typescript --out-dir pkg --out-name fedi_credential_sdk_wasm
wasm-opt -O3 -o pkg/fedi_credential_sdk_wasm_bg.wasm pkg/fedi_credential_sdk_wasm_bg.wasm

rm -f pkg/.gitignore
pnpm run format:pkg
