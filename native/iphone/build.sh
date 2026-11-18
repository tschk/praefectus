#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
# Mac satellites mirror the worktree without .git.
if [[ ! -f "$root/native/iphone/Cargo.toml" ]]; then
    printf '%s\n' 'Run from the Praefectus repository root.' >&2
    exit 2
fi
target="${1:-aarch64-apple-ios-sim}"
case "$target" in
    aarch64-apple-ios-sim) sdk=iphonesimulator; destination='generic/platform=iOS Simulator' ;;
    aarch64-apple-ios) sdk=iphoneos; destination='generic/platform=iOS' ;;
    *) printf '%s\n' 'Expected aarch64-apple-ios-sim or aarch64-apple-ios' >&2; exit 2 ;;
esac
rustup target add "$target"
cargo build --locked --package praefectus-iphone-host --target "$target" --target-dir "$root/target"
xcodebuild -project "$root/native/iphone/PraefectusPhone.xcodeproj" -scheme PraefectusPhone \
    -configuration Debug -sdk "$sdk" -destination "$destination" \
    -derivedDataPath "$root/target/iphone-xcode" \
    PRAEFECTUS_RUST_LIB_DIR="$root/target/$target/debug" CODE_SIGNING_ALLOWED=NO build
