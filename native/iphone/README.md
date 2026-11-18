# iPhone reference host

This experimental app embeds Praefectus's Rust engine and CoreDevice executor on the iPhone. **The existing-record device connection is disabled pending authenticated RemotePairing support.** The code below describes implemented operations and intended setup, not working phone control in this revision. Neither the on-phone nor computer-assisted constructor can establish an operational device session. It is not a release-ready standalone controller.

The imported [idevice pair-verify flow](https://github.com/jkcoxson/idevice/blob/d32c8189c51c2789496b0768039419c3705498c3/idevice/src/remote_pairing/mod.rs) derives a key from the peer's ephemeral key and authenticates the host, but does not verify the device's identity. Its stored `public_key` is the host key, not a trusted device key. Praefectus now refuses this flow before sending pairing messages or exposing session keys. An independently verified device-authentication contract and trusted identity material are required before restoring it. No speculative HomeKit proof format or invented credential field substitutes for that work.

The library remains ISC. Device services use MIT-licensed `idevice` 0.1.68. The adapted MIT RemotePairing client in `src/iphone_transport` uses cryptographic traits directly and does not resolve RSA. Its full notice and repeatable import script are retained. No Poki source or patches are included.

## Implemented operations

The optional `iphone` library feature provides `IphoneConfig`, `IphoneExecutor`, `IphoneSession`, and `IphoneScreen`.

| Operation | Implementation and limits |
| --- | --- |
| Session discovery | Authenticated Remote Service Discovery; one explicitly configured device, not a USB or Bonjour device scanner. |
| App discovery | Installed bundle identifiers through CoreDevice AppService. |
| Screen observation | PNG through CoreDevice ScreenCaptureService; decoded pixels and geometry fence the screenshot. No accessibility tree. |
| Tap | One left-button click mapped to a touch. |
| Swipe | Left-button drag between two coordinates from the same screenshot. |
| Scroll | One directional swipe, amount 1, in any of four directions. Edge coordinates can produce a shorter gesture. |
| Keys | One Home, Return, Backspace, or Escape. No arbitrary hotkeys. |
| Text | Paste or `type_text` through the device clipboard and Command-V. Replaces clipboard contents. No clear or typing delay. Optional Return is supported by the library. |
| App navigation | Launch a bundle identifier, or Home. No app installation, force quit, or window management. |

The reference UI exposes Tap, Swipe, Scroll down, Paste text, Home, and Launch app. Other implemented variants are library APIs. Discovery reports counts in the reference UI; the library returns the identifiers.

Capabilities reflect advertised services, not proof that those services accept input. The native HID path needs a DisplayService media session and compatible CoreDevice services. There is no XCTest fallback. Older iOS versions that lack these services are unsupported for this input path. No iOS version has been physically validated for this implementation.

## Authority and execution

The Swift host stores its Ed25519 signing key and imported device pairing record in the device-only Keychain. Connecting enables a 15-minute local execution session. **Confirm each action** is off by default and can be enabled for an additional confirmation dialog. The UI still requires you to submit each operation; it is not an autonomous planner.

Swift automatically signs each submitted proposal within the active lease. Every grant expires within 15 seconds and no later than the lease. Rust receives only the pinned public key and signed request. Reconnection creates a new session identity and rejects old-session requests. **Stop and revoke**, app termination, or lease expiry prevents further input under that session. Background-task expiry also revokes the session. Stop cannot undo an effect already dispatched. The ordinary `Engine` still verifies every grant and owns durable at-most-once dispatch. Neither pairing nor host authority configuration is a model action parameter. Other library hosts retain their own approval policy; the engine does not default to auto-authorization.

Input requires the latest screenshot, captured within 30 seconds. The executor rechecks device-bound geometry, decoded pixel content, snapshot identity, and coordinate bounds before dispatch. Swipe endpoints share the same fence. Full-screen changes, including clocks and animations, can invalidate a target. Screen comparisons are boundary checks, not a guarantee that the display cannot change during input.

Input uses the shared device's global pointer route. `background_only` and the global-input restriction refuse it. The reference app uses interactive requests with no outcome verification. Successful delivery is `executed_unverified`, not proof that the intended app effect occurred. Transport interruption after a possible effect is `outcome_unknown`; inspect the phone before any retry. Stream setup itself can have an effect, so its failures are also conservatively unknown. Reconnect after a broken session.

Screenshot bytes stay out of requests, receipts, and ledgers. The app writes its latest image to an app-private file. Hosts must protect this file and the operation ledger. Do not enable verbose `idevice` tracing: upstream debug logging can contain pairing and protocol material.

## Required setup

1. Build and sign the app using your own Apple developer configuration. A computer is needed for initial installation and may be needed again for signing renewal. Nothing here depends on the user's laptop being online during execution.
2. Enable Developer Mode and mount the compatible developer disk image using authorized developer tooling. This app does not download, personalize, or mount developer images.
3. Obtain a real **RemotePairing** record for this phone and import its plist through the app. Traditional lockdown plists are not accepted. The app does not create pairing records or automatically fall back to new pairing. A computer-created record is not guaranteed to authenticate a self-connection on newer iOS versions.
4. Install and enable a separately supplied, trusted loopback VPN that routes `10.7.0.1` back to this iPhone, including dynamic developer-service ports. Praefectus does not bundle a Network Extension or VPN. VPN connectivity alone does not prove developer-service connectivity.
5. Supply the actual RemotePairing port. The UI starts with 49152, but this port can change. Automatic Bonjour port discovery is not implemented.
6. Connect, discover, and observe. Observation and input wait three seconds so you can switch to the target app. Return to submit an action, then switch back. The target screen must still match the observation.

The app requests only a finite UIKit background task for one operation. iOS may suspend or terminate it. There is no persistent background daemon, relay, autonomous planner, signing renewal, or unattended-lifetime guarantee. Device unlock, automation consent, service availability, VPN behavior, and developer-image state still require owner setup and physical testing.

## Build and check

Run from the repository root on an Apple Silicon Mac with Xcode and Rust installed:

```sh
bash native/iphone/build.sh aarch64-apple-ios-sim
bash native/iphone/build.sh aarch64-apple-ios
```

Both commands build **unsigned** apps. `build.sh` does not install or upload them. For installation, open `PraefectusPhone.xcodeproj`, set your team and a unique bundle identifier, and supply `PRAEFECTUS_RUST_LIB_DIR` pointing to the corresponding Rust target's `debug` directory. Sign and install with your own authorized device workflow. This is a developer-service client, not an App Store compatibility claim.

The simulator UI test checks setup refusal and operation fields. It cannot test the real device's developer services:

```sh
xcodebuild -project native/iphone/PraefectusPhone.xcodeproj \
  -scheme PraefectusPhone -configuration Debug \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  -derivedDataPath target/iphone-xcode \
  PRAEFECTUS_RUST_LIB_DIR="$PWD/target/aarch64-apple-ios-sim/debug" \
  CODE_SIGNING_ALLOWED=NO test
```

Use an installed simulator's name or ID. Before releasing, test pairing, self-routing, screenshot geometry and rotation, each input action, cancellation during input, stale observations, replay, reboot, lock/unlock, and background expiry on an authorized physical iPhone with its computer disconnected.

## Release blockers

- Existing-record peer authentication is unsupported. Connection fails closed, so no device observation or input is currently operational. Resolve this protocol blocker before treating the setup instructions as usable.
- No authorized physical iPhone was available. Simulator and unsigned device builds do not validate device transport, HID negotiation, coordinates, or standalone execution.
- Developer image, valid self-connection pairing, signing, and a compatible external VPN must be supplied. Without these, this app cannot control the phone.

`IphoneConfig::on_phone` fixes the connection address to `10.7.0.1`. `computer_assisted` accepts a host-selected device socket address and credentials for a host running on a computer. That second mode is explicitly computer-assisted, not standalone phone control. Neither mode bypasses `Engine` authority.
