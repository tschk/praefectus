# iPhone reference host

This experimental app embeds Praefectus's Rust engine and CoreDevice executor on the iPhone. Device-authenticated RemotePairing is implemented and tested against Apple's macOS pairing framework, but actual iPhone service and device behavior remain unverified. The code below describes implemented operations and intended setup, not proven working phone control. It is not a release-ready standalone controller.

The imported [idevice pair-verify flow](https://github.com/jkcoxson/idevice/blob/d32c8189c51c2789496b0768039419c3705498c3/idevice/src/remote_pairing/mod.rs) authenticates the host but does not verify the device's identity. Its stored `public_key` is the host key, not a trusted device key. Praefectus's replacement in `src/iphone_transport/verify.rs` checks the pinned device identifier and Ed25519 signature over both ephemeral keys before releasing the host identity proof. Session keys and authenticated RPC become available only after successful completion. Failed verification clears previous session key material.

The exported plist adds `peer_identifier` and `peer_public_key` as local credential metadata from the authenticated trusted-USB setup response. These are not invented RemotePairing wire fields. The public setup PIN `000000` is not authentication. Local physical USB with preexisting lockdown trust is the setup trust boundary; the setup response's self-signature alone does not establish device identity over an untrusted network. Existing host-only records lack the pinned device identity and are rejected by both `IphoneConfig` constructors. Re-export them over trusted USB as described below rather than filling in peer fields manually.

The library remains ISC. Device services use MIT-licensed `idevice` 0.1.68. The adapted MIT RemotePairing client in `src/iphone_transport` uses cryptographic traits directly and does not resolve RSA. Its full notice and repeatable import script are retained. No AGPL code, Poki source, or Poki patches are included.

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

Capabilities reflect advertised services, not proof that those services accept input. The native HID path needs a DisplayService media session and compatible CoreDevice services. There is no XCTest fallback. Older iOS versions that lack these services are unsupported for this input path. No iOS version has been physically validated for CoreDevice observation or input through this implementation.

## Selected iPhone 13 compatibility

Bounded probes on the owner-selected iPhone14,5 running iOS 16.3.1 build 20D67 used its existing USB lockdown trust. The lockdown session and service connections used SSL where required. The probes did not pair, mount an image, install software, dispatch input, or change the OS or accounts.

| Check | Observed result |
| --- | --- |
| `com.apple.dt.remotepairingdeviced.lockdown` | Service start, USB connection, service SSL, and one wire-19 handshake succeeded. The request set `attemptPairVerify=false`; no setup or verify TLVs were sent. The response reported `allowsIncomingTunnelConnections=false`. |
| `com.apple.internal.devicecompute.CoreDeviceProxy` | `Invalid service` (-27). |
| `com.apple.mobile.screenshotr` | Service start and DeviceLink handshake succeeded. One screenshot request through libimobiledevice returned a PNG, 1170×2532. Image bytes stayed in process memory. |
| `com.apple.instruments.remoteserver.DVTSecureSocketProxy` | Service start succeeded. No DVT session or process launch was attempted. |
| `com.apple.instruments.remoteserver` | `Invalid service` (-27). |
| `com.apple.testmanagerd.lockdown.secure` | Service start succeeded. No XCTest session or runner launch was attempted. |
| Passive `_remotepairing._tcp` discovery | Two add events in six seconds. Neither was attributed to the selected phone; no advertised endpoint was contacted. |

The handshake response describes that USB endpoint before authentication. It does not prove device identity or rule out a different tunnel-capable endpoint. Peer versions and supported tunnel types remain unknown. Mounted developer-image state is also unknown.

The current executor needs a tunnel-capable RemotePairing endpoint, CDTunnel, RSD, and compatible CoreDevice services. The observed USB pairing service alone cannot provide that route. Legacy screenshotr, DVT, and XCTest use a different lockdown transport. Service availability does not establish input support. The reference app's iOS 18 deployment target prevents installation on this iOS 16 phone, but that build setting is not evidence about either transport.

### USB-assisted legacy observation

The library provides `iphone::observe_iphone_over_usb(udid, cancellation, deadline)` on macOS and Linux. It selects only the exact physical USB device through local `/var/run/usbmuxd`, reads its existing pairing record, checks `UniqueDeviceID`, and requests one screenshot. It closes the screenshot socket and stops the lockdown session on success. Failure or cancellation drops connections without retrying or attempting new pairing. Secret-bearing upstream tracing is suppressed for this operation only.

The private DeviceLink reader bounds each frame before allocation. PNG decoding uses the same size limits, decoded-pixel content hash, fresh snapshot identity, and device-bound geometry as CoreDevice capture. USB observations do not update a CoreDevice executor's current input fence. This entry point provides no legacy input backend or phone-side connection.

The verification example independently decodes the PNG in memory and checks its dimensions and coordinate bounds. Its output contains metadata only:

```sh
cargo run --locked --features iphone --example iphone_observe_usb -- OWNED_USB_DEVICE_UDID
```

The satellite-built arm64 executable was SHA-256 verified and run exactly once on the selected phone's macOS host. It exited 0 with this output:

```json
{"ok":true,"transport":"usb_screenshotr","format":"PNG","width":1170,"height":2532,"decoded_pixels_verified":true,"bounds_verified":true}
```

This result exercises the actual Praefectus library, not only the earlier libimobiledevice probe. No screenshot contents or pairing secrets left process memory. The temporary executable and archive were removed after the coordinated window closed.

This is computer-assisted observation. A legacy standalone controller would additionally need an authenticated same-phone lockdown connection and an implemented on-phone input path. The library does not expose upstream's permissive legacy TLS verifier as a network connection option. There is no automatic fallback from CoreDevice, and lowering the app's deployment target would not add the missing backend.

## Authority and execution

The Swift host stores its Ed25519 signing key and imported device pairing record in the device-only Keychain. Connecting enables a 15-minute local execution session. **Confirm each action** is off by default and can be enabled for an additional confirmation dialog. The UI still requires you to submit each operation; it is not an autonomous planner.

Swift automatically signs each submitted proposal within the active lease. Every grant expires within 15 seconds and no later than the lease. Rust receives only the pinned public key and signed request. Reconnection creates a new session identity and rejects old-session requests. **Stop and revoke**, app termination, or lease expiry prevents further input under that session. Background-task expiry also revokes the session. Stop cannot undo an effect already dispatched. The ordinary `Engine` still verifies every grant and owns durable at-most-once dispatch. Neither pairing nor host authority configuration is a model action parameter. Other library hosts retain their own approval policy; the engine does not default to auto-authorization.

Input requires the latest screenshot, captured within 30 seconds. The executor rechecks device-bound geometry, decoded pixel content, snapshot identity, and coordinate bounds before dispatch. Swipe endpoints share the same fence. Full-screen changes, including clocks and animations, can invalidate a target. Screen comparisons are boundary checks, not a guarantee that the display cannot change during input.

Input uses the shared device's global pointer route. `background_only` and the global-input restriction refuse it. The reference app uses interactive requests with no outcome verification. Successful delivery is `executed_unverified`, not proof that the intended app effect occurred. Transport interruption after a possible effect is `outcome_unknown`; inspect the phone before any retry. Stream setup itself can have an effect, so its failures are also conservatively unknown. Reconnect after a broken session.

Screenshot bytes stay out of requests, receipts, and ledgers. The app writes its latest image to an app-private file. Hosts must protect this file and the operation ledger. Do not enable verbose `idevice` tracing: upstream debug logging can contain pairing and protocol material.

## Required setup

1. Build and sign the app using your own Apple developer configuration. A computer is needed for initial installation and may be needed again for signing renewal. Nothing here depends on the user's laptop being online during execution.
2. Enable Developer Mode and mount the compatible developer disk image using authorized developer tooling. This app does not download, personalize, or mount developer images.
3. Export a device-pinned **RemotePairing** record over trusted USB using the command below, then import its plist through the app. Traditional lockdown plists and old host-only RemotePairing records are not accepted. The app does not create pairing records or automatically fall back to new pairing. A computer-created record is not guaranteed to authenticate a self-connection on newer iOS versions.
4. Install and enable a separately supplied, trusted loopback VPN that routes `10.7.0.1` back to this iPhone, including dynamic developer-service ports. Praefectus does not bundle a Network Extension or VPN. VPN connectivity alone does not prove developer-service connectivity.
5. Supply the actual RemotePairing port. The UI starts with 49152, but this port can change. Automatic Bonjour port discovery is not implemented.
6. Connect, discover, and observe. Observation and input wait three seconds so you can switch to the target app. Return to submit an action, then switch back. The target screen must still match the observation.

For step 3, use an authorized macOS or Linux host with a preexisting lockdown trust relationship to the owned, physically USB-connected phone. Select that phone's UDID explicitly:

```sh
cargo run --locked --features iphone --example iphone_pair -- OWNED_USB_DEVICE_UDID NEW_OUTPUT_PLIST
```

The helper uses the local `/var/run/usbmuxd` socket, selects only the matching physical USB device, and opens `com.apple.dt.remotepairingdeviced.lockdown` through the trusted lockdown session. It checks the setup response's `remotepairing_udid` against the selected UDID. There is no network setup fallback. The helper requires a new output path and creates the credential file with mode `0600`. Transfer the plist securely, then remove exported copies. Do not print or log its contents. This bootstrap path still needs validation against an eligible physical iPhone.

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

### Authentication evidence

On a Mac satellite, this explicit test passed both setup and verify against the installed native Apple `CUPairingSession`, including comparison of the derived `ServerEncrypt-main` key:

```sh
cargo test --locked --features iphone --lib apple_pairing_framework_interoperability -- --ignored --nocapture
```

`native/iphone/ApplePairingPeer.m` is a test-only adapter to the installed private CoreUtils framework. It uses fresh in-memory identities, not a pairing daemon, Keychain, or real device. The adapter is not shipped on the phone. This result establishes Apple macOS pairing-primitive interoperability, not iPhone-specific service compatibility or restored physical operation.

The portable authenticated RPC/adversarial test passed nine cases: a successful authenticated RPC, wrong key, wrong identifier, tampered proof, wrong transcript, missing proof, bad state, low-order ephemeral key, and bad final state. Run it with:

```sh
cargo test --locked --features iphone --lib authenticated_rpc_and_adversarial_handshakes -- --nocapture
```

These tests do not validate the physical USB bootstrap service, on-phone self-connection, TLS tunnel, CoreDevice services, or input effects on an actual iPhone.

## Release blockers

- Actual iPhone RemotePairing service compatibility remains unverified. The authentication contract passes macOS framework interoperability, but that does not prove acceptance by the phone's service.
- The selected iPhone 13 has verified legacy USB screenshotr observation through Praefectus, but not CoreDevice, physical input, or standalone execution. Its observed USB pairing endpoint does not advertise tunnels. USB RemotePairing bootstrap and network authentication remain untested on that phone.
- Developer image, valid self-connection pairing, signing, and a compatible external VPN must be supplied. Without these, this app cannot control the phone.

`IphoneConfig::on_phone` fixes the connection address to `10.7.0.1`. `computer_assisted` accepts a host-selected device socket address and credentials for a host running on a computer. That second mode is explicitly computer-assisted, not standalone phone control. Neither mode bypasses `Engine` authority.
