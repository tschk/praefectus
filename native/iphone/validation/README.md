# Bounded XCTest validation runner

This diagnostic runner tests one supervised legacy iPhone control path. It is not
a Praefectus executor, a WDA server, or a standalone phone controller. It adds no
input capability to the Rust library and does not bypass `Engine` authority.

`HomeValidation/testHomeOnce` activates Settings, requires Settings to be
foreground, presses Home exactly once, and verifies that Settings leaves the
foreground and a SpringBoard icon is visible. It does not tap any Settings
control, type text, change preferences, or communicate externally. A failed
precondition stops the test. Do not retry a physical run after an ambiguous
dispatch, disconnect, or timeout.

## Build without signing

Use an installed Xcode whose embedded XCTest frameworks support the target
phone. Setting `IPHONEOS_DEPLOYMENT_TARGET` alone does not lower the minimum OS
of those frameworks. In the satellite used for this validation, Xcode 26.6's
embedded arm64 frameworks support iOS 13 and the test bundle targets iOS 16.
Xcode 27's XCTest requires iOS 17 and is unsuitable for the selected iOS 16.3.1
phone.

From the repository root:

```sh
DEVELOPER_DIR=/Applications/Xcode_26.6.app/Contents/Developer \
  xcodebuild \
  -project native/iphone/validation/PraefectusControlTests.xcodeproj \
  -scheme PraefectusControlTests \
  -destination 'generic/platform=iOS' \
  -derivedDataPath target/iphone-home-validation \
  CODE_SIGNING_ALLOWED=NO build-for-testing
```

The resulting `PraefectusControlTests-Runner.app` contains only this test bundle
and Xcode's runner/framework support. Its generated application identifier is
the build's `PRODUCT_BUNDLE_IDENTIFIER` followed by `.xctrunner`. Override that
build setting only after agreeing the owner-authorized identifier and team.
Building this project does not register an App ID or provision or install it.

## Run on a simulator

Select an installed iPhone simulator with `xcrun simctl list devices available`.
Run from the repository root, replacing `SIMULATOR_ID` with that simulator's ID:

```sh
xcodebuild \
  -project native/iphone/validation/PraefectusControlTests.xcodeproj \
  -scheme PraefectusControlTests \
  -destination 'platform=iOS Simulator,id=SIMULATOR_ID' \
  -derivedDataPath target/iphone-home-validation-sim \
  -only-testing:PraefectusControlTests/HomeValidation/testHomeOnce \
  CODE_SIGNING_ALLOWED=NO test
```

This changes the simulator's foreground app from Settings to Home. It does not
connect to a physical phone, use an Apple account, or create signing assets.
The expected result is one executed test, zero failures, and `TEST SUCCEEDED`.

## Verification evidence and limits

The same test source passed on the satellite's iOS 26.5 simulator, with one test
and zero failures. A scratch copy with the Home invocation removed failed
because Settings remained foreground. SpringBoard's process state by itself
does not establish that Home is displayed; it can report foreground while
Settings is also foreground. The test therefore checks Settings's transition
and Home icons.

The physical-target unsigned build also passed. These checks do not establish
that an iOS 16 phone accepts the runner, its XCTest bootstrap, or the Home event.

Physical provisioning and testing are deferred at the owner's request. The
runner has not been installed or executed on the selected phone. PR #236 is
parked for source and simulator review, not merge or release. Experimental USB
launcher and installer helpers remain outside the published tree: they were
never run against the phone and are not supported execution tools.

Before a physical run, verify the signed artifact, exact application identifier,
team, embedded profile, signing-certificate match, profile expiry and selected
device membership. Do not install with a profile that excludes the phone.
Signing success alone is not provisioning or installation proof. Coordinate a
single physical operator and inspect the installed artifact and existing trust
before launching anything.

The launcher must select exactly `HomeValidation/testHomeOnce`, observe one
matching passing test and normal plan completion, reject failures or extra
tests, and verify runner termination. A completed plan or a successful host
process exit alone is insufficient. Keep identifiers, profile contents, device
logs and automatic XCTest screenshots private. Report only sanitized test and
lifecycle results.

Even a successful physical test would prove a supervised XCTest path, not a
Praefectus input backend, authenticated same-phone networking, background
execution, or operation with the computer disconnected.
