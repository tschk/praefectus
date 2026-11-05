# Background computer use: audit and direction

This audit describes the code at November 2026. Proposals are not promises of platform support. Live desktop behavior needs validation on each platform.

## Constraints

Background execution must not activate another application or move the user's pointer on a shared desktop. Target-addressed accessibility operations use the existing foreground, focus, and pointer sentinel. The sentinel compares boundary samples, not continuous behavior. A host-owned isolated session is needed when global input or stronger noninterference is required. `outcome_unknown` is not permission to retry.

## Reliability work

- Status and execution consult the host outcome ledger when resolving an incomplete local claim or a previously persisted recovery-generated unknown. A recorded host outcome is appended to the local ledger without redispatch; other unknown outcomes remain unknown.
- Execution still holds a ledger-wide lock across dispatch. Its lock acquisition checks cancellation and the deadline while contended, but status has no deadline parameter. Investigate per-operation locking without weakening atomic claims or crash recovery.
- The plugins obtain capabilities and status from the execution host bridge, not a separate CLI. Existing execute-only bridges must implement both read operations. A missing status record is not proof that an action did not run.
- Plugin capability validators accept current native capability facts, including `global_input` and the Linux backend name `praefectus-linux`, while exposing only actions that the plugins can submit.

## More useful background observation

- Large native trees can be truncated. Linux caps its traversal at 512 elements, and the common observation only reports whether truncation occurred. Explore bounded subtree observations rooted at a current fenced target. Revalidate the root, issue fresh tags, and preserve the deadline, depth, and byte budgets.
- CDP observes only the selected root frame and does not provide element bounds. Add optional viewport-relative bounds for disambiguation without granting coordinate-action authority. Investigate child frames separately: bind frame identity and navigation generation, and fail closed when a frame cannot be revalidated.
- Report observation modes, limits, and enumeration scope separately from action capabilities. For example, a missing minimized Windows window is not evidence that the window does not exist. Any protocol extension must account for strict unknown-field rejection.
- Provide a host integration example that associates an ephemeral image with an observation and explicit geometry. Keep image bytes out of requests, receipts, and ledgers. An image is not itself authority to click; coordinate actions still need their own current fence.

## Experiments before implementation

Test each proposal with a real application, including a large accessibility tree, embedded browser frames, hidden or minimized windows, and a changing foreground context. Record which platform APIs support a target-addressed operation without activation. Do not generalize a successful isolated-session experiment to a shared desktop.

Browser contexts can separate browser storage, as described in [Playwright's isolation guide](https://playwright.dev/docs/browser-contexts). Storage isolation alone does not prove desktop input or process isolation. The host remains responsible for establishing the isolation that it declares to Praefectus.

## Pull request closure review

On 5 November 2026, PRs 149 through 228 contained 79 closures and merged PR 157. Each closure has a comment with its reason. The counts below assign each closed PR to its primary stated reason, not every possible concern. An overlapping alternative selected for review was not necessarily accepted.

| Primary closure reason | Count | PR numbers |
| --- | ---: | --- |
| Overlap with another proposal | 31 | 150, 151, 152, 153, 154, 155, 161, 162, 164, 165, 167, 169, 174, 175, 176, 177, 180, 182, 183, 189, 196, 198, 200, 203, 204, 206, 208, 210, 214, 223, 225 |
| Extraction without demonstrated need or new behavior coverage | 21 | 160, 166, 170, 171, 173, 179, 181, 184, 187, 191, 192, 193, 199, 202, 213, 215, 216, 218, 221, 226, 228 |
| Redundant, implementation-specific, or unused tests | 6 | 149, 156, 185, 205, 211, 217 |
| Unvalidated behavior or platform delivery change | 6 | 195, 201, 207, 209, 219, 220 |
| Claimed command or path vulnerability not established | 5 | 158, 159, 186, 188, 194 |
| Performance benefit not demonstrated | 3 | 168, 172, 224 |
| Superseded or fixed on main | 3 | 178, 190, 212 |
| Routing refactor included source-rewriting or backup artifacts | 2 | 163, 197 |
| Empty diff | 2 | 222, 227 |

The readable diffs and closure comments were reviewed again after the initial triage. PRs 203 through 228, except the empty diffs, were reopened before that review because the initial review did not establish that every full diff had been read. Binary additions in PRs 169 and 224 were not inspected as source. Whether a refactor is worthwhile remains a judgment, not a fact established by the diff.
