# Background computer use: audit and direction

This audit describes the code at November 2026. Proposals are not promises of platform support. Live desktop behavior needs validation on each platform.

## Constraints

Background execution must not activate another application or move the user's pointer on a shared desktop. Target-addressed accessibility operations use the existing foreground, focus, and pointer sentinel. The sentinel compares boundary samples, not continuous behavior. A host-owned isolated session is needed when global input or stronger noninterference is required. `outcome_unknown` is not permission to retry.

## Reliability work

- Host outcome recovery needs to remain consistent regardless of whether the caller invokes `status` or `execute` first. `OperationLedger::status` currently persists an unknown terminal for a claim without a terminal. That can hide a result already recorded in the host outcome ledger. Add a regression covering both recovery orders before changing persistence semantics.
- Execution takes a ledger-wide blocking lock across dispatch. A slow executor can delay unrelated operations and status requests beyond their deadlines. Investigate deadline-aware acquisition and per-operation locking without weakening atomic claims or crash recovery.
- The plugins obtain capabilities and status from a separate CLI, while execution goes through a host bridge. Different executor configurations or ledger paths can make those answers misleading. Route these queries to the executing host or enforce a shared configuration. A missing status record is not proof that an action did not run.
- The plugin capability validators and fixtures need a contract check against real CLI output. The current native output includes `global_input`, and Linux reports `praefectus-linux`. Validate the full native result and expose only actions that the plugin can actually submit.

## More useful background observation

- Large native trees can be truncated. Linux caps its traversal at 512 elements, and the common observation only reports whether truncation occurred. Explore bounded subtree observations rooted at a current fenced target. Revalidate the root, issue fresh tags, and preserve the deadline, depth, and byte budgets.
- CDP observes only the selected root frame and does not provide element bounds. Add optional viewport-relative bounds for disambiguation without granting coordinate-action authority. Investigate child frames separately: bind frame identity and navigation generation, and fail closed when a frame cannot be revalidated.
- Report observation modes, limits, and enumeration scope separately from action capabilities. For example, a missing minimized Windows window is not evidence that the window does not exist. Any protocol extension must account for strict unknown-field rejection.
- Provide a host integration example that associates an ephemeral image with an observation and explicit geometry. Keep image bytes out of requests, receipts, and ledgers. An image is not itself authority to click; coordinate actions still need their own current fence.

## Experiments before implementation

Test each proposal with a real application, including a large accessibility tree, embedded browser frames, hidden or minimized windows, and a changing foreground context. Record which platform APIs support a target-addressed operation without activation. Do not generalize a successful isolated-session experiment to a shared desktop.

Browser contexts can separate browser storage, as described in [Playwright's isolation guide](https://playwright.dev/docs/browser-contexts). Storage isolation alone does not prove desktop input or process isolation. The host remains responsible for establishing the isolation that it declares to Praefectus.
