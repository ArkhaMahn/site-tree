## Site tree v1.2.0

### New Features
- **Configurable thread pool**: Added thread concurrency control for link extraction (2-8 threads, default 2)
- Thread count now persisted in ZAP configuration
- **Configurable maximum response body size** (1-100 MB, default 5 MB): responses with a larger body are not parsed at all, so a very large download, media file or source map can no longer be copied on the network thread and decoded on a worker
- **Subdomain discovery from HTTP response headers**: hostnames found in response headers (CSP, Link, Set-Cookie, Location, vendor `X-*` headers, ...) are added as new subdomain folder nodes; wildcard entries such as `*.example.com` resolve to the apex domain. Toggle under `Tools > Options > Site tree`.
- **Record discoveries in the history tab**: new "Record discovered links and subdomains in the history tab" option under `Tools > Options > Site tree`. When enabled, every discovered link or subdomain is also listed in the history tab, using the same `HistoryReference` as the Site tree entry. No request is ever sent to the discovered URL. Disabled by default so the history tab is not flooded.
- The option is a real off switch: with it disabled, a discovered entry is created with the history type ZAP does not list in that tab (`HistoryReference.TYPE_HIDDEN`), so it never shows up there - not when it is added, and not after the history view is rebuilt by the in-scope toggle, the history filter, or reopening a session. The Site tree entry and the session record are unaffected.

### UI Improvements
- Thread slider panel with "Number of threads:" label as header above the slider
- Slider expands to fill available width
- Removed thread counter label next to slider
- Added line break in intro text for better readability
- Panel name made consistent: **Site tree** (was "Sites tree")
- New checkbox: "Record discovered links and subdomains in the history tab"
- New input: "Maximum response body size to scan (MB):" with a tooltip explaining the limit

### Internal Changes
- `LinkExtractorNetworkListener` now uses configurable thread pool from options
- `LinkExtractorOptionsParam` stores thread configuration with validation (min 2, max 8)
- `LinkExtractorOptionsParam` stores the new header-subdomain-discovery toggle
- `LinkExtractorOptionsParam` stores the new `linkextractor.recordInProxyHistory` toggle (default `false`)
- `LinkExtractorOptionsParam` stores the new `linkextractor.maxBodySizeMb` value (1-100 MB, default 5, clamped on read and on write) and exposes it as bytes for the network-thread gate
- The stored configuration version moved from 2 to 3 for that new key. A configuration written by an earlier build is recognised as older, and the migration writes the default limit into it instead of leaving it to an in-memory fallback
- Discovered entries are registered with `ExtensionHistory.addHistory(HistoryReference)` on the EDT after the Site tree insertion, keeping the existing "NOT requested" note, and only when the option is enabled
- The `HistoryReference` type of each entry is now chosen from the option: `TYPE_ZAP_USER` when the entry should be listed in the history tab, `TYPE_HIDDEN` when it should not (the history tab is rebuilt from the session by `ExtensionHistory.getHistoryIds()`, which only queries the proxied, ZAP-user and proxy-connect types, so skipping `addHistory` alone would not keep the entry out of that tab)
- Updated unit tests to use valid options, plus new tests for the default value, persistence of the history-tab option, and the mapping of the option to the history type (including a test pinning that the type used for the off state is not one of the types the history tab lists)
- Added tests for the body-size gate's boundary (a body of exactly the limit is still scanned, one byte more is not, at both ends of the option range), the saturation gate's threshold, the configuration migration, the rate limit granting exactly the available tokens and denying an empty bucket, the bounded patterns still extracting real-world `meta`/`$.ajax` URLs while staying fast on crafted bodies, the trailing-garbage normalisation, and the pre-computed registrable-domain check agreeing with the two-argument one

### Fixes
- **The insertion rate limit did nothing.** The token-bucket check clamped an empty bucket to `0` and then tested the result against `>= 0`, so a token was granted on every single attempt and a crafted page could write history rows to the session database as fast as it could produce unique URLs. It now actually denies, restoring the intended 50 (+10 per 100 ms) budget.
- **Quadratic regex work on crafted pages.** The `<meta ... url=` and `$.ajax({ ... url:` patterns used unbounded lazy runs whose terminator may be absent, so an unclosed `<meta` or `$.ajax({` made every start offset rescan the rest of the body (measured: ~50s for a single 300 KB response, pinning a worker thread). The runs are now bounded; a regression test covers it.
- **A thread per inserted node, and a wait that usually timed out.** Waiting for the source host node to appear created a new non-daemon thread per candidate and blocked the worker on `join()` - and it waited for the full request URL rather than the host node, so it normally burned the full 1.5s timeout. The wait is now a single bounded poll per response, inline on the worker, for the host node itself.
- **The body size was not bounded anywhere.** The body was snapshotted on the network thread and decoded to a `String` on a worker for every response, and the encoded-character decoder can hold several further copies of it, so a single very large response (a download, a media file, a source map) could stall the request/response path and spike memory. Responses over the configured limit (default 5 MB) are now rejected on the network thread before anything is copied.
- **The body was copied even for parses that were then dropped.** The pool's queue depth is now checked on the network thread before the snapshot copy, so responses that arrive while the pool is backed up are dropped instead of paying for a copy that may only be used long after the response stopped being relevant.
- **The host-node wait was long enough to matter.** A worker thread was occupied for up to 1.5 s waiting for the source host node; the wait is a short race-window wait and is now capped at 0.5 s (still once per response, never retried).
- EDT batching was unbounded, so a burst of insertions could run every Site tree mutation in one UI callback; the flush now runs at most 50 tasks per callback and continues in a further one.
- **Failed insertions were never retried**: a candidate whose insertion was rate limited, or whose history reference could not be created, stayed in the dedup set and could never be re-added. It is now released again on failure.
- **Orphaned database rows**: if the Site tree insertion failed after the history reference had been written, the row was left behind with nothing pointing at it; it is removed again.
- **Threads outliving the session**: the worker pool and the token-refill scheduler are now released by a `shutdown()` hook wired to the extension's `unload()`/`destroy()`, and queued UI work is dropped.
- Per-response and per-insert logging moved from `INFO` to `DEBUG` (an active scan produced a log line per response).

### Performance
- The encoded-character decoder compiled its six patterns on every response and scanned the whole body six times; the patterns are now compiled once and a body that cannot contain any encoded character (no `%`, `&` or `\`) skips the decoding entirely.
- Trailing-character normalisation of every candidate used two `String.replaceAll` calls, which re-compiled their patterns for each candidate (~17,000 short-lived patterns per large response); it now uses character loops. The same applies to the template-literal interpolation rewrite.
- Bracket stripping no longer allocates a stack for candidates that contain no brackets.
- The source host's registrable domain is computed once per response instead of once per cross-host candidate.
- Candidates with no backslash skip the escape-collapsing scans.
- Response logging and the insert-cap notice are behind `isDebugEnabled()`.

### Changes
- The `HrefTypeInfo` registration of the "not in history tab" type was removed. ZAP only reads `HrefTypeInfo` for the history tab and the manual-request editor - never for Site tree nodes - and entries of that type are never listed in the history tab, so the name could not be displayed anywhere; the add-on no longer mutates that global registry.
- **New option: maximum response body size to scan** (`Tools > Options > Site tree`, 1-100 MB, default 5 MB). Responses with a larger body are no longer parsed at all.

### Build
```sh
gradle build
```

Requires JDK 17.