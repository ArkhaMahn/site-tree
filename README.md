<div align="center">

# Site Tree

### A ZAP 2.17.0 add-on for network-layer passive link extraction — inspired by [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder).

<p>
<a href="LICENSE"><img src="https://img.shields.io/github/license/ArkhaMahn/site-tree?color=5B3AB6&label=license" alt="license"></a>
<a href="https://github.com/ArkhaMahn/site-tree/issues"><img src="https://img.shields.io/badge/PRs-welcome-5B3AB6" alt="PRs welcome"></a>
</p>

</div>

---

# Site Tree — ZAP add-on

A [ZAP](https://www.zaproxy.org/) add-on that performs **network-layer passive link extraction** on every in-scope response. It discovers URLs in HTML, JavaScript, CSS, JSON, and XML bodies and adds them to the Site tree as unrequested (`TYPE_ZAP_USER`) entries — without sending any requests to them.

Inspired by the [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder) project.

> **Status: alpha.** Built and verified for ZAP 2.17.0. The extension loads cleanly with no errors. Please report any issues.

---

## What it does

- Hooks the network layer (`HttpSenderListener`) and runs inline on every in-scope response (proxied browsing, spider, AJAX spider, active scan).
- Extracts URLs and endpoint-looking string literals from HTML/JS/CSS/JSON/XML bodies.
- Adds discovered URLs to the Site tree as unrequested entries with an empty response and a "Discovered via passive link extraction - NOT requested" note.
- Optionally records the same entries in the history tab too, so discovered links and subdomains are visible in both places. Off by default.
- The history tab option is a true switch: with it off, discovered entries never reach the history tab - not when they are added, and not after the tab is rebuilt (in-scope toggle, history filter, or reopening a session). Entries are still kept in the Site tree and in the session, using the history type ZAP does not list in that tab (`HistoryReference.TYPE_HIDDEN`).
  - Two consequences of that type, both inherent to using it: ZAP's Sites-tree **"Show in History"** context-menu item is only enabled for its own proxied/ZAP-user types, so it is greyed out for entries added while the option is off; and toggling the option only affects entries discovered **after** the change (existing nodes keep the type they were created with). Delete a node (or refresh the Site tree) and it is re-discovered with the new setting.
- **No requests are ever sent** to discovered URLs.
- Cross-host candidates are added as new subdomain folder nodes flagged with a "[NEW SUBDOMAIN]" note.
  - A cross-host candidate on the same registrable domain as the source host (a subdomain of the in-scope domain) is added without an extra in-scope check - that is what makes subdomain discovery work. ZAP's exclude rules are not consulted for those candidates, so hosts you have excluded can still be discovered as subdomains; everything unrelated to the source domain's family is rejected.
- Hostnames found in HTTP response headers (CSP, Link, Set-Cookie, Location, ...) are added as new subdomain folder nodes; wildcard entries such as `*.example.com` are resolved to the apex domain.
- Tree populates immediately when a domain is visited — no dependency on the passive scan queue.
- JavaScript parsing, subdomain discovery from body links, subdomain discovery from HTTP response headers (wildcards such as `*.example.com` supported), and recording discovered links and subdomains in the history tab can each be toggled under `Tools > Options > Site tree`. The same panel sets the number of worker threads and the largest response body that is scanned at all.

### Options (`Tools > Options > Site tree`)

| Option | Default | Meaning |
| --- | --- | --- |
| Parse JavaScript | on | Also run the JS patterns (fetch/axios/XHR/template literals, bare API path literals) and gate `<script>` contents behind this. |
| Discover subdomains | on | Add cross-host links from response bodies as new subdomain folder nodes. |
| Discover subdomains from HTTP response headers | on | Add hostnames found in headers (CSP, `Link`, `Set-Cookie`, ...) as subdomain nodes, resolving wildcards such as `*.example.com`. |
| Record discovered links and subdomains in the history tab | off | Also list the discovered entries in the history tab (see above for the exact semantics). |
| Number of threads | 2 | Worker threads that decode and parse responses (2-8). |
| Maximum response body size to scan (MB) | 5 | Responses with a body larger than this are not scanned at all (1-100 MB). |

### Resource limits

The add-on runs on ZAP's network layer, so a hostile page must not be able to turn it into a way of
exhausting ZAP. It is bounded by:

- **Cheap gates only on the network thread** (body size, empty body, content type, source scope, and
  the parse-queue depth), all of them O(1). The only body data the network thread touches is a
  snapshot of a body that has already passed the size gate. Decoding, parsing and insertion run on a
  pool of daemon worker threads; a response that arrives while the pool or its queue is saturated is
  dropped instead of stalling the proxy thread.
- **A configurable maximum body size** (default 5 MB, 1-100 MB via
  `Tools > Options > Site tree`). Above it the response is not scanned, so neither the network-thread
  snapshot nor the worker's decode can be made arbitrarily large - a big download, media file or
  source map is skipped rather than parsed.
- **A token bucket** (50, +10 every 100 ms) checked *before* anything is persisted, plus a cap of
  200 inserted nodes per response, so one response cannot flood the session database.
- **Bounded regex quantifiers** everywhere, so a crafted page cannot make a pattern rescan the body
  quadratically.
- **One short host-node wait per response** (max 0.5 s, shared by all of that response's candidates,
  and never retried) and at most 50 Site tree mutations per EDT callback, so a single response can
  neither pin a worker thread nor freeze the UI.
- **Full release on shutdown**: the worker pool, the token-refill scheduler and any queued UI work
  are released when the session ends or the add-on is unloaded.

Under heavy load the caps mean fewer nodes are added per response than without them. That is
intentional: the caps are what keep the add-on safe to leave enabled.

---

## Build

Requires JDK 17+ and [Gradle](https://gradle.org/install/) 8.13+ (or use the included wrapper):

```sh
./gradlew build
# or, if Gradle is installed globally:
gradle build
```

The ZAP add-on artifact is produced at:
`build/zapAddOn/bin/site-tree-alpha-1.2.0.zap`

## Install in ZAP

1. Build the `.zap` (above).
2. In ZAP: **File → Load Add-on File…** and select the built `.zap`, OR drop the `.zap` into ZAP's `plugin` directory and restart.
3. The add-on runs automatically on in-scope traffic — no further configuration needed.

---

## Development

```
src/main/java/org/zaproxy/addon/linkextractor/
  ExtensionLinkExtractor.java       # ExtensionAdaptor entry point
  LinkExtractorNetworkListener.java # HttpSenderListener — inline response processing
  LinkExtractorOptionsPanel.java    # Options UI (Tools > Options > Site tree)
  LinkExtractorOptionsParam.java    # Options persistence
```

The extraction runs on the request/proxy thread (inline with response processing) for immediate tree updates.

---

## Credits

Original idea and implementation credit goes to [xnl-h4ck3r](https://github.com/xnl-h4ck3r) and the [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder) project.

---

## License

[Apache-2.0](LICENSE) © 2026 Arkhamahn