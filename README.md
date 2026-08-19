<div align="center">

# Site Tree

### A ZAP 2.17.0 add-on for network-layer passive link extraction — inspired by [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder).

<p>
<a href="LICENSE"><img src="https://img.shields.io/github/license/ArkhaMahn/site-tree?color=5B3AB6&label=license" alt="license"></a>
<a href="https://github.com/ArkhaMahn/site-tree/actions"><img src="https://img.shields.io/github/actions/workflow/status/ArkhaMahn/site-tree/build.yml?branch=master&label=build" alt="build"></a>
<a href="https://github.com/ArkhaMahn/site-tree/issues"><img src="https://img.shields.io/badge/PRs-welcome-5B3AB6" alt="PRs welcome"></a>
</p>

</div>

---

# Site Tree — ZAP add-on

A [ZAP](https://www.zaproxy.org/) add-on that performs **network-layer passive link extraction** on every in-scope response. It discovers URLs in HTML, JavaScript, CSS, JSON, and XML bodies and adds them to the Sites tree as unrequested (`TYPE_ZAP_USER`) entries — without sending any requests to them.

Inspired by the [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder) project.

> **Status: alpha.** Built and verified for ZAP 2.17.0. The extension loads cleanly with no errors. Please report any issues.

---

## What it does

- Hooks the network layer (`HttpSenderListener`) and runs inline on every in-scope response (proxied browsing, spider, AJAX spider, active scan).
- Extracts URLs and endpoint-looking string literals from HTML/JS/CSS/JSON/XML bodies.
- Adds discovered URLs to the Sites tree as unrequested entries with an empty response and a "Discovered via passive link extraction - NOT requested" note.
- **No requests are ever sent** to discovered URLs.
- Cross-host candidates are added as new subdomain folder nodes flagged with a "[NEW SUBDOMAIN]" note.
- Tree populates immediately when a domain is visited — no dependency on the passive scan queue.
- JavaScript parsing and subdomain discovery can be toggled under `Tools > Options > Sites tree`.

---

## Build

Requires JDK 17+ and [Gradle](https://gradle.org/install/) 8.13+:

```sh
gradle build
```

The ZAP add-on artifact is produced at:
`build/zapAddOn/bin/site-tree-alpha-1.1.0.zap`

## Install in ZAP

1. Build the `.zap` (above), or download it from the latest [GitHub Actions build](../../actions).
2. In ZAP: **File → Load Add-on File…** and select the built `.zap`, OR drop the `.zap` into ZAP's `plugin` directory and restart.
3. The add-on runs automatically on in-scope traffic — no further configuration needed.

---

## Development

```
src/main/java/org/zaproxy/addon/linkextractor/
  ExtensionLinkExtractor.java       # ExtensionAdaptor entry point
  LinkExtractorNetworkListener.java # HttpSenderListener — inline response processing
  LinkExtractorOptionsPanel.java    # Options UI (Tools > Options > Sites tree)
  LinkExtractorOptionsParam.java    # Options persistence
```

The extraction runs on the request/proxy thread (inline with response processing) for immediate tree updates.

---

## Credits

Original idea and implementation credit goes to [xnl-h4ck3r](https://github.com/xnl-h4ck3r) and the [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder) project.

---

## License

[Apache-2.0](LICENSE) © 2024 Arkhamahn