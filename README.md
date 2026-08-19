Site tree
=========

A ZAP 2.17.0 add-on that performs network-layer Burp-style link extraction: it
runs inline on every response ZAP receives and, for in-scope sources, adds URLs
discovered in HTML/JS/CSS/JSON/XML bodies to the Sites tree as unrequested
(`TYPE_ZAP_USER`) entries, without sending any requests to them.

It is inspired by [`xnLinkFinder`](https://github.com/xnl-h4ck3r/xnLinkFinder).

Author: Arkhamahn. Original idea and implementation credit goes to
[`xnl-h4ck3r`](https://github.com/xnl-h4ck3r) and the `xnLinkFinder` project.

Vibecoded with love 🖤

## How it works

Every in-scope response ZAP receives (proxied browsing, spider, AJAX spider,
active scan) is inspected the moment it arrives. All URLs and
endpoint-looking string literals in HTML/JS/CSS/JSON/XML bodies are resolved
and added to the Sites tree as unrequested (`TYPE_ZAP_USER`) entries with an
empty response and a "Discovered via passive link extraction - NOT requested"
note.

No request is ever sent to the discovered URLs. Cross-host candidates are
added as new subdomain folder nodes flagged with a "[NEW SUBDOMAIN]" note.

Because it hooks the network layer (`HttpSenderListener`) and runs inline on
the request/proxy thread, the tree populates immediately when a domain is
visited, with no dependency on the passive scan queue.

Both JavaScript parsing and subdomain discovery can be toggled under
`Tools > Options > Sites tree`.

## Building

Requires JDK 17+ and Gradle 8.13+.

```
gradle build
```

The ZAP add-on artifact is produced at
`build/zapAddOn/bin/site-tree-alpha-1.0.0.zap`. Install it in ZAP via
`Manage Add-ons -> Install...`.