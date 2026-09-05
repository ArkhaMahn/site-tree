## Site tree v1.2.0

### New Features
- **Configurable thread pool**: Added thread concurrency control for link extraction (2-8 threads, default 2)
- Thread count now persisted in ZAP configuration
- **Subdomain discovery from HTTP response headers**: hostnames found in response headers (CSP, Link, Set-Cookie, Location, vendor `X-*` headers, ...) are added as new subdomain folder nodes; wildcard entries such as `*.example.com` resolve to the apex domain. Toggle under `Tools > Options > Site tree`.

### UI Improvements
- Thread slider panel with "Number of threads:" label as header above the slider
- Slider expands to fill available width
- Removed thread counter label next to slider
- Added line break in intro text for better readability
- Panel name made consistent: **Site tree** (was "Sites tree")

### Internal Changes
- `LinkExtractorNetworkListener` now uses configurable thread pool from options
- `LinkExtractorOptionsParam` stores thread configuration with validation (min 2, max 8)
- `LinkExtractorOptionsParam` stores the new header-subdomain-discovery toggle
- Updated unit tests to use valid options

### Build
```sh
gradle build
```

Requires JDK 17.