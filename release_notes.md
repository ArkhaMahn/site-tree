## Site tree v1.1.0

### New Features
- **Configurable thread pool**: Added thread concurrency control for link extraction (2-8 threads, default 2)
- Thread count now persisted in ZAP configuration

### UI Improvements
- Thread slider panel with "Number of threads:" label as header above the slider
- Slider expands to fill available width
- Removed thread counter label next to slider
- Added line break in intro text for better readability

### Internal Changes
- `LinkExtractorNetworkListener` now uses configurable thread pool from options
- `LinkExtractorOptionsParam` stores thread configuration with validation (min 2, max 8)
- Updated unit tests to use valid options

### Build
```sh
gradle build
```

Requires JDK 17.