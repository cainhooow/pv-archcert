# Opt-in Glassmere browser tests

This directory contains development qualification tooling only. Nothing here is
bundled into the Rust panel or downloaded by the running application.

Use Node 26.10.0 and npm 12.1.0, as pinned in package.json. Install the exact lock
with scripts disabled:

```sh
npm ci --ignore-scripts --prefix tools/glassmere-browser
npm audit --prefix tools/glassmere-browser
node scripts/test-glassmere-browser
```

The test uses an operator-installed Google Chrome (`channel: chrome`); no executable
browser download is implicit. It reads private credentials from the ignored preview
directory and never prints them. Results/screenshots remain under target/. Override
`GLASSMERE_PREVIEW`, `GLASSMERE_RESULTS` or `PLAYWRIGHT_MODULE` only with explicit
local paths. The test closes only its own browser, leaving the preview running.
