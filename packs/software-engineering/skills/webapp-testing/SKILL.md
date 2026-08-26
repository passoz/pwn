---
name: webapp-testing
description: Toolkit for interacting with and testing local web applications using Playwright. Supports verifying frontend functionality, debugging UI behavior, capturing browser screenshots, and viewing browser logs.
license: Complete terms in LICENSE.txt
---

# Web Application Testing

Use native JavaScript Playwright scripts with the project's installed Node runtime.

**Helper script:**
- `scripts/with_server.js` — manages one or more local server processes.

Resolve helper and example paths relative to this skill directory. Always run the helper with `--help` first. Treat it as a black box unless its documented interface is insufficient.

## Decision tree

```text
User task → static HTML?
  Yes → read the HTML to discover selectors
  No  → server already running?
          No  → node scripts/with_server.js --help
          Yes → reconnaissance, then action
```

For dynamic applications:

1. Navigate and wait for `networkidle`.
2. Capture a screenshot or inspect the rendered DOM.
3. Identify selectors from the rendered state.
4. Perform actions with those selectors.
5. Inspect console errors, page errors, and unexpected failed requests.

## Start servers around an automation command

Single server:

```bash
node scripts/with_server.js --server "npm run dev" --port 5173 -- node automation.js
```

Multiple servers:

```bash
node scripts/with_server.js \
  --server "cd backend && npm start" --port 3000 \
  --server "cd frontend && npm run dev" --port 5173 \
  -- node automation.js
```

Ports and commands must come from the repository; never assume the values shown in examples.

## Minimal Playwright script

```js
import { chromium } from "playwright";

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  await page.goto("http://localhost:5173");
  await page.waitForLoadState("networkidle");
  // Inspect, then interact with selectors discovered from the rendered page.
} finally {
  await browser.close();
}
```

## Practices

- Keep Chromium headless unless visual debugging explicitly requires otherwise.
- Wait for `networkidle` before inspecting a dynamic page.
- Prefer role, label, text, stable CSS, or ID selectors supported by the real DOM.
- Use targeted waits instead of arbitrary delays where possible.
- Always close the browser.
- Validate screenshots visually when the task concerns layout, color, alignment, or appearance.
- A build or HTTP 200 response does not prove UI correctness.

## Examples

- `examples/element_discovery.js`
- `examples/static_html_automation.js`
- `examples/console_logging.js`
