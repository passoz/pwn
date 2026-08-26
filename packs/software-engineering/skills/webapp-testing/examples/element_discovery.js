import { chromium } from "playwright";

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  await page.goto("http://localhost:5173");
  await page.waitForLoadState("networkidle");

  const buttons = page.locator("button");
  console.log(`Found ${await buttons.count()} buttons:`);
  for (let index = 0; index < await buttons.count(); index += 1) {
    const button = buttons.nth(index);
    const text = await button.isVisible() ? await button.innerText() : "[hidden]";
    console.log(`  [${index}] ${text}`);
  }

  const links = page.locator("a[href]");
  console.log(`\nFound ${await links.count()} links:`);
  for (let index = 0; index < Math.min(5, await links.count()); index += 1) {
    const link = links.nth(index);
    console.log(`  - ${(await link.innerText()).trim()} -> ${await link.getAttribute("href")}`);
  }

  const inputs = page.locator("input, textarea, select");
  console.log(`\nFound ${await inputs.count()} input fields:`);
  for (let index = 0; index < await inputs.count(); index += 1) {
    const input = inputs.nth(index);
    const name = await input.getAttribute("name") || await input.getAttribute("id") || "[unnamed]";
    const type = await input.getAttribute("type") || "text";
    console.log(`  - ${name} (${type})`);
  }

  await page.screenshot({ path: "/tmp/page_discovery.png", fullPage: true });
  console.log("\nScreenshot saved to /tmp/page_discovery.png");
} finally {
  await browser.close();
}
