import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const htmlFilePath = path.resolve("path/to/your/file.html");
const outputDirectory = "/mnt/user-data/outputs";
await mkdir(outputDirectory, { recursive: true });

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
  await page.goto(pathToFileURL(htmlFilePath).href);
  await page.screenshot({ path: path.join(outputDirectory, "static_page.png"), fullPage: true });
  await page.getByText("Click Me").click();
  await page.locator("#name").fill("John Doe");
  await page.locator("#email").fill("john@example.com");
  await page.locator('button[type="submit"]').click();
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(outputDirectory, "after_submit.png"), fullPage: true });
} finally {
  await browser.close();
}

console.log("Static HTML automation completed!");
