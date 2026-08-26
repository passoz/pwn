import { chromium } from "playwright";
import { mkdir, writeFile } from "node:fs/promises";

const url = "http://localhost:5173"; // Replace with your URL.
const output = "/mnt/user-data/outputs/console.log";
const consoleLogs = [];
const browser = await chromium.launch({ headless: true });

try {
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
  page.on("console", (message) => {
    const line = `[${message.type()}] ${message.text()}`;
    consoleLogs.push(line);
    console.log(`Console: ${line}`);
  });
  await page.goto(url);
  await page.waitForLoadState("networkidle");
  await page.getByText("Dashboard").click();
  await page.waitForTimeout(1000);
} finally {
  await browser.close();
}

await mkdir("/mnt/user-data/outputs", { recursive: true });
await writeFile(output, consoleLogs.join("\n"), "utf8");
console.log(`\nCaptured ${consoleLogs.length} console messages`);
console.log(`Logs saved to: ${output}`);
