import puppeteer from "puppeteer-core";
import fs from "fs";
import path from "path";

const ARTIFACT_DIR = "C:\\Users\\patel\\.gemini\\antigravity\\brain\\90049d38-4ac8-410a-bc14-8fa155c39c04";
const EDGE_PATH = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";

async function run() {
  console.log("Launching Edge browser via puppeteer-core...");
  const browser = await puppeteer.launch({
    executablePath: EDGE_PATH,
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--window-size=1440,900",
    ],
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

  console.log("Navigating to login page...");
  await page.goto("http://localhost:3000/login", { waitUntil: "networkidle0" });

  console.log("Logging in as Lead SRE...");
  await page.type("input[type='email']", "sre@sentinelops.local");
  await page.type("input[type='password']", "SentinelOps2026!");
  await page.click("button[type='submit']");

  // Wait for dashboard navigation
  console.log("Waiting for dashboard redirect...");
  await page.waitForNavigation({ waitUntil: "networkidle0", timeout: 15000 }).catch(() => {});
  await new Promise((r) => setTimeout(r, 2000));

  // 1. Playbooks List
  console.log("Navigating to /playbooks...");
  await page.goto("http://localhost:3000/playbooks", { waitUntil: "networkidle0" });
  await new Promise((r) => setTimeout(r, 2000));
  const listPath = path.join(ARTIFACT_DIR, "screenshot_1_playbooks_list.png");
  await page.screenshot({ path: listPath, fullPage: true });
  console.log(`Saved screenshot 1 to ${listPath}`);

  // 2. Playbook Creation Wizard
  console.log("Navigating to /playbooks/new...");
  await page.goto("http://localhost:3000/playbooks/new", { waitUntil: "networkidle0" });
  await new Promise((r) => setTimeout(r, 2000));
  const wizardPath = path.join(ARTIFACT_DIR, "screenshot_2_playbooks_wizard.png");
  await page.screenshot({ path: wizardPath, fullPage: true });
  console.log(`Saved screenshot 2 to ${wizardPath}`);

  // 3. Playbook Detail Page
  const detailUrl = "http://localhost:3000/playbooks/4b5dd6dc-eef8-4530-906a-3f7b689e4580";
  console.log(`Navigating to ${detailUrl}...`);
  await page.goto(detailUrl, { waitUntil: "networkidle0" });
  await new Promise((r) => setTimeout(r, 2000));
  const detailPath = path.join(ARTIFACT_DIR, "screenshot_3_playbook_detail.png");
  await page.screenshot({ path: detailPath, fullPage: true });
  console.log(`Saved screenshot 3 to ${detailPath}`);

  // 4. Playbook Edit Page
  const editUrl = "http://localhost:3000/playbooks/4b5dd6dc-eef8-4530-906a-3f7b689e4580/edit";
  console.log(`Navigating to ${editUrl}...`);
  await page.goto(editUrl, { waitUntil: "networkidle0" });
  await new Promise((r) => setTimeout(r, 2000));
  const editPath = path.join(ARTIFACT_DIR, "screenshot_4_playbook_edit.png");
  await page.screenshot({ path: editPath, fullPage: true });
  console.log(`Saved screenshot 4 to ${editPath}`);

  await browser.close();
  console.log("Screenshots captured successfully!");
}

run().catch((err) => {
  console.error("Error capturing screenshots:", err);
  process.exit(1);
});
