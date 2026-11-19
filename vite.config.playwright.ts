import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

// BROWSERS=chromium,firefox,webkit runs the suite in each engine; the default is Chromium only.
const browsers = (process.env.BROWSERS ?? "chromium")
  .split(",")
  .map((browser) => browser.trim())
  .filter(Boolean);

export default defineConfig({
  test: {
    include: ["**/*.browser.test.ts"],
    globalSetup: ["test/corpus/setup.ts"],
    testTimeout: 120_000,
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: browsers.map((browser) => ({ browser: browser as "chromium" | "firefox" | "webkit" })),
    },
  },
});
