/// <reference types="vitest" />
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    minify: false,
    outDir: "dist",
    target: "esnext",
    lib: {
      entry: "src/index.ts",
      formats: ["es"],
      fileName: "index",
    },
  },
  test: {
    globals: true,
    browser: {
      provider: "playwright",
      enabled: true,
      headless: false,
      instances: [
        { browser: "chromium" },
      ],
    },
  },
});
