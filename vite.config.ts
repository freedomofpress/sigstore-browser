/// <reference types="vitest" />
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    outDir: "dist",
    target: "es2020",
    lib: {
      entry: "src/index.ts",
      formats: ["es"],
      fileName: "index",
    },
  },
  test: {
    globals: true,
    environment: "node",
    globalSetup: ["test/corpus/setup.ts"],
    testTimeout: 120_000,
  },
});
