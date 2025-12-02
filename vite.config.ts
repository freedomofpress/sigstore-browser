/// <reference types="vitest" />
import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  build: {
    outDir: "dist",
    target: "esnext",
    minify: "esbuild",
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      name: "SigstoreBrowser",
      formats: ["es", "iife"],
      fileName: (format) => (format === "iife" ? "sigstore.min.js" : "index.js"),
    },
    rollupOptions: {
      output: {
        globals: {},
      },
    },
    sourcemap: true,
  },
  test: {
    globals: true,
    environment: "node",
  },
});
