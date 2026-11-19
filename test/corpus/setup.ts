// vitest globalSetup: reads the vendored vectors once, in Node, and provides them to every test
// file, including those running in a browser.
import type { TestProject } from "vitest/node";

import { type Corpus, loadCorpus } from "./data.ts";

export default function setup(project: TestProject): void {
  project.provide("corpus", loadCorpus());
}

declare module "vitest" {
  export interface ProvidedContext {
    corpus: Corpus;
  }
}
