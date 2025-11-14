declare module 'tuf-browser/dist/tuf.js' {
  export class TUFClient {
    constructor(
      repositoryUrl: string,
      startingRoot: string,
      namespace: string,
      targetBaseUrl?: string
    );

    updateTUF(): Promise<void>;
    getTarget(targetPath: string): Promise<Uint8Array>;
  }
}
