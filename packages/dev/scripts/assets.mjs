import { copyFile, cp } from "node:fs/promises";

await copyFile(
  new URL("../src/types.d.ts", import.meta.url),
  new URL("../dist/index.d.ts", import.meta.url),
);
await cp(
  new URL("../../../apps/web/dist/", import.meta.url),
  new URL("../dist/web/", import.meta.url),
  { recursive: true },
);
