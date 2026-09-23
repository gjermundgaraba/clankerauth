import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const directory = new URL("../.dev/", import.meta.url);

const secretFile = new URL("secret", directory);

mkdirSync(directory, { recursive: true, mode: 0o700 });

try {
  writeFileSync(secretFile, randomBytes(32).toString("hex"), { flag: "wx", mode: 0o600 });
} catch (error) {
  if (error.code !== "EEXIST") throw error;
}

const secret = readFileSync(secretFile, "utf8").trim();

if (secret.length < 32)
  throw new Error("The dev secret in .dev/secret must contain at least 32 characters.");

// Dev always uses its own identity state, even when production variables are exported.
Object.assign(process.env, {
  CLANKERAUTH_BASE_URL: "http://localhost:3000",
  CLANKERAUTH_BETTER_AUTH_SECRET: secret,
  CLANKERAUTH_DATABASE: fileURLToPath(new URL("clankerauth.sqlite", directory)),
  CLANKERAUTH_HOST: "127.0.0.1",
  CLANKERAUTH_PORT: "3001",
});
