import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { build } from "vite";
import { publicUrl, startIssuer } from "../tests/issuer.ts";

const execute = promisify(execFile);

const root = fileURLToPath(new URL("../", import.meta.url));

const { name, version } = JSON.parse(await readFile(join(root, "package.json"), "utf8"));

const directory = await mkdtemp(join(tmpdir(), "clankerauth-sdk-install-"));

const typeCheck = (file) =>
  execute(
    process.execPath,
    [
      join(root, "node_modules/typescript/bin/tsc"),
      "--noEmit",
      "--strict",
      "--target",
      "ESNext",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      join(directory, file),
    ],
    { cwd: directory },
  );

try {
  // pnpm resolves the workspace catalog protocol in the packed manifest; npm would not.
  await execute("pnpm", ["pack", "--pack-destination", directory], { cwd: root });
  const [tarball] = await readdir(directory);
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  await execute(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", join(directory, tarball)],
    { cwd: directory },
  );
  const installed = join(directory, "node_modules", name);
  const manifest = JSON.parse(await readFile(join(installed, "package.json"), "utf8"));
  assert.equal(manifest.version, version);
  assert.equal(manifest.sideEffects, false);
  assert.equal(manifest.peerDependenciesMeta["@gjermundgaraba/effect-actions"].optional, true);
  assert.equal(manifest.dependencies["@gjermundgaraba/effect-actions"], undefined);
  await readFile(join(installed, "dist/index.d.ts"), "utf8");
  await writeFile(
    join(directory, "consumer.ts"),
    `
import { Effect } from "effect";
import { HttpClient } from "effect/unstable/http";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import type { AuthenticationError, ConfigurationError } from "@gjermundgaraba/clankerauth-sdk/errors";
const verification: Effect.Effect<Verifier.Principal, AuthenticationError | ConfigurationError, HttpClient.HttpClient> =
  Verifier.make({ issuer: "https://auth.example/api/auth", resource: "https://notes.example/" })
    .pipe(Effect.flatMap(verifier => verifier.verifyToken("token")));
void verification;
`,
  );
  // Core consumers type-check without installing effect-actions or skipping declarations.
  await typeCheck("consumer.ts");

  await writeFile(join(directory, "consumer.mjs"), `export * from "${name}";`);
  const api = await import(pathToFileURL(join(directory, "consumer.mjs")).href);

  for (const exported of ["Verifier", "RequestPolicy"])
    assert(exported in api, `Missing core export: ${exported}`);

  // Errors live behind `/errors` only, so a shared contract cannot reach for them here.
  for (const absent of ["Unauthorized", "InsufficientScope", "authenticationErrors"])
    assert(!(absent in api), `Root re-exports an error: ${absent}`);

  await writeFile(join(directory, "errors.mjs"), `export * from "${name}/errors";`);
  const errors = await import(pathToFileURL(join(directory, "errors.mjs")).href);

  for (const exported of [
    "Unauthorized",
    "InsufficientScope",
    "RateLimited",
    "ProviderUnavailable",
    "ConfigurationError",
    "authenticationErrors",
  ])
    assert(exported in errors, `Missing error export: ${exported}`);

  // Resolve Effect from the isolated installation, not the workspace's development dependencies.
  const { Effect } = await import(
    pathToFileURL(join(directory, "node_modules/effect/dist/index.js")).href
  );

  const { FetchHttpClient } = await import(
    pathToFileURL(join(directory, "node_modules/effect/dist/unstable/http/index.js")).href
  );

  const make = (options) =>
    Effect.runPromise(api.Verifier.make(options).pipe(Effect.provide(FetchHttpClient.layer)));

  const verifier = await make({
    issuer: "https://auth.example/api/auth",
    resource: "https://notes.example/",
  });

  const missing = await Effect.runPromise(Effect.flip(verifier.verify(null)));
  assert(missing instanceof errors.Unauthorized);

  // Verify API-key authentication and revocation through the installed package.
  const issuer = await startIssuer();

  try {
    const installedVerifier = await make({
      issuer: issuer.issuer,
      resource: `${publicUrl}/api`,
    });

    assert.deepEqual(await Effect.runPromise(installedVerifier.verifyToken(issuer.key)), {
      subject: "owner",
      scopes: ["notes:read", "notes:write"],
      actor: { kind: "key", keyId: "writer" },
      // An API key has no token lifetime; it is re-verified on every request.
      expiresAt: undefined,
    });
    issuer.keys.delete(issuer.key);
    const revoked = await Effect.runPromise(Effect.flip(installedVerifier.verifyToken(issuer.key)));
    assert(revoked instanceof errors.Unauthorized);
    assert.equal(issuer.count(), 2);
  } finally {
    await issuer.close();
  }

  // Optional integration is installed and exercised separately from the core consumer.
  await execute(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      `@gjermundgaraba/effect-actions@${manifest.peerDependencies["@gjermundgaraba/effect-actions"]}`,
    ],
    { cwd: directory },
  );
  await writeFile(
    join(directory, "integration.ts"),
    `
import { Effect } from "effect";
import { Resource, CurrentPrincipal } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import { Principal, Session, signOutUrl } from "@gjermundgaraba/clankerauth-sdk/session";
const make = Resource.make({
  issuer: "https://auth.example/api/auth",
  publicUrl: new URL("https://notes.example"),
  scopes: { read: "notes:read", write: "notes:write" },
});
const subject = Effect.map(CurrentPrincipal, principal => principal.subject);
const page: (principal: Principal) => string = principal => signOutUrl(principal.issuer, "/");
void make;
void subject;
void Session.name;
void page;
`,
  );
  // The effect-actions package must also expose valid declarations.
  await typeCheck("integration.ts");
  await writeFile(join(directory, "integration.mjs"), `export * from "${name}/effect-actions";`);
  const { Resource } = await import(pathToFileURL(join(directory, "integration.mjs")).href);

  const resource = await Effect.runPromise(
    Resource.make({
      issuer: "https://auth.example/api/auth",
      publicUrl: new URL("https://notes.example"),
      scopes: { read: "notes:read" },
    }).pipe(Effect.provide(FetchHttpClient.layer)),
  );

  assert.equal(resource.resource, "https://notes.example/");
  assert(
    (await Effect.runPromise(Effect.flip(resource.verifier.verify(null)))) instanceof
      errors.Unauthorized,
  );

  // The browser entry points are what a page and a shared contract import. Bundling them
  // for the browser is the only way to prove that no verification code follows.
  await writeFile(
    join(directory, "browser.ts"),
    `export * from "${name}/errors";\nexport * from "${name}/session";\n`,
  );

  const bundled = await build({
    root: directory,
    logLevel: "error",
    configFile: false,
    build: {
      write: false,
      minify: false,
      lib: { entry: join(directory, "browser.ts"), formats: ["es"], fileName: "browser" },
    },
  });

  const chunks = bundled
    .flatMap((output) => output.output)
    .filter((chunk) => chunk.type === "chunk");

  const code = chunks.map((chunk) => chunk.code).join("\n");
  const modules = chunks.flatMap((chunk) => Object.keys(chunk.modules));

  assert(code.length > 0, "The browser entry points produced no bundle");

  for (const forbidden of ["jose", "verifyApiKey", "at+jwt"]) {
    assert(!code.includes(forbidden), `The browser bundle reaches server code: ${forbidden}`);
    assert(
      !modules.some((id) => id.includes(forbidden)),
      `The browser bundle pulls in a server module: ${forbidden}`,
    );
  }

  process.stdout.write(`${name}@${version} installs and loads\n`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
