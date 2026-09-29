import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { build } from "vite";

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

/** The version the workspace tests against, which the isolated installation must use too. */
const tested = async (dependency) =>
  `${dependency}@${JSON.parse(await readFile(join(root, "node_modules", dependency, "package.json"), "utf8")).version}`;

/** Imports an entry point the way a consumer in the isolated installation resolves it. */
const load = async (specifier) => {
  const file = join(directory, `${specifier.replaceAll(/[^\w-]/gu, "_")}.mjs`);
  await writeFile(file, `export * from "${specifier}";`);

  return import(pathToFileURL(file).href);
};

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
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      join(directory, tarball),
      await tested("effect"),
    ],
    { cwd: directory },
  );
  const installed = join(directory, "node_modules", name);
  const manifest = JSON.parse(await readFile(join(installed, "package.json"), "utf8"));
  assert.equal(manifest.version, version);
  assert.equal(manifest.sideEffects, false);
  assert.equal(manifest.peerDependenciesMeta["@gjermundgaraba/effect-actions"].optional, true);
  assert.equal(manifest.dependencies["@gjermundgaraba/effect-actions"], undefined);
  // The application's Effect is the SDK's: a second copy would split its types and services.
  assert.ok(manifest.peerDependencies.effect);
  assert.equal(manifest.dependencies.effect, undefined);

  // The README's install line is the peer range, so it cannot drift past a breaking minor.
  assert.ok(
    (await readFile(join(installed, "README.md"), "utf8")).includes(
      `@gjermundgaraba/effect-actions@${manifest.peerDependencies["@gjermundgaraba/effect-actions"]}`,
    ),
    "The README's effect-actions install line does not match the peer range",
  );

  // Every entry point ships declarations; a build that emits only some of them is
  // invisible until a consumer imports the one that is missing.
  for (const [entry, target] of Object.entries(manifest.exports))
    assert.ok(
      (await readFile(join(installed, target.types), "utf8")).length > 0,
      `Entry point ships no declarations: ${entry}`,
    );

  await writeFile(
    join(directory, "consumer.ts"),
    `
import { Effect } from "effect";
import { HttpClient } from "effect/http";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import type { AuthenticationError, ConfigurationError } from "@gjermundgaraba/clankerauth-sdk/errors";
const verification: Effect.Effect<Verifier.Principal, AuthenticationError | ConfigurationError, HttpClient.HttpClient> =
  Verifier.make({ issuer: "https://clankerauth.example/api/auth", resource: "https://notes.example/" })
    .pipe(Effect.flatMap(verifier => verifier.verifyToken("token")));
void verification;
`,
  );
  // Core consumers type-check without installing effect-actions or skipping declarations.
  await typeCheck("consumer.ts");

  const api = await load(name);

  for (const exported of ["Verifier", "RequestPolicy"])
    assert(exported in api, `Missing core export: ${exported}`);

  // Errors live behind `/errors` only, so a shared contract cannot reach for them here.
  for (const absent of ["Unauthorized", "InsufficientScope", "authenticationErrors"])
    assert(!(absent in api), `Root re-exports an error: ${absent}`);

  const errors = await load(`${name}/errors`);

  for (const exported of [
    "Unauthorized",
    "InsufficientScope",
    "ProviderUnavailable",
    "ConfigurationError",
    "authenticationErrors",
  ])
    assert(exported in errors, `Missing error export: ${exported}`);

  // Resolve Effect from the isolated installation, not the workspace's development dependencies.
  const { Effect } = await load("effect");
  const { FetchHttpClient } = await load("effect/http");

  const make = (options) =>
    Effect.runPromise(api.Verifier.make(options).pipe(Effect.provide(FetchHttpClient.layer)));

  const verifier = await make({
    issuer: "https://clankerauth.example/api/auth",
    resource: "https://notes.example/",
  });

  const missing = await Effect.runPromise(Effect.flip(verifier.verify(null)));
  assert(missing instanceof errors.Unauthorized);

  const keyList = await load(`${name}/key-list`);

  for (const exported of ["seal", "open", "digest", "type", "lifetime", "Entry", "Grant", "Claims"])
    assert(exported in keyList, `Missing key-list export: ${exported}`);

  // Verify API keys offline against the installed fake issuer, and a revocation in the
  // next list, through the installed package.
  const { startFakeIssuer } = await load(`${name}/testing`);
  const notes = "http://127.0.0.1:7337/";
  const issuer = await startFakeIssuer({ resource: notes, scopes: ["notes:read", "notes:write"] });

  try {
    const key = issuer.apiKey();
    const listed = () => make({ issuer: issuer.issuer, resource: notes });
    const installedVerifier = await listed();

    assert.deepEqual(await Effect.runPromise(installedVerifier.verifyToken(key)), {
      subject: "owner",
      scopes: ["notes:read", "notes:write"],
      actor: { kind: "key", keyId: "key-1" },
      // This key does not expire.
      expiresAt: undefined,
    });
    await Effect.runPromise(installedVerifier.verifyToken(await issuer.sign()));
    issuer.revoke(key);
    const revoked = await Effect.runPromise(Effect.flip((await listed()).verifyToken(key)));
    assert(revoked instanceof errors.Unauthorized);
    assert.equal(issuer.keyLists(), 2);
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
      await tested("@gjermundgaraba/effect-actions"),
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
  issuer: "https://clankerauth.example/api/auth",
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
  const { Resource } = await load(`${name}/effect-actions`);

  const resource = await Effect.runPromise(
    Resource.make({
      issuer: "https://clankerauth.example/api/auth",
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

  for (const forbidden of ["jose", "keyList", "key-list", "at+jwt"]) {
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
