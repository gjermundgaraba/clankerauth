import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
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

/** Emits declarations for `files`, as a consumer package that exports what they declare does. */
const emitDeclarations = (...files) =>
  execute(
    process.execPath,
    [
      join(root, "node_modules/typescript/bin/tsc"),
      "--declaration",
      "--emitDeclarationOnly",
      "--outDir",
      join(directory, "declarations"),
      "--strict",
      "--target",
      "ESNext",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      ...files.map((file) => join(directory, file)),
    ],
    { cwd: directory },
  );

/**
 * The copy the workspace tests against, packed, which the isolated installation must use too:
 * a registry version or a local tarball alike.
 */
const tested = async (dependency) => {
  const { stdout } = await execute(
    "npm",
    [
      "pack",
      "--json",
      "--ignore-scripts",
      "--pack-destination",
      directory,
      await realpath(join(root, "node_modules", dependency)),
    ],
    { cwd: directory },
  );

  return join(directory, JSON.parse(stdout)[0].filename);
};

/** Imports an entry point the way a consumer in the isolated installation resolves it. */
const load = async (specifier) => {
  const file = join(directory, `${specifier.replaceAll(/[^\w-]/gu, "_")}.mjs`);
  await writeFile(file, `export * from "${specifier}";`);

  return import(pathToFileURL(file).href);
};

try {
  // pnpm resolves the workspace catalog protocol in the packed manifest; npm would not.
  await execute("pnpm", ["pack", "--pack-destination", directory], { cwd: root });
  const tarball = (await readdir(directory)).find((file) => file.endsWith(".tgz"));

  // Without one, npm would install the directory itself and test nothing that ships.
  if (tarball === undefined) throw new Error(`pnpm pack wrote no tarball to ${directory}`);
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
  for (const absent of ["Unauthorized", "InsufficientScope", "ProviderUnavailable"])
    assert(!(absent in api), `Root re-exports an error: ${absent}`);

  const errors = await load(`${name}/errors`);

  for (const exported of [
    "Unauthorized",
    "InsufficientScope",
    "ProviderUnavailable",
    "ConfigurationError",
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

  const missing = await Effect.runPromise(Effect.flip(verifier.verifyToken("")));
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
import type { Layer } from "effect";
import { HttpRouter } from "effect/http";
import type * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import type { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import { CurrentPrincipal, Principal, Whoami, signOutUrl } from "@gjermundgaraba/clankerauth-sdk/session";
import type { Caller } from "@gjermundgaraba/clankerauth-sdk/session";
import { ProviderUnavailable } from "@gjermundgaraba/clankerauth-sdk/errors";
const Notes = Resource.make(
  Authentication.make("notes.Login", CurrentPrincipal, { error: ProviderUnavailable }),
  { scopes: ["notes:read", "notes:write"], required: "notes:read" },
);
// @ts-expect-error A resource's descriptor declares the issuer being unreachable.
void Resource.make(Authentication.make("notes.Undeclared", CurrentPrincipal), {
  scopes: ["notes:read"],
  required: "notes:read",
});
// @ts-expect-error The scope every credential carries is one the resource has.
void Resource.make(Notes.authentication, { scopes: ["notes:read"], required: "notes:write" });
const layer = Notes.layer({
  issuer: "https://clankerauth.example/api/auth",
  publicUrl: new URL("https://notes.example"),
});
const subject = Effect.map(CurrentPrincipal, principal => principal.subject);
const page: (principal: Principal) => string = principal => signOutUrl(principal.issuer, "/");
void layer;
void Notes.provider;
void Notes.session;
void Notes.admitted().layer;
void Notes.admitted("notes:write").layer;
// @ts-expect-error A route requires a scope, not a contract's readOnly.
void Notes.admitted(true);
// @ts-expect-error A scope the resource does not declare is a type error.
void Notes.admitted("notes:wirte");
// @ts-expect-error So is one an authorizer requires.
void Notes.requires("notes:wirte");
void Effect.map(Notes.service, ({ admit, watch }) => [
  // @ts-expect-error And one a caller outside the router is admitted with.
  admit(undefined, "notes:wirte"),
  // @ts-expect-error And one a held connection is watched for.
  watch(undefined, "notes:wirte"),
  admit(undefined, "notes:write"),
  watch(undefined, "notes:write"),
]);
// The application's own rule, which its implementations state.
const authorize: (action: Action.Any) => Effect.Effect<void, Action.Forbidden, CurrentPrincipal> =
  (action) => (action.readOnly ? Effect.void : Notes.requires("notes:write"));
void authorize;
// Middleware of the host's own reading the caller, inside \`admitted\`.
const tagged: Layer.Layer<any, any, any> = HttpRouter.middleware((route) =>
  Effect.flatMap(CurrentPrincipal, () => route),
).combine(Notes.admitted("notes:write")).layer;
void tagged;
void Effect.provideService(subject, CurrentPrincipal, Notes.local("owner"));
// A verifier's principal is a caller; a local caller is no verifier's principal.
const verified = (principal: Verifier.Principal): Caller => principal;
// @ts-expect-error The process on a local surface is no verifier's result.
const local: Verifier.Principal = Notes.local("owner");
void verified;
void local;
void subject;
void Whoami.name;
void page;
`,
  );
  // The effect-actions package must also expose valid declarations.
  await typeCheck("integration.ts");

  // A consumer package exports its descriptor, its resource and the implementations stating
  // its authorizer, and emits declarations for them: every type those mention must be
  // nameable through an entry point. The second file imports no SDK name, as an
  // application's actions module does not.
  await writeFile(
    join(directory, "declared-resource.ts"),
    `
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import { ProviderUnavailable } from "@gjermundgaraba/clankerauth-sdk/errors";
import { CurrentPrincipal } from "@gjermundgaraba/clankerauth-sdk/session";
export const Login = Authentication.make("notes.Login", CurrentPrincipal, { error: ProviderUnavailable });
export const Notes = Resource.make(Login, { scopes: ["notes:read", "notes:write"], required: "notes:read" });
`,
  );
  await writeFile(
    join(directory, "declared-actions.ts"),
    `
import { Effect, Schema } from "effect";
import { HttpRouter } from "effect/http";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import { CurrentPrincipal } from "@gjermundgaraba/clankerauth-sdk/session";
import { Notes } from "./declared-resource.js";
const Read = Action.make("read", { description: "Read a note.", success: Schema.String, readOnly: true, caller: CurrentPrincipal });
export const authorize = (action: Action.Any) => action.readOnly ? Effect.void : Notes.requires("notes:write");
export const requires = Notes.requires;
export const apps = [
  Action.implement(Read, () => Effect.succeed("note"), { authorize }),
  Notes.session,
];
export const resource = Notes.layer;
export const provider = Notes.provider;
export const built = Effect.map(Notes.service, (resource) => resource);
export const admitted = Effect.flatMap(Notes.service, ({ admit }) => admit(undefined));
export const watched = Effect.flatMap(Notes.service, ({ watch }) => watch(null, "notes:write"));
export const verifier = Effect.map(Notes.service, (resource) => resource.verifier);
export const frame = Notes.admitted();
export const frameLayer = Notes.admitted("notes:write").layer;
export const admittedAt = Notes.admitted;
export const tagged = HttpRouter.middleware((route) =>
  Effect.flatMap(CurrentPrincipal, () => route),
).combine(Notes.admitted());
export const local = Notes.local("owner");
`,
  );
  // A shared contracts package declares its descriptor from the browser-safe entries alone.
  await writeFile(
    join(directory, "declared-login.ts"),
    `
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { ProviderUnavailable } from "@gjermundgaraba/clankerauth-sdk/errors";
import { CurrentPrincipal } from "@gjermundgaraba/clankerauth-sdk/session";
export const Login = Authentication.make("notes.Login", CurrentPrincipal, { error: ProviderUnavailable });
`,
  );
  await emitDeclarations("declared-resource.ts", "declared-actions.ts");
  // Alone, so no other file's imports reach the type `/session` must name itself.
  await emitDeclarations("declared-login.ts");

  const { Resource } = await load(`${name}/effect-actions`);
  const { CurrentPrincipal } = await load(`${name}/session`);
  const { make: login } = await load("@gjermundgaraba/effect-actions/Authentication");

  const Notes = Resource.make(
    login("notes.Login", CurrentPrincipal, { error: errors.ProviderUnavailable }),
    { scopes: ["notes:read"], required: "notes:read" },
  );

  const resource = await Effect.runPromise(
    Effect.service(Notes.service).pipe(
      Effect.provide(
        Notes.layer({
          issuer: "https://clankerauth.example/api/auth",
          publicUrl: new URL("https://notes.example"),
        }),
      ),
      Effect.provide(FetchHttpClient.layer),
    ),
  );

  assert.equal(resource.resource, "https://notes.example/");
  assert.deepEqual(Notes.local("owner").actor, { kind: "local" });
  assert(
    (await Effect.runPromise(Effect.flip(resource.verifier.verifyToken("")))) instanceof
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
