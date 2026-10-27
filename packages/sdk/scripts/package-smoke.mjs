import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { Schema } from "effect";
import { build } from "vite";

import {
  assertDeclarations,
  execute,
  installPacked,
  packDependency,
} from "../../../scripts/package-install.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));

const Manifest = Schema.Struct({
  name: Schema.String,
  version: Schema.String,
  sideEffects: Schema.Boolean,
  dependencies: Schema.Record(Schema.String, Schema.String),
  peerDependencies: Schema.Record(Schema.String, Schema.String),
  peerDependenciesMeta: Schema.Struct({
    "@gjermundgaraba/effect-actions": Schema.Struct({
      optional: Schema.Boolean,
    }),
  }),
  exports: Schema.Record(
    Schema.String,
    Schema.Struct({ types: Schema.String })
  ),
});

const decodeManifest = Schema.decodeUnknownSync(
  Schema.fromJsonString(Manifest)
);

/** @param {string} directory The package's directory. */
const readManifest = async (directory) =>
  decodeManifest(await readFile(path.join(directory, "package.json"), "utf-8"));

const { name, version } = await readManifest(root);

const directory = await mkdtemp(
  path.join(tmpdir(), "clankerauth-sdk-install-")
);

/** @param {string} file The file to check, in the install directory. */
const typeCheck = async (file) =>
  await execute(
    process.execPath,
    [
      path.join(root, "node_modules/typescript/bin/tsc"),
      "--noEmit",
      "--strict",
      "--target",
      "ESNext",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      path.join(directory, file),
    ],
    { cwd: directory }
  );

/** @param {...string} files The files to compile, in the install directory. */
const emitDeclarations = async (...files) =>
  await execute(
    process.execPath,
    [
      path.join(root, "node_modules/typescript/bin/tsc"),
      "--declaration",
      "--emitDeclarationOnly",
      "--outDir",
      path.join(directory, "declarations"),
      "--strict",
      "--target",
      "ESNext",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      ...files.map((file) => path.join(directory, file)),
    ],
    { cwd: directory }
  );

/** @param {string} specifier The module to import from the install directory. */
const load = async (specifier) => {
  const file = path.join(
    directory,
    `${specifier.replaceAll(/[^\w-]/gu, "_")}.mjs`
  );

  await writeFile(file, `export * from "${specifier}";`);

  return await import(pathToFileURL(file).href);
};

try {
  await installPacked(directory, root, ["effect"]);
  const installed = path.join(directory, "node_modules", name);

  const manifest = await readManifest(installed);

  assert.equal(manifest.version, version);
  assert.equal(manifest.sideEffects, false);
  assert.equal(
    manifest.peerDependenciesMeta["@gjermundgaraba/effect-actions"].optional,
    true
  );
  assert.equal(
    manifest.dependencies["@gjermundgaraba/effect-actions"],
    undefined
  );
  assert.ok(
    manifest.peerDependencies.effect !== undefined &&
      manifest.peerDependencies.effect !== "",
    "effect must be a peer: a second copy would split its types and services"
  );
  assert.equal(manifest.dependencies.effect, undefined);

  const readme = await readFile(path.join(installed, "README.md"), "utf-8");

  assert.ok(
    readme.includes(
      `@gjermundgaraba/effect-actions@${manifest.peerDependencies["@gjermundgaraba/effect-actions"]}`
    ),
    "The README's effect-actions install line does not match the peer range"
  );
  await assertDeclarations(installed, manifest.exports);

  await writeFile(
    path.join(directory, "consumer.ts"),
    `
import { Effect } from "effect";
import { HttpClient } from "effect/http";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import type { AuthenticationError, ConfigurationError } from "@gjermundgaraba/clankerauth-sdk/errors";
const verification: Effect.Effect<Verifier.Principal, AuthenticationError | ConfigurationError, HttpClient.HttpClient> =
  Verifier.make({ issuer: "https://clankerauth.example/api/auth", resource: "https://notes.example/", store: Verifier.store() })
    .pipe(Effect.flatMap(verifier => verifier.verifyToken("token")));
void verification;
`
  );
  await typeCheck("consumer.ts");

  const api = await load(name);

  for (const exported of ["Verifier", "RequestPolicy"]) {
    assert.ok(exported in api, `Missing core export: ${exported}`);
  }

  for (const absent of [
    "Unauthorized",
    "InsufficientScope",
    "ProviderUnavailable",
  ]) {
    assert.ok(!(absent in api), `Root re-exports an error: ${absent}`);
  }

  const errors = await load(`${name}/errors`);

  for (const exported of [
    "Unauthorized",
    "InsufficientScope",
    "ProviderUnavailable",
    "ConfigurationError",
  ]) {
    assert.ok(exported in errors, `Missing error export: ${exported}`);
  }

  const { Effect } = await load("effect");
  const { FetchHttpClient } = await load("effect/http");

  const make = (options) =>
    Effect.runPromise(
      api.Verifier.make(options).pipe(Effect.provide(FetchHttpClient.layer))
    );

  const verifier = await make({
    issuer: "https://clankerauth.example/api/auth",
    resource: "https://notes.example/",
    store: api.Verifier.store(),
  });

  const missing = await Effect.runPromise(
    Effect.flip(verifier.verifyToken(""))
  );

  assert.ok(missing instanceof errors.Unauthorized);

  const keyList = await load(`${name}/key-list`);

  for (const exported of [
    "seal",
    "open",
    "digest",
    "type",
    "lifetime",
    "keyPrefix",
    "Entry",
    "Grant",
    "Claims",
  ]) {
    assert.ok(exported in keyList, `Missing key-list export: ${exported}`);
  }

  const credentials = await load(`${name}/credentials`);

  for (const exported of [
    "signIn",
    "token",
    "authorizing",
    "signOut",
    "list",
    "path",
    "SignIn",
    "SignInRequired",
    "TokenUnavailable",
    "SignInFailed",
  ]) {
    assert.ok(
      exported in credentials,
      `Missing credentials export: ${exported}`
    );
  }

  process.env.XDG_CONFIG_HOME = path.join(directory, "config");
  assert.deepEqual(await Effect.runPromise(credentials.signOut()), {
    signedOut: false,
  });
  assert.deepEqual(await Effect.runPromise(credentials.list()), []);

  const { startFakeIssuer } = await load(`${name}/testing`);
  const notes = "http://127.0.0.1:7337/";

  const issuer = await startFakeIssuer({
    resource: notes,
    scopes: ["notes:read", "notes:write"],
  });

  try {
    const key = issuer.apiKey();
    const store = api.Verifier.store();

    const listed = (held = api.Verifier.store()) =>
      make({ issuer: issuer.issuer, resource: notes, store: held });

    const installedVerifier = await listed(store);

    assert.deepEqual(
      await Effect.runPromise(installedVerifier.verifyToken(key)),
      {
        subject: "owner",
        scopes: ["notes:read", "notes:write"],
        actor: { kind: "key", keyId: "key-1" },
        expiresAt: undefined,
      }
    );
    await Effect.runPromise(installedVerifier.verifyToken(await issuer.sign()));
    issuer.revoke(key);
    const relisted = await listed(store);
    await Effect.runPromise(relisted.verifyToken(key));
    assert.equal(issuer.keyLists(), 1);

    const unlisted = await listed();

    const revoked = await Effect.runPromise(
      Effect.flip(unlisted.verifyToken(key))
    );

    assert.ok(revoked instanceof errors.Unauthorized);
    assert.equal(issuer.keyLists(), 2);
  } finally {
    await issuer.close();
  }

  await execute(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      await packDependency(directory, root, "@gjermundgaraba/effect-actions"),
    ],
    { cwd: directory }
  );
  await writeFile(
    path.join(directory, "integration.ts"),
    `
import { Effect } from "effect";
import type { Layer } from "effect";
import { HttpRouter } from "effect/http";
import type * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import { CurrentPrincipal, Principal, Whoami, returnToParameter, signOutPath, signOutUrl } from "@gjermundgaraba/clankerauth-sdk/session";
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
  publicUrl: new URL("https://notes.example"), store: Verifier.store(),
});
const subject = Effect.map(CurrentPrincipal, principal => principal.subject);
const page: (principal: Principal) => string = principal => signOutUrl(principal.issuer, "/");
const protocol: readonly [string, string] = [signOutPath, returnToParameter];
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
void protocol;
`
  );
  await typeCheck("integration.ts");

  // why: declared-actions.ts imports no SDK name, as an application's actions module does not.
  await writeFile(
    path.join(directory, "declared-resource.ts"),
    `
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import { ProviderUnavailable } from "@gjermundgaraba/clankerauth-sdk/errors";
import { CurrentPrincipal } from "@gjermundgaraba/clankerauth-sdk/session";
export const Login = Authentication.make("notes.Login", CurrentPrincipal, { error: ProviderUnavailable });
export const Notes = Resource.make(Login, { scopes: ["notes:read", "notes:write"], required: "notes:read" });
`
  );
  await writeFile(
    path.join(directory, "declared-actions.ts"),
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
`
  );
  await writeFile(
    path.join(directory, "declared-login.ts"),
    `
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { ProviderUnavailable } from "@gjermundgaraba/clankerauth-sdk/errors";
import { CurrentPrincipal } from "@gjermundgaraba/clankerauth-sdk/session";
export const Login = Authentication.make("notes.Login", CurrentPrincipal, { error: ProviderUnavailable });
`
  );
  await emitDeclarations("declared-resource.ts", "declared-actions.ts");
  // why: alone, so no other file's imports reach the type `/session` must name itself.
  await emitDeclarations("declared-login.ts");

  const { Resource } = await load(`${name}/effect-actions`);
  const { CurrentPrincipal } = await load(`${name}/session`);

  const { make: login } = await load(
    "@gjermundgaraba/effect-actions/Authentication"
  );

  const Notes = Resource.make(
    login("notes.Login", CurrentPrincipal, {
      error: errors.ProviderUnavailable,
    }),
    { scopes: ["notes:read"], required: "notes:read" }
  );

  const resource = await Effect.runPromise(
    Effect.service(Notes.service).pipe(
      Effect.provide(
        Notes.layer({
          issuer: "https://clankerauth.example/api/auth",
          publicUrl: new URL("https://notes.example"),
          store: api.Verifier.store(),
        })
      ),
      Effect.provide(FetchHttpClient.layer)
    )
  );

  assert.equal(resource.resource, "https://notes.example/");
  assert.deepEqual(Notes.local("owner").actor, { kind: "local" });
  assert.ok(
    (await Effect.runPromise(
      Effect.flip(resource.verifier.verifyToken(""))
    )) instanceof errors.Unauthorized
  );

  await writeFile(
    path.join(directory, "browser.ts"),
    `export * from "${name}/errors";\nexport * from "${name}/session";\n`
  );

  const bundled = await build({
    root: directory,
    logLevel: "error",
    configFile: false,
    build: {
      write: false,
      minify: false,
      lib: {
        entry: path.join(directory, "browser.ts"),
        formats: ["es"],
        fileName: "browser",
      },
    },
  });

  assert.ok(
    Array.isArray(bundled),
    "The library build returns its outputs as an array"
  );

  const chunks = bundled
    .flatMap((output) => output.output)
    .filter((chunk) => chunk.type === "chunk");

  const code = chunks.map((chunk) => chunk.code).join("\n");
  const modules = chunks.flatMap((chunk) => Object.keys(chunk.modules));

  assert.ok(code.length > 0, "The browser entry points produced no bundle");

  for (const forbidden of ["jose", "keyList", "key-list", "at+jwt"]) {
    assert.ok(
      !code.includes(forbidden),
      `The browser bundle reaches server code: ${forbidden}`
    );
    assert.ok(
      !modules.some((id) => id.includes(forbidden)),
      `The browser bundle pulls in a server module: ${forbidden}`
    );
  }

  process.stdout.write(`${name}@${version} installs and loads\n`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
