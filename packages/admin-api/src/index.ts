import { Context, type Effect, Schema, type Scope } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { HttpApiSchema, HttpApiSecurity } from "effect/http-api";

export class BadRequest extends Schema.TaggedError<BadRequest>()(
  "BadRequest",
  {
    error: Schema.String,
  },
  { httpApiStatus: 400 },
) {}

export class NotFound extends Schema.TaggedError<NotFound>()(
  "NotFound",
  {
    error: Schema.String,
  },
  { httpApiStatus: 404 },
) {}

export class Conflict extends Schema.TaggedError<Conflict>()(
  "Conflict",
  {
    error: Schema.String,
  },
  { httpApiStatus: 409 },
) {}

export class TooManyRequests extends Schema.TaggedError<TooManyRequests>()(
  "TooManyRequests",
  {
    error: Schema.String,
  },
  { httpApiStatus: 429 },
) {}

/** The schema defines the public response; the diagnostic cause reaches logs, never a caller. */
export class InternalServerError extends Schema.TaggedError<InternalServerError>()(
  "InternalServerError",
  {
    error: Schema.String,
  },
  { httpApiStatus: 500 },
) {
  override cause?: unknown;
}

export class ServiceUnavailable extends Schema.TaggedError<ServiceUnavailable>()(
  "ServiceUnavailable",
  {
    error: Schema.String,
  },
  { httpApiStatus: 503 },
) {}

/**
 * What every action may fail with, beside effect-actions' built-in `InvalidInput`,
 * `Unauthenticated` and `Forbidden`, which every endpoint and tool declares.
 */
export const errors = [
  BadRequest,
  NotFound,
  Conflict,
  TooManyRequests,
  InternalServerError,
  ServiceUnavailable,
] as const;

/**
 * What administration refuses with, and the issuer answers its own routes with: the
 * contract's errors and the built-in `Forbidden`.
 */
export const ownerErrors = [...errors, Action.Forbidden] as const;

export type OwnerError = (typeof ownerErrors)[number]["Type"];

/**
 * The owner administering the issuer, as its authentication verified the request: what every
 * administration action states, `caller: CurrentOwner`. Never supplied by action arguments or
 * at startup.
 */
export class CurrentOwner extends Context.Service<CurrentOwner, Owner>()(
  "clankerauth/CurrentOwner",
) {}

export interface Owner {
  readonly userId: string;
  readonly email: string;
  /** Whether the caller may change anything; the dashboard session always may. */
  readonly writable: boolean;
  readonly providerHeaders: Effect.Effect<Headers, OwnerError, Scope.Scope>;
}

/**
 * The dashboard's owner session: the issuer's session cookie, named `cookie`, which the browser
 * sends. The provider names that cookie by the deployment, `__Secure-` prefixed over HTTPS, so
 * the server builds this descriptor where it starts, from the name its sessions use, and builds
 * both its binding and its `Authentication.layer` from it: that layer serves only a binding
 * built from that very descriptor, not another naming the same cookie. A browser's binding,
 * from `OwnerSession`, only calls. Its verifier reads the session through the provider, so it
 * may fail as an action does, with any of `errors`, such as `ServiceUnavailable`, answered with
 * its own status.
 */
export const ownerSession = (cookie: string) =>
  Authentication.make("clankerauth.OwnerSession", CurrentOwner, {
    security: HttpApiSecurity.apiKey({ in: "cookie", key: cookie }),
    error: errors,
  });

/**
 * The browser's owner session. A page never needs the cookie's name, as the browser sends its
 * cookies itself: this one names the provider's cookie over plain HTTP, which only the server
 * would read.
 */
export const OwnerSession = ownerSession("better-auth.session_token");

/**
 * An administration MCP client's OAuth access token for `<baseURL>/mcp`. Its verifier reads
 * the token's owner and client from the database, so it may fail as an action does, with any
 * of `errors`: `ServiceUnavailable` when the token cannot be decided, or `InternalServerError`.
 */
export const OwnerToken = Authentication.make("clankerauth.OwnerToken", CurrentOwner, {
  error: errors,
});

export const SetupInput = Schema.Struct({ email: Schema.String, password: Schema.String });

export const ClientAuthMethod = Schema.Literals([
  "none",
  "client_secret_basic",
  "client_secret_post",
]);

export const ApplicationType = Schema.Literals(["web", "native"]);

/** The resources a managed client may obtain, each named once. */
const ResourceSelection = Schema.Array(Schema.String).check(
  Schema.isUnique({ message: "Choose unique Resources" }),
);

/** Provider vocabulary: the server passes these fields through unchanged. */
export const ClientInput = Schema.Struct({
  client_name: Schema.String,
  redirect_uris: Schema.Array(Schema.String),
  resources: ResourceSelection,
  token_endpoint_auth_method: ClientAuthMethod,
  application_type: ApplicationType,
});

/** The provider's update endpoint cannot change the authentication method. */
export const ClientUpdateInput = Schema.Struct({
  client_id: Schema.String,
  client_name: Schema.String,
  redirect_uris: Schema.Array(Schema.String),
  application_type: ApplicationType,
});

export const ClientId = Schema.Struct({ client_id: Schema.String });

/** Without a resource, every authorization the client holds. */
export const ClientRevokeInput = Schema.Struct({
  client_id: Schema.String,
  resource: Schema.optional(Schema.String),
});

export const ClientBlockInput = Schema.Struct({
  client_id: Schema.String,
  blocked: Schema.Boolean,
});

export const Client = Schema.Struct({
  onboarding: Schema.optional(Schema.Literals(["managed", "dcr", "cimd"])),
  blocked: Schema.optional(Schema.Boolean),
  client_id: Schema.String,
  client_name: Schema.optional(Schema.String),
  redirect_uris: Schema.Array(Schema.String),
  token_endpoint_auth_method: Schema.optional(Schema.String),
  application_type: Schema.optional(Schema.NullOr(Schema.String)),
  scope: Schema.optional(Schema.String),
  grant_types: Schema.optional(Schema.Array(Schema.String)),
});

export const ClientCredentials = Client.pipe(
  Schema.fieldsAssign({
    client_secret: Schema.optional(Schema.String),
    client_secret_expires_at: Schema.optional(Schema.Number),
  }),
);

export const Resource = Schema.Struct({
  identifier: Schema.String,
  name: Schema.String,
  scopes: Schema.Array(Schema.String),
});

export const ResourceSummary = Resource.pipe(Schema.fieldsAssign({ builtIn: Schema.Boolean }));

/**
 * A resource as the owner writes it. The issuer trims each field before storing it, so the
 * rules allow surrounding whitespace: a name that is not blank, and scopes that are OAuth
 * scope tokens (RFC 6749 §3.3). Stored resources are `Resource`, which carries no rule.
 */
export const ResourceInput = Schema.Struct({
  identifier: Schema.String,
  name: Schema.String.check(Schema.isPattern(/\S/u, { message: "Resources require a name" })),
  scopes: Schema.Array(
    Schema.String.check(
      Schema.isPattern(/^\s*[\x21\x23-\x5B\x5D-\x7E]+\s*$/u, {
        message: "Resources require well-formed custom scopes",
      }),
    ),
  ),
});

export const ResourceId = Schema.Struct({ identifier: Schema.String });

export const ClientAccess = Schema.Struct({
  client_id: Schema.String,
  resource: Schema.String,
});

export const ClientAccessInput = Schema.Struct({
  client_id: Schema.String,
  resources: ResourceSelection,
});

export const ClientAccessResult = Schema.Struct({ clientAccess: Schema.Array(ClientAccess) });

export const KeyPermissions = Schema.Record(Schema.String, Schema.Array(Schema.String));

/**
 * Permissions as the owner grants them: at least one resource, each with scopes named once.
 * A stored key's are `KeyPermissions`, which a key whose permissions no longer decode is
 * listed with, empty.
 */
const KeyGrants = Schema.Record(
  Schema.String,
  Schema.Array(Schema.String).check(
    Schema.isMinLength(1, {
      message: "Select explicitly granted, currently available Resource scopes",
    }),
    Schema.isUnique({ message: "Select explicitly granted, currently available Resource scopes" }),
  ),
).check(Schema.isMinProperties(1, { message: "Select at least one Resource and scope" }));

/** A key's name as the owner writes it; the issuer stores it trimmed. */
const KeyName = Schema.String.check(
  Schema.isMaxLength(100, { message: "Key names require 1–100 characters" }),
  Schema.isPattern(/\S/u, { message: "Key names require 1–100 characters" }),
);

/**
 * Timestamps stay ISO strings on the wire and arrive as `DateTime.Utc` values. An input
 * without an offset is read as UTC, so the instant an API caller means never depends on
 * the host's time zone; every value this issuer writes carries `Z`.
 */
const Timestamp = Schema.DateTimeUtcFromString;

/**
 * What a client holds for one resource: a consent, a live refresh token, or both. A
 * managed client skips consent, so `approvedAt` is null for it and it shows only while it
 * holds a refresh token. `scopes` are the consent's, else the newest token's.
 * `refreshedAt` is when the newest live refresh token was issued, at sign-in or on refresh.
 */
export const Connection = Schema.Struct({
  client_id: Schema.String,
  resource: Schema.String,
  scopes: Schema.Array(Schema.String),
  approvedAt: Schema.NullOr(Timestamp),
  refreshedAt: Schema.NullOr(Timestamp),
});

export const ApiKeyInput = Schema.Struct({
  name: KeyName,
  permissions: KeyGrants,
  expiresAt: Schema.NullOr(Timestamp),
});

export const ApiKeyId = Schema.Struct({ keyId: Schema.String });

export const ApiKeyUpdate = Schema.Struct({
  keyId: Schema.String,
  name: Schema.optional(KeyName),
  permissions: Schema.optional(KeyGrants),
  enabled: Schema.optional(Schema.Boolean),
});

export const MachineKey = Schema.Struct({
  keyId: Schema.String,
  name: Schema.String,
  enabled: Schema.Boolean,
  permissions: KeyPermissions,
  expiresAt: Schema.NullOr(Timestamp),
  createdAt: Timestamp,
});

/** What every issuer action shares: any caller, and the contract's errors. */
const anyone = { caller: Action.Anyone, error: errors } as const;

/** What every administration action shares: the owner as its caller, and the contract's errors. */
const owned = { caller: CurrentOwner, error: errors } as const;

// These actions have their own access rules, not an owner-session requirement.
// They are HTTP-only: bootstrap and key lists are not MCP administration tools.
export const IssuerActions = [
  Action.make("setupStatus", {
    description: "Check whether the issuer needs its first owner account.",
    readOnly: true,
    ...anyone,
    success: Schema.Struct({ required: Schema.Boolean }),
  }),
  Action.make("setupOwner", {
    description: "Create the first owner account.",
    readOnly: false,
    ...anyone,
    input: SetupInput,
    success: Schema.Struct({ created: Schema.Boolean }).pipe(HttpApiSchema.status(201)),
  }),
  Action.make("keyList", {
    description:
      "The signed list a resource server verifies API keys against: one sealed entry per key granted on the resource, readable only with that key.",
    readOnly: true,
    ...anyone,
    input: Schema.Struct({ resource: Schema.String }),
    success: Schema.Struct({ list: Schema.String }),
  }),
] as const;

export const ClientListResult = Schema.Struct({
  clients: Schema.Array(Client),
  resources: Schema.Array(ResourceSummary),
  clientAccess: Schema.Array(ClientAccess),
  connections: Schema.Array(Connection),
  email: Schema.String,
  issuer: Schema.String,
});

export const Administration = [
  Action.make("listClients", {
    description:
      "List clients, resources, managed clients' resource access (what they may obtain), and every client's connections (what it holds).",
    readOnly: true,
    ...owned,
    success: ClientListResult,
  }),
  Action.make("createClient", {
    description: "Register a first-party OAuth client. Returns its secret once when confidential.",
    readOnly: false,
    ...owned,
    input: ClientInput,
    success: ClientCredentials.pipe(HttpApiSchema.status(201)),
  }),
  Action.make("updateClient", {
    description: "Rename a first-party client or change its redirect URIs and application type.",
    readOnly: false,
    ...owned,
    input: ClientUpdateInput,
    success: Client,
  }),
  Action.make("deleteClient", {
    description:
      "Delete a client and its stored authorization. An automatic client can register again; block it to keep it out.",
    readOnly: false,
    ...owned,
    input: ClientId,
    success: Schema.Struct({ deleted: Schema.Boolean }),
  }),
  Action.make("revokeClient", {
    description:
      "Revoke a client’s stored authorization, for one resource or all. It must authorize again; an automatic client asks for consent.",
    readOnly: false,
    ...owned,
    input: ClientRevokeInput,
    success: Schema.Struct({ revoked: Schema.Boolean }),
  }),
  Action.make("blockClient", {
    description: "Block or unblock OAuth authorization for a client.",
    readOnly: false,
    ...owned,
    input: ClientBlockInput,
    success: Schema.Struct({ blocked: Schema.Boolean }),
  }),
  Action.make("rotateClientSecret", {
    description: "Rotate a confidential client secret. Returns the new secret once.",
    readOnly: false,
    ...owned,
    input: ClientId,
    success: ClientCredentials,
  }),
  Action.make("setClientAccess", {
    description:
      "Set the resources a managed client may obtain. Removing one revokes its authorization for it. Automatic clients may ask for any resource with consent.",
    readOnly: false,
    ...owned,
    input: ClientAccessInput,
    success: ClientAccessResult,
  }),
  Action.make("createResource", {
    description: "Create an OAuth resource and its scopes.",
    readOnly: false,
    ...owned,
    input: ResourceInput,
    success: Resource.pipe(HttpApiSchema.status(201)),
  }),
  Action.make("updateResource", {
    description: "Update an OAuth resource and its scopes.",
    readOnly: false,
    ...owned,
    input: ResourceInput,
    success: Resource,
  }),
  Action.make("deleteResource", {
    description:
      "Delete a resource, its client access and every client’s authorization for it. API-key permissions are retained; recreating the resource restores them.",
    readOnly: false,
    ...owned,
    input: ResourceId,
    success: Schema.Struct({ deleted: Schema.Boolean }),
  }),
  Action.make("listApiKeys", {
    description: "List API key metadata without secret values.",
    readOnly: true,
    ...owned,
    success: Schema.Struct({ keys: Schema.Array(MachineKey) }),
  }),
  Action.make("createApiKey", {
    description: "Create a scoped API key. Returns its secret once.",
    readOnly: false,
    ...owned,
    input: ApiKeyInput,
    success: MachineKey.pipe(
      Schema.fieldsAssign({ key: Schema.String }),
      HttpApiSchema.status(201),
    ),
  }),
  Action.make("updateApiKey", {
    description: "Update an API key’s name, permissions or enabled state.",
    readOnly: false,
    ...owned,
    input: ApiKeyUpdate,
    success: MachineKey,
  }),
  Action.make("deleteApiKey", {
    description: "Delete an API key.",
    readOnly: false,
    ...owned,
    input: ApiKeyId,
    success: Schema.Struct({ deleted: Schema.Boolean }),
  }),
] as const;

/**
 * Every action over HTTP, at `/api/<action>`, owner administration authenticated by
 * `authentication`: the server's, from its deployment's cookie, or the browser's
 * `OwnerSession`. Resource servers read `/api/keyList`, so that path is part of the protocol.
 */
export const binding = (authentication: typeof OwnerSession) =>
  ActionHttp.make([...Administration, ...IssuerActions], { authentication });

/** The browser's binding, and a typed client's: the cookie name is the server's concern. */
export const Http = binding(OwnerSession);
