import { Context, type Effect, Schema, type Scope } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { HttpApiSchema, HttpApiSecurity } from "effect/http-api";

export class InternalServerError extends Schema.TaggedError<InternalServerError>()(
  "InternalServerError",
  { message: Schema.String },
  { httpApiStatus: 500 },
) {
  override cause?: unknown;

  static readonly of = (cause: unknown) => {
    const error = new InternalServerError({ message: "Request could not be completed" });
    error.cause = cause;

    return error;
  };
}

export class ServiceUnavailable extends Schema.TaggedError<ServiceUnavailable>()(
  "ServiceUnavailable",
  { message: Schema.String },
  { httpApiStatus: 503 },
) {}

export class ClientNotFound extends Schema.TaggedError<ClientNotFound>()(
  "ClientNotFound",
  { clientId: Schema.String, message: Schema.String },
  { httpApiStatus: 404 },
) {
  static readonly of = (clientId: string) =>
    new ClientNotFound({ clientId, message: `No client ${clientId} is registered` });
}

export class ResourceNotFound extends Schema.TaggedError<ResourceNotFound>()(
  "ResourceNotFound",
  { identifier: Schema.String, message: Schema.String },
  { httpApiStatus: 404 },
) {
  static readonly of = (identifier: string) =>
    new ResourceNotFound({ identifier, message: `No resource ${identifier} exists` });
}

export class ApiKeyNotFound extends Schema.TaggedError<ApiKeyNotFound>()(
  "ApiKeyNotFound",
  { keyId: Schema.String, message: Schema.String },
  { httpApiStatus: 404 },
) {
  static readonly of = (keyId: string) =>
    new ApiKeyNotFound({ keyId, message: `No API key ${keyId} exists` });
}

export class ClientIsAutomatic extends Schema.TaggedError<ClientIsAutomatic>()(
  "ClientIsAutomatic",
  { clientId: Schema.String, message: Schema.String },
  { httpApiStatus: 409 },
) {
  static readonly of = (clientId: string) =>
    new ClientIsAutomatic({
      clientId,
      message: `Client ${clientId} registered itself; revoke, block or delete it instead`,
    });
}

export class OwnerExists extends Schema.TaggedError<OwnerExists>()(
  "OwnerExists",
  { message: Schema.String },
  { httpApiStatus: 409 },
) {
  static readonly of = () => new OwnerExists({ message: "Setup already completed" });
}

export class ProviderRefused extends Schema.TaggedError<ProviderRefused>()(
  "ProviderRefused",
  { message: Schema.String },
  { httpApiStatus: 400 },
) {}

export class UnreadableRequest extends Schema.TaggedError<UnreadableRequest>()(
  "UnreadableRequest",
  { message: Schema.String },
  { httpApiStatus: 400 },
) {}

export const errors = [
  InternalServerError,
  ServiceUnavailable,
  ClientNotFound,
  ResourceNotFound,
  ApiKeyNotFound,
  ClientIsAutomatic,
  OwnerExists,
  ProviderRefused,
  UnreadableRequest,
] as const;

export type IssuerError = (typeof errors)[number]["Type"];

const undecided = [ServiceUnavailable, InternalServerError] as const;

export class CurrentOwner extends Context.Service<CurrentOwner, Owner>()(
  "clankerauth/CurrentOwner",
) {}

export interface Owner {
  readonly userId: string;
  readonly email: string;
  /** Whether the caller may change anything; the dashboard session always may. */
  readonly writable: boolean;
  readonly providerHeaders: Effect.Effect<Headers, InternalServerError, Scope.Scope>;
}

// why: the cookie name varies by deployment, and a layer serves only its own descriptor's binding.
export const ownerSession = (cookie: string) =>
  Authentication.make("clankerauth.OwnerSession", CurrentOwner, {
    security: HttpApiSecurity.apiKey({ in: "cookie", key: cookie }),
    error: undecided,
  });

// why: a browser sends its cookies itself, so only the server would read this cookie name.
export const OwnerSession = ownerSession("better-auth.session_token");

export const OwnerToken = Authentication.make("clankerauth.OwnerToken", CurrentOwner, {
  error: undecided,
});

export const administrationIdentifier = (origin: string) => new URL("/", origin).href;

export const administrationScopes = { read: "clankerauth:read", write: "clankerauth:write" };

export const MINIMUM_PASSWORD_LENGTH = 8;

export const MAXIMUM_PASSWORD_LENGTH = 128;

const passwordRule = `Passwords have ${MINIMUM_PASSWORD_LENGTH} to ${MAXIMUM_PASSWORD_LENGTH} characters`;

export const SetupInput = Schema.Struct({
  email: Schema.String.check(Schema.isPattern(/\S/u, { message: "Setup requires an email" })),
  password: Schema.String.check(
    Schema.isMinLength(MINIMUM_PASSWORD_LENGTH, { message: passwordRule }),
    Schema.isMaxLength(MAXIMUM_PASSWORD_LENGTH, { message: passwordRule }),
  ),
});

export const ClientAuthMethod = Schema.Literals([
  "none",
  "client_secret_basic",
  "client_secret_post",
]);

export const ApplicationType = Schema.Literals(["web", "native"]);

const ResourceSelection = Schema.Array(Schema.String).check(
  Schema.isUnique({ message: "Choose unique Resources" }),
);

export const ClientInput = Schema.Struct({
  client_name: Schema.String,
  redirect_uris: Schema.Array(Schema.String),
  resources: ResourceSelection,
  token_endpoint_auth_method: ClientAuthMethod,
  application_type: ApplicationType,
});

// why: the provider's update endpoint cannot change `token_endpoint_auth_method`.
export const ClientUpdateInput = Schema.Struct({
  client_id: Schema.String,
  client_name: Schema.String,
  redirect_uris: Schema.Array(Schema.String),
  application_type: ApplicationType,
});

export const ClientId = Schema.Struct({ client_id: Schema.String });

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

// why: the issuer trims each field before storing it, so these checks allow surrounding spaces.
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

const KeyGrants = Schema.Record(
  Schema.String,
  Schema.Array(Schema.String).check(
    Schema.isMinLength(1, {
      message: "Select explicitly granted, currently available Resource scopes",
    }),
    Schema.isUnique({ message: "Select explicitly granted, currently available Resource scopes" }),
  ),
).check(Schema.isMinProperties(1, { message: "Select at least one Resource and scope" }));

const KeyName = Schema.String.check(
  Schema.isMaxLength(100, { message: "Key names require 1–100 characters" }),
  Schema.isPattern(/\S/u, { message: "Key names require 1–100 characters" }),
);

// why: an input without an offset reads as UTC, so no instant depends on the host's time zone.
const Timestamp = Schema.DateTimeUtcFromString;

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

export const ApiKey = Schema.Struct({
  keyId: Schema.String,
  name: Schema.String,
  enabled: Schema.Boolean,
  permissions: KeyPermissions,
  expiresAt: Schema.NullOr(Timestamp),
  createdAt: Timestamp,
});

const anyone = { caller: Action.Anyone } as const;

const owned = { caller: CurrentOwner } as const;

export const IssuerActions = [
  Action.make("setupStatus", {
    description: "Check whether the issuer needs its first owner account.",
    readOnly: true,
    ...anyone,
    error: [InternalServerError],
    success: Schema.Struct({ required: Schema.Boolean }),
  }),
  Action.make("setupOwner", {
    description: "Create the first owner account.",
    readOnly: false,
    ...anyone,
    error: [OwnerExists, ProviderRefused, InternalServerError],
    input: SetupInput,
    success: Schema.Struct({ created: Schema.Boolean }).pipe(HttpApiSchema.status(201)),
  }),
  Action.make("keyList", {
    description:
      "The signed list a resource server verifies API keys against: one sealed entry per key granted on the resource, readable only with that key.",
    readOnly: true,
    ...anyone,
    error: [InternalServerError],
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
    error: [InternalServerError],
    success: ClientListResult,
  }),
  Action.make("createClient", {
    description: "Register a first-party OAuth client. Returns its secret once when confidential.",
    readOnly: false,
    ...owned,
    error: [ProviderRefused, InternalServerError],
    input: ClientInput,
    success: ClientCredentials.pipe(HttpApiSchema.status(201)),
  }),
  Action.make("updateClient", {
    description: "Rename a first-party client or change its redirect URIs and application type.",
    readOnly: false,
    ...owned,
    error: [ClientNotFound, ClientIsAutomatic, ProviderRefused, InternalServerError],
    input: ClientUpdateInput,
    success: Client,
  }),
  Action.make("deleteClient", {
    description:
      "Delete a client and its stored authorization. An automatic client can register again; block it to keep it out.",
    readOnly: false,
    ...owned,
    error: [ClientNotFound, InternalServerError],
    input: ClientId,
    success: Schema.Struct({ deleted: Schema.Boolean }),
  }),
  Action.make("revokeClient", {
    description:
      "Revoke a client’s stored authorization, for one resource or all. It must authorize again; an automatic client asks for consent.",
    readOnly: false,
    ...owned,
    error: [ClientNotFound, InternalServerError],
    input: ClientRevokeInput,
    success: Schema.Struct({ revoked: Schema.Boolean }),
  }),
  Action.make("blockClient", {
    description: "Block or unblock OAuth authorization for a client.",
    readOnly: false,
    ...owned,
    error: [ClientNotFound, InternalServerError],
    input: ClientBlockInput,
    success: Schema.Struct({ blocked: Schema.Boolean }),
  }),
  Action.make("rotateClientSecret", {
    description: "Rotate a confidential client secret. Returns the new secret once.",
    readOnly: false,
    ...owned,
    error: [ClientNotFound, ClientIsAutomatic, ProviderRefused, InternalServerError],
    input: ClientId,
    success: ClientCredentials,
  }),
  Action.make("setClientAccess", {
    description:
      "Set the resources a managed client may obtain. Removing one revokes its authorization for it. Automatic clients may ask for any resource with consent.",
    readOnly: false,
    ...owned,
    error: [ClientNotFound, ClientIsAutomatic, InternalServerError],
    input: ClientAccessInput,
    success: ClientAccessResult,
  }),
  Action.make("createResource", {
    description: "Create an OAuth resource and its scopes.",
    readOnly: false,
    ...owned,
    error: [ProviderRefused, InternalServerError],
    input: ResourceInput,
    success: Resource.pipe(HttpApiSchema.status(201)),
  }),
  Action.make("updateResource", {
    description: "Update an OAuth resource and its scopes.",
    readOnly: false,
    ...owned,
    error: [ResourceNotFound, ProviderRefused, InternalServerError],
    input: ResourceInput,
    success: Resource,
  }),
  Action.make("deleteResource", {
    description:
      "Delete a resource, its client access and every client’s authorization for it. API-key permissions are retained; recreating the resource restores them.",
    readOnly: false,
    ...owned,
    error: [ResourceNotFound, InternalServerError],
    input: ResourceId,
    success: Schema.Struct({ deleted: Schema.Boolean }),
  }),
  Action.make("listApiKeys", {
    description: "List API key metadata without secret values.",
    readOnly: true,
    ...owned,
    error: [InternalServerError],
    success: Schema.Struct({ keys: Schema.Array(ApiKey) }),
  }),
  Action.make("createApiKey", {
    description: "Create a scoped API key. Returns its secret once.",
    readOnly: false,
    ...owned,
    error: [ProviderRefused, InternalServerError],
    input: ApiKeyInput,
    success: ApiKey.pipe(Schema.fieldsAssign({ key: Schema.String }), HttpApiSchema.status(201)),
  }),
  Action.make("updateApiKey", {
    description: "Update an API key’s name, permissions or enabled state.",
    readOnly: false,
    ...owned,
    error: [ApiKeyNotFound, ProviderRefused, InternalServerError],
    input: ApiKeyUpdate,
    success: ApiKey,
  }),
  Action.make("deleteApiKey", {
    description: "Delete an API key.",
    readOnly: false,
    ...owned,
    error: [ApiKeyNotFound, InternalServerError],
    input: ApiKeyId,
    success: Schema.Struct({ deleted: Schema.Boolean }),
  }),
] as const;

export const binding = (authentication: typeof OwnerSession) =>
  ActionHttp.make([...Administration, ...IssuerActions], { authentication });

export const Http = binding(OwnerSession);

export const OwnerHttp = ActionHttp.make(Administration, {
  prefix: "/api/owner",
  authentication: OwnerToken,
});
