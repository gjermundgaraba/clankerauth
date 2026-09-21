import { Schema } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionGroup from "@gjermundgaraba/effect-actions/ActionGroup";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import { HttpApiSchema, type HttpApiError } from "effect/unstable/httpapi";

export class BadRequest extends Schema.TaggedError<BadRequest>()(
  "BadRequest",
  {
    error: Schema.String,
  },
  { httpApiStatus: 400 },
) {}

export class Unauthorized extends Schema.TaggedError<Unauthorized>()(
  "Unauthorized",
  {
    error: Schema.String,
  },
  { httpApiStatus: 401 },
) {}

export class Forbidden extends Schema.TaggedError<Forbidden>()(
  "Forbidden",
  {
    error: Schema.String,
  },
  { httpApiStatus: 403 },
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

export class InternalServerError extends Schema.TaggedError<InternalServerError>()(
  "InternalServerError",
  {
    error: Schema.String,
  },
  { httpApiStatus: 500 },
) {}

export class ServiceUnavailable extends Schema.TaggedError<ServiceUnavailable>()(
  "ServiceUnavailable",
  {
    error: Schema.String,
  },
  { httpApiStatus: 503 },
) {}

export const errors = [
  BadRequest,
  Unauthorized,
  Forbidden,
  NotFound,
  Conflict,
  TooManyRequests,
  InternalServerError,
  ServiceUnavailable,
];

export const SetupInput = Schema.Struct({ email: Schema.String, password: Schema.String });

export const ClientAuthMethod = Schema.Literals([
  "none",
  "client_secret_basic",
  "client_secret_post",
]);

export const ApplicationType = Schema.Literals(["web", "native"]);

/** Provider vocabulary: the server passes these fields through unchanged. */
export const ClientInput = Schema.Struct({
  client_name: Schema.String,
  redirect_uris: Schema.Array(Schema.String),
  resources: Schema.Array(Schema.String),
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

export const ResourceId = Schema.Struct({ identifier: Schema.String });

export const ClientAccess = Schema.Struct({
  client_id: Schema.String,
  resource: Schema.String,
});

export const ClientAccessInput = Schema.Struct({
  client_id: Schema.String,
  resources: Schema.Array(Schema.String),
});

export const ClientAccessResult = Schema.Struct({ clientAccess: Schema.Array(ClientAccess) });

export const KeyPermissions = Schema.Record(Schema.String, Schema.Array(Schema.String));

export const ApiKeyInput = Schema.Struct({
  name: Schema.String,
  permissions: KeyPermissions,
  expiresAt: Schema.NullOr(Schema.String),
});

export const ApiKeyId = Schema.Struct({ keyId: Schema.String });

export const ApiKeyUpdate = Schema.Struct({
  keyId: Schema.String,
  name: Schema.optional(Schema.String),
  permissions: Schema.optional(KeyPermissions),
  enabled: Schema.optional(Schema.Boolean),
});

export const MachineKey = Schema.Struct({
  keyId: Schema.String,
  name: Schema.String,
  enabled: Schema.Boolean,
  permissions: KeyPermissions,
  expiresAt: Schema.NullOr(Schema.String),
  createdAt: Schema.String,
});

// Every action can fail with shared API errors. HTTP maps native schema failures
// through the group policy; MCP retains its native validation and error responses.
const schemaError = {
  errors: [BadRequest, InternalServerError],
  map: (failure: HttpApiError.HttpApiSchemaError) =>
    failure.kind === "Body" || failure.kind === "ResponseHeaders"
      ? new InternalServerError({ error: "Request could not be completed" })
      : new BadRequest({ error: "Invalid request" }),
};

// These actions have their own access rules, not an owner-session requirement.
// They are HTTP-only: bootstrap and key introspection are not MCP administration tools.
export const IssuerActions = ActionGroup.make(
  { name: "issuer", errors, schemaError },
  Action.make("setupStatus", {
    description: "Check whether the issuer needs its first owner account.",
    access: "read",
    success: Schema.Struct({ required: Schema.Boolean }),
    mcp: false,
  }),
  Action.make("setupOwner", {
    description: "Create the first owner account.",
    access: "write",
    input: SetupInput,
    success: Schema.Struct({ created: Schema.Boolean }).pipe(HttpApiSchema.status(201)),
    mcp: false,
  }),
  Action.make("verifyApiKey", {
    description: "Verify the bearer API key against one resource and return its granted scopes.",
    access: "read",
    input: Schema.Struct({ resource: Schema.String }),
    success: Schema.Struct({
      keyId: Schema.String,
      ownerId: Schema.String,
      resource: Schema.String,
      scopes: Schema.Array(Schema.String),
      expiresAt: Schema.NullOr(Schema.String),
    }),
    mcp: false,
  }),
);

export const ClientListResult = Schema.Struct({
  clients: Schema.Array(Client),
  resources: Schema.Array(ResourceSummary),
  clientAccess: Schema.Array(ClientAccess),
  email: Schema.String,
  issuer: Schema.String,
});

export const Administration = ActionGroup.make(
  { name: "administration", errors, schemaError },
  Action.make("listClients", {
    description: "List clients, resources and access grants.",
    access: "read",
    success: ClientListResult,
  }),
  Action.make("createClient", {
    description: "Register a first-party OAuth client. Returns its secret once when confidential.",
    access: "write",
    input: ClientInput,
    success: ClientCredentials.pipe(HttpApiSchema.status(201)),
  }),
  Action.make("updateClient", {
    description: "Rename a first-party client or change its redirect URIs and application type.",
    access: "write",
    input: ClientUpdateInput,
    success: Client,
  }),
  Action.make("deleteClient", {
    description: "Delete a first-party OAuth client.",
    access: "write",
    input: ClientId,
    success: Schema.Struct({ deleted: Schema.Boolean }),
  }),
  Action.make("revokeClient", {
    description: "Revoke a client’s authorization grants.",
    access: "write",
    input: ClientId,
    success: Schema.Struct({ revoked: Schema.Boolean }),
  }),
  Action.make("blockClient", {
    description: "Block or unblock OAuth authorization for a client.",
    access: "write",
    input: ClientBlockInput,
    success: Schema.Struct({ blocked: Schema.Boolean }),
  }),
  Action.make("rotateClientSecret", {
    description: "Rotate a confidential client secret. Returns the new secret once.",
    access: "write",
    input: ClientId,
    success: ClientCredentials,
  }),
  Action.make("setClientAccess", {
    description: "Set the resources a client may request.",
    access: "write",
    input: ClientAccessInput,
    success: ClientAccessResult,
  }),
  Action.make("createResource", {
    description: "Create an OAuth resource and its scopes.",
    access: "write",
    input: Resource,
    success: Resource.pipe(HttpApiSchema.status(201)),
  }),
  Action.make("updateResource", {
    description: "Update an OAuth resource and its scopes.",
    access: "write",
    input: Resource,
    success: Resource,
  }),
  Action.make("deleteResource", {
    description:
      "Delete a resource and its client-resource links. Stored authorization grants and API-key permissions are retained; recreating the resource can restore access.",
    access: "write",
    input: ResourceId,
    success: Schema.Struct({ deleted: Schema.Boolean }),
  }),
  Action.make("listApiKeys", {
    description: "List API key metadata without secret values.",
    access: "read",
    success: Schema.Struct({ keys: Schema.Array(MachineKey) }),
  }),
  Action.make("createApiKey", {
    description: "Create a scoped API key. Returns its secret once.",
    access: "write",
    input: ApiKeyInput,
    success: MachineKey.pipe(
      Schema.fieldsAssign({ key: Schema.String }),
      HttpApiSchema.status(201),
    ),
  }),
  Action.make("updateApiKey", {
    description: "Update an API key’s name, permissions or enabled state.",
    access: "write",
    input: ApiKeyUpdate,
    success: MachineKey,
  }),
  Action.make("deleteApiKey", {
    description: "Delete an API key.",
    access: "write",
    input: ApiKeyId,
    success: Schema.Struct({ deleted: Schema.Boolean }),
  }),
);

export const Http = ActionHttp.make({ apiPath: "/api" }, Administration, IssuerActions);

export const Api = Http.api;
