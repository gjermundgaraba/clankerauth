import { Context, Schema } from "effect";
import {
  HttpApi,
  HttpApiEndpoint,
  HttpApiGroup,
  HttpApiMiddleware,
  HttpApiSchema,
} from "effect/unstable/httpapi";

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

const errors = [
  BadRequest,
  Unauthorized,
  Forbidden,
  NotFound,
  Conflict,
  TooManyRequests,
  InternalServerError,
  ServiceUnavailable,
];

export class ApiValidation extends HttpApiMiddleware.Service<ApiValidation>()(
  "ClankerAuth/ApiValidation",
  { error: [BadRequest, InternalServerError] },
) {}

export class CurrentOwner extends Context.Service<
  CurrentOwner,
  { readonly userId: string; readonly email: string }
>()("ClankerAuth/CurrentOwner") {}
export class OwnerAuthorization extends HttpApiMiddleware.Service<
  OwnerAuthorization,
  { provides: CurrentOwner }
>()("ClankerAuth/OwnerAuthorization", { error: errors }) {}
export class SetupProtection extends HttpApiMiddleware.Service<SetupProtection>()(
  "ClankerAuth/SetupProtection",
  { error: [BadRequest, Forbidden] },
) {}

export const SetupInput = Schema.Struct({ email: Schema.String, password: Schema.String });
export const ClientInput = Schema.Struct({
  name: Schema.String,
  redirect: Schema.String,
  resources: Schema.Array(Schema.String),
  confidential: Schema.Boolean,
  native: Schema.Boolean,
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

export const Api = HttpApi.make("ClankerAuth")
  .add(
    HttpApiGroup.make("apiKeys")
      .add(
        HttpApiEndpoint.get("list", "/admin/api-keys", {
          success: Schema.Struct({ keys: Schema.Array(MachineKey) }),
          error: errors,
        }),
        HttpApiEndpoint.post("create", "/admin/api-keys", {
          payload: ApiKeyInput,
          success: MachineKey.pipe(
            Schema.fieldsAssign({ key: Schema.String }),
            HttpApiSchema.status(201),
          ),
          error: errors,
        }),
        HttpApiEndpoint.post("update", "/admin/api-keys/update", {
          payload: ApiKeyUpdate,
          success: MachineKey,
          error: errors,
        }),
        HttpApiEndpoint.post("delete", "/admin/api-keys/delete", {
          payload: ApiKeyId,
          success: Schema.Struct({ deleted: Schema.Boolean }),
          error: errors,
        }),
      )
      .middleware(OwnerAuthorization),
    HttpApiGroup.make("keyVerification").add(
      HttpApiEndpoint.post("verify", "/api/api-keys/verify", {
        payload: Schema.Struct({ resource: Schema.String }),
        success: Schema.Struct({
          keyId: Schema.String,
          ownerId: Schema.String,
          resource: Schema.String,
          scopes: Schema.Array(Schema.String),
          expiresAt: Schema.NullOr(Schema.String),
        }),
        error: errors,
      }),
    ),
    HttpApiGroup.make("setup").add(
      HttpApiEndpoint.get("status", "/api/setup", {
        success: Schema.Struct({ required: Schema.Boolean }),
        error: errors,
      }),
      HttpApiEndpoint.post("create", "/api/setup", {
        payload: SetupInput,
        success: Schema.Struct({ created: Schema.Boolean }).pipe(HttpApiSchema.status(201)),
        error: errors,
      }).middleware(SetupProtection),
    ),
    HttpApiGroup.make("clients")
      .add(
        HttpApiEndpoint.get("list", "/admin/clients", {
          success: Schema.Struct({
            clients: Schema.Array(Client),
            resources: Schema.Array(Resource),
            clientAccess: Schema.Array(ClientAccess),
            email: Schema.String,
            issuer: Schema.String,
          }),
          error: errors,
        }),
        HttpApiEndpoint.post("create", "/admin/clients", {
          payload: ClientInput,
          success: ClientCredentials.pipe(HttpApiSchema.status(201)),
          error: errors,
        }),
        HttpApiEndpoint.post("delete", "/admin/clients/delete", {
          payload: ClientId,
          success: Schema.Struct({ deleted: Schema.Boolean }),
          error: errors,
        }),
        HttpApiEndpoint.post("revoke", "/admin/clients/revoke", {
          payload: ClientId,
          success: Schema.Struct({ revoked: Schema.Boolean }),
          error: errors,
        }),
        HttpApiEndpoint.post("block", "/admin/clients/block", {
          payload: ClientBlockInput,
          success: Schema.Struct({ blocked: Schema.Boolean }),
          error: errors,
        }),
        HttpApiEndpoint.post("rotate", "/admin/clients/rotate", {
          payload: ClientId,
          success: ClientCredentials,
          error: errors,
        }),
        HttpApiEndpoint.post("access", "/admin/clients/access", {
          payload: ClientAccessInput,
          success: ClientAccessResult,
          error: errors,
        }),
      )
      .middleware(OwnerAuthorization),
    HttpApiGroup.make("resources")
      .add(
        HttpApiEndpoint.post("create", "/admin/resources", {
          payload: Resource,
          success: Resource.pipe(HttpApiSchema.status(201)),
          error: errors,
        }),
        HttpApiEndpoint.post("update", "/admin/resources/update", {
          payload: Resource,
          success: Resource,
          error: errors,
        }),
        HttpApiEndpoint.post("delete", "/admin/resources/delete", {
          payload: ResourceId,
          success: Schema.Struct({ deleted: Schema.Boolean }),
          error: errors,
        }),
      )
      .middleware(OwnerAuthorization),
  )
  .middleware(ApiValidation);
