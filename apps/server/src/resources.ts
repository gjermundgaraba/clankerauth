import type Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { Schema } from "effect";
import { APIError } from "better-auth/api";
import { ClientAccess, Resource } from "@clankerauth/api";

export const protocolScopes = ["openid", "profile", "email", "offline_access"];
export const resourceReference = (identifier: string) => `resource:${identifier}`;
const strings = Schema.decodeUnknownSync(Schema.Array(Schema.String));
const resourceRow = Schema.decodeUnknownSync(
  Schema.Struct({
    identifier: Schema.String,
    name: Schema.String,
    allowedScopes: Schema.String,
  }),
);
const accessRows = Schema.decodeUnknownSync(Schema.Array(ClientAccess));
const credentialRows = Schema.decodeUnknownSync(
  Schema.Array(
    Schema.Struct({
      id: Schema.String,
      scopes: Schema.String,
    }),
  ),
);
const codeRows = Schema.decodeUnknownSync(
  Schema.Array(
    Schema.Struct({
      id: Schema.String,
      value: Schema.String,
    }),
  ),
);
const codeShape = Schema.Struct({
  type: Schema.Literal("authorization_code"),
  query: Schema.Struct({ client_id: Schema.String, scope: Schema.optional(Schema.String) }),
  referenceId: Schema.String,
});
const decodeScopes = (value: string) => strings(JSON.parse(value));
type ResourceValue = typeof Resource.Type;

// These synchronous operations target the pinned provider schema. Callers admit
// them through Service.exclusive, so async provider operations cannot interleave.
export function resourceStore(db: Database.Database, changed: (scopes: string[]) => void) {
  const decodeResource = (value: unknown): ResourceValue => {
    const row = resourceRow(value);
    return {
      identifier: row.identifier,
      name: row.name,
      scopes: decodeScopes(row.allowedScopes).filter((scope) => !protocolScopes.includes(scope)),
    };
  };
  const list = () =>
    db
      .prepare(
        "SELECT identifier, name, allowedScopes FROM oauthResource ORDER BY createdAt, identifier",
      )
      .all()
      .map(decodeResource);
  const get = (identifier: string) => {
    const row = db
      .prepare("SELECT identifier, name, allowedScopes FROM oauthResource WHERE identifier = ?")
      .get(identifier);
    return row ? decodeResource(row) : undefined;
  };
  const access = () =>
    accessRows(
      db
        .prepare(
          "SELECT clientId AS client_id, resourceId AS resource FROM oauthClientResource ORDER BY clientId, resourceId",
        )
        .all(),
    );
  const validateSelection = (identifiers: readonly string[]) => {
    if (new Set(identifiers).size !== identifiers.length)
      throw new APIError("BAD_REQUEST", { message: "Choose unique Resources" });
    return identifiers.map((id) => {
      const resource = get(id);
      if (!resource) throw new APIError("BAD_REQUEST", { message: "Unknown Resource" });
      return resource;
    });
  };
  const scopesFor = (identifiers: readonly string[]) => [
    ...new Set([
      ...protocolScopes,
      ...validateSelection(identifiers).flatMap((resource) => resource.scopes),
    ]),
  ];
  const validate = (input: ResourceValue): ResourceValue => {
    const identifier = input.identifier.trim();
    const name = input.name.trim();
    const scopes = [...new Set(input.scopes.map((scope) => scope.trim()))];
    let uri: URL;
    try {
      uri = new URL(identifier);
    } catch {
      throw new APIError("BAD_REQUEST", { message: "Invalid Resource identifier" });
    }
    if (
      uri.protocol !== "https:" ||
      identifier.includes("#") ||
      identifier.includes("?") ||
      uri.username ||
      uri.password
    )
      throw new APIError("BAD_REQUEST", {
        message: "Resource identifiers must be HTTPS URLs without credentials, query or fragment",
      });
    if (
      !name ||
      !scopes.length ||
      scopes.some((scope) => !/^[a-z][a-z0-9:-]+$/.test(scope) || protocolScopes.includes(scope))
    )
      throw new APIError("BAD_REQUEST", {
        message: "Resources require a name and nonempty custom scopes",
      });
    return { identifier, name, scopes };
  };
  const syncClient = (clientId: string) => {
    const identifiers = access()
      .filter((link) => link.client_id === clientId)
      .map((link) => link.resource);
    db.prepare("UPDATE oauthClient SET scopes = ?, updatedAt = ? WHERE clientId = ?").run(
      JSON.stringify(scopesFor(identifiers)),
      Date.now(),
      clientId,
    );
  };
  const cleanup = (clientId: string, identifier: string, removed?: readonly string[]) => {
    const reference = resourceReference(identifier);
    const affected = (scopes: readonly string[]) =>
      !removed || scopes.some((scope) => removed.includes(scope));
    const predicate = "clientId = ? AND referenceId = ?";
    const consents = credentialRows(
      db.prepare(`SELECT id, scopes FROM oauthConsent WHERE ${predicate}`).all(clientId, reference),
    );
    for (const consent of consents) {
      if (!removed) db.prepare("DELETE FROM oauthConsent WHERE id = ?").run(consent.id);
      else
        db.prepare("UPDATE oauthConsent SET scopes = ?, updatedAt = ? WHERE id = ?").run(
          JSON.stringify(decodeScopes(consent.scopes).filter((scope) => !removed.includes(scope))),
          Date.now(),
          consent.id,
        );
    }
    for (const row of codeRows(
      db
        .prepare(
          "SELECT id, value FROM verification WHERE json_valid(value) AND json_extract(value, '$.type') = 'authorization_code' AND json_extract(value, '$.referenceId') = ? AND json_extract(value, '$.query.client_id') = ?",
        )
        .all(reference, clientId),
    )) {
      const value: unknown = JSON.parse(row.value);
      if (!Schema.is(codeShape)(value)) throw new Error("Invalid stored authorization code");
      if (affected(value.query.scope?.split(" ") ?? []))
        db.prepare("DELETE FROM verification WHERE id = ?").run(row.id);
    }
    // Delete dependents before refresh tokens because refreshId is a foreign key.
    for (const table of ["oauthAccessToken", "oauthRefreshToken"]) {
      const rows = credentialRows(
        db.prepare(`SELECT id, scopes FROM ${table} WHERE ${predicate}`).all(clientId, reference),
      );
      for (const row of rows)
        if (affected(decodeScopes(row.scopes))) {
          if (table === "oauthRefreshToken")
            db.prepare("DELETE FROM oauthAccessToken WHERE refreshId = ?").run(row.id);
          db.prepare(`DELETE FROM ${table} WHERE id = ?`).run(row.id);
        }
    }
  };
  const supportedScopes = () => [
    ...new Set([...protocolScopes, ...list().flatMap((resource) => resource.scopes)]),
  ];
  const commit = <A>(operation: () => A): A => {
    const committed = db
      .transaction(() => {
        const result = operation();
        const scopes = supportedScopes();
        return { result, scopes };
      })
      .immediate();
    changed(committed.scopes);
    return committed.result;
  };
  return {
    list,
    get,
    access,
    scopesFor,
    supportedScopes,
    create(input: ResourceValue) {
      const resource = validate(input);
      return commit(() => {
        if (get(resource.identifier))
          throw new APIError("CONFLICT", { message: "Resource already exists" });
        const now = Date.now();
        db.prepare(
          "INSERT INTO oauthResource (id, identifier, name, allowedScopes, accessTokenTtl, createdAt, updatedAt) VALUES (?, ?, ?, ?, 300, ?, ?)",
        ).run(
          randomUUID(),
          resource.identifier,
          resource.name,
          JSON.stringify([...protocolScopes, ...resource.scopes]),
          now,
          now,
        );
        return resource;
      });
    },
    update(input: ResourceValue) {
      const resource = validate(input);
      return commit(() => {
        const previous = get(resource.identifier);
        if (!previous) throw new APIError("NOT_FOUND", { message: "Resource not found" });
        db.prepare(
          "UPDATE oauthResource SET name = ?, allowedScopes = ?, updatedAt = ?, policyVersion = COALESCE(policyVersion, 1) + 1 WHERE identifier = ?",
        ).run(
          resource.name,
          JSON.stringify([...protocolScopes, ...resource.scopes]),
          Date.now(),
          resource.identifier,
        );
        const removed = previous.scopes.filter((scope) => !resource.scopes.includes(scope));
        for (const link of access().filter((link) => link.resource === resource.identifier)) {
          syncClient(link.client_id);
          if (removed.length) cleanup(link.client_id, resource.identifier, removed);
        }
        return resource;
      });
    },
    delete(identifier: string) {
      return commit(() => {
        if (!get(identifier)) throw new APIError("NOT_FOUND", { message: "Resource not found" });
        if (access().some((link) => link.resource === identifier))
          throw new APIError("CONFLICT", {
            message: "Remove Client access before deleting this Resource",
          });
        db.prepare("DELETE FROM oauthResource WHERE identifier = ?").run(identifier);
        return { deleted: true };
      });
    },
    setAccess(clientId: string, identifiers: readonly string[]) {
      return commit(() => {
        if (!db.prepare("SELECT id FROM oauthClient WHERE clientId = ?").get(clientId))
          throw new APIError("NOT_FOUND", { message: "Client not found" });
        validateSelection(identifiers);
        const previous = access()
          .filter((link) => link.client_id === clientId)
          .map((link) => link.resource);
        for (const identifier of previous.filter((id) => !identifiers.includes(id))) {
          cleanup(clientId, identifier);
          db.prepare("DELETE FROM oauthClientResource WHERE clientId = ? AND resourceId = ?").run(
            clientId,
            identifier,
          );
        }
        for (const identifier of identifiers.filter((id) => !previous.includes(id)))
          db.prepare(
            "INSERT INTO oauthClientResource (id, clientId, resourceId, createdAt) VALUES (?, ?, ?, ?)",
          ).run(randomUUID(), clientId, identifier, Date.now());
        syncClient(clientId);
        return access().filter((link) => link.client_id === clientId);
      });
    },
  };
}
