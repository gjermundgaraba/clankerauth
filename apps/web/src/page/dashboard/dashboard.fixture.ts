import { Result, Schema } from "effect";
import { modifyFields } from "foldkit/struct";

import { Listing, listingQuery } from "./listing.ts";
import { Message } from "./message.ts";
import type { Model } from "./model.ts";
import { init, update } from "./update.ts";

export const FIRST_READ = 1;

export const SECOND_READ = 2;

export const THIRD_READ = 3;

export const readOf = (generation: number, data: Listing) =>
  listingQuery.Message.CompletedFetch({ generation, result: Result.succeed(data) });

export const failedReadOf = (generation: number) =>
  listingQuery.Message.CompletedFetch({
    generation,
    result: Result.fail("Fixture request failed"),
  });

const settled = (model: Model, message: typeof listingQuery.Message.Type): Model =>
  update(model, Message.GotListingMessage({ message })).model;

export const rereading = (model: Model): Model =>
  modifyFields(model, { listing: (query) => listingQuery.revalidate(query).model });

export const listing = Schema.decodeUnknownSync(Listing)({
  overview: {
    email: "owner@fixture.invalid",
    issuer: "https://issuer.fixture.invalid",
    clients: [],
    resources: [
      {
        identifier: "https://api.fixture.invalid",
        name: "Fixture API",
        scopes: ["read"],
        builtIn: false,
      },
    ],
    clientAccess: [],
    connections: [],
  },
  keys: [
    {
      keyId: "fixture-key",
      name: "Automation",
      enabled: true,
      permissions: {},
      expiresAt: null,
      createdAt: "2026-01-01T00:00:00.000Z",
    },
  ],
});

export const listed = settled(init().model, readOf(FIRST_READ, listing));

export const staleListed = settled(rereading(listed), failedReadOf(SECOND_READ));

export const unlisted = settled(init().model, failedReadOf(FIRST_READ));

export const catalog = Schema.decodeUnknownSync(Listing)({
  overview: {
    email: "owner@fixture.invalid",
    issuer: "https://issuer.fixture.invalid",
    clients: [
      {
        client_id: "managed-client",
        client_name: "Managed client",
        redirect_uris: ["https://fixture.invalid/callback"],
        token_endpoint_auth_method: "client_secret_basic",
      },
      {
        client_id: "https://client.fixture.invalid/metadata.json",
        client_name: "Automatic client",
        redirect_uris: ["https://fixture.invalid/callback"],
        token_endpoint_auth_method: "none",
        onboarding: "cimd",
      },
    ],
    resources: [
      {
        identifier: "https://api.fixture.invalid",
        name: "Fixture API",
        scopes: ["read"],
        builtIn: false,
      },
      {
        identifier: "https://issuer.fixture.invalid/",
        name: "clankerauth administration",
        scopes: ["clankerauth:read", "clankerauth:write"],
        builtIn: true,
      },
    ],
    clientAccess: [],
    connections: [],
  },
  keys: [],
});

export const cataloged = settled(init().model, readOf(FIRST_READ, catalog));
