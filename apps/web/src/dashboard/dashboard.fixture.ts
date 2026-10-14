import { Result, Schema } from "effect";
import { modifyFields } from "foldkit/struct";

import { Message } from "./message.ts";
import { Listing, ListingData, type Model } from "./model.ts";
import { init } from "./update.ts";

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

export const listed: Model = modifyFields(init().model, {
  listing: () => ListingData.Success({ data: listing }),
});

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

export const cataloged: Model = modifyFields(init().model, {
  listing: () => ListingData.Success({ data: catalog }),
});

export const reread = Message.SettledFetchListing({ result: Result.succeed(listing) });
