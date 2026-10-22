# @gjermundgaraba/clankerauth-admin-api

The administration contract of a [clankerauth](https://github.com/gjermundgaraba/clankerauth) issuer: every owner action as an [effect-actions](https://www.npmjs.com/package/@gjermundgaraba/effect-actions) action, with its input and output schemas, its tagged errors, and the HTTP bindings the issuer serves them on. The issuer, its dashboard, its MCP endpoint and the `clankerauth` CLI all derive from it, so a program calling it gets the same actions, typed, with no CLI in between.

Its version follows the issuer's: use the one matching the issuer you call.

## Install

```sh
vp add @gjermundgaraba/clankerauth-admin-api effect @gjermundgaraba/effect-actions@^0.19.0
```

Effect 4.0, from 4.0.4, and effect-actions are peers, shared with the program.

## Call administration from a program

`OwnerHttp` is the binding served at `/api/owner/<action>`, authenticated by an owner's access token for the administration resource, the issuer's origin root. The owner's sign-in that `clankerauth login <issuer>` keeps gives one: `authorizing` of [`@gjermundgaraba/clankerauth-sdk/credentials`](../sdk/README.md) sends it with each request, refreshed as it expires, and the methods fail with `SignInRequired` when there is none.

```ts
import { Effect } from "effect";
import { FetchHttpClient } from "effect/http";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as Credentials from "@gjermundgaraba/clankerauth-sdk/credentials";
import { OwnerHttp } from "@gjermundgaraba/clankerauth-admin-api";

const issuer = "https://clankerauth.home.example";

const program = Effect.gen(function* () {
  const admin = yield* ActionHttp.client(OwnerHttp, {
    baseUrl: issuer,
    transformClient: Credentials.authorizing({ url: issuer }),
  });

  const { created } = yield* admin.putResource({
    identifier: "https://notes.home.example/",
    name: "Notes",
    scopes: ["notes:read", "notes:write"],
  });

  return created;
}).pipe(Effect.provide(FetchHttpClient.layer));
```

A refusal fails with its tagged error, such as `ResourceNotFound` from `getResource` or `deleteResource`; each action declares the ones it can produce. `getResource` reads one resource, `putResource` creates or updates one to exactly the name and scopes given, so a deployment tool states what it wants without choosing between create and update, and `deleteResource` removes one.

Administration takes no API keys: the token is always an owner's.

MIT licensed.
