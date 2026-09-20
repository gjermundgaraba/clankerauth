# Provider integration

The integration targets Better Auth and `@better-auth/oauth-provider` 1.7.5, unpatched. Upstream documentation may describe newer releases; behavior claims below describe this repository's pinned integration.

Better Auth documents Node's built-in SQLite and its Kysely adapter. This service uses the exported `NodeSqliteDialect` with `DatabaseSync`, then shares the Kysely instance with Better Auth and a small Effect tagged-query helper. WAL, foreign keys and a five-second busy timeout are enabled. Kysely owns connection reservation, transactions and cleanup. See [SQLite integration](https://better-auth.com/docs/adapters/sqlite) and [database concepts](https://better-auth.com/docs/concepts/database).

The provider owns OAuth protocol handling, credential hashing, consent, resource CRUD, client/resource links, client registration, secret rotation, client updates and client deletion. Owner-authenticated application routes call its supported server APIs; native administrative endpoints are not publicly mounted. The provider documentation describes client and resource administration, registration and protocol options in [OAuth Provider](https://better-auth.com/docs/plugins/oauth-provider).

Application-specific behavior remains where the provider does not directly express this product's policy:

- The dashboard lists every client row, including automatic clients without an owner association. Onboarding is derived from provider columns: a client discovery identifier means CIMD, a missing owner means DCR, otherwise the client is managed.
- Resource scope changes synchronize client scope ceilings, and automatic clients are linked to resources added after registration. The owner may unlink any client from any resource.
- First-run account creation calls the provider's email sign-up, so validation matches sign-in and the owner is signed in by the same response. The sign-up route itself is not mounted, a user-creation database hook rejects any second account, and setup requests are serialized in process, so the owner is simply the only user; there is no separate marker or role system.
- The built-in administration resource is seeded through the provider's `resources` option in its default insert-only mode, so the owner's later name edits survive restarts.
- Routes enforce the single-resource authorization contract, sole-account setup and the allowed protocol endpoint surface.
- Managed clients are registered with the provider's `skip_consent` flag at creation. The owner's session lasts 30 days and slides with use; together these make sign-in at one first-party application sign-in at all of them.
- Dynamic registrations that omit `application_type` while using a non-HTTPS redirect URI are registered as native clients, because the provider's web default forbids loopback callbacks that MCP clients rely on.

## Client and resource lifecycle

Resources, scopes and client access are stored in SQLite. Fresh installations contain the built-in administration resource; restarts preserve edits. Resource identifiers remain stable; names and ordinary resource scopes can change, and a resource may define no custom scopes. The built-in administration scope is fixed. Managed clients may be registered without resource access and linked later. Each authorization request targets exactly one resource, with independent consent; token requests may omit `resource`, in which case the provider reuses the resource bound to the code or refresh token. New scopes require consent before issuance.

Client/resource unlinking is a policy change. It prevents new authorization and refresh while unlinked, retaining consent, codes and credentials. Relinking may permit those retained authorizations again. Removing a scope narrows newly issued tokens to the resource's current allowed scopes without deleting grants; a refresh may still succeed with fewer scopes. Restoring scopes can make retained authorization usable again. Deleting a resource removes its client links through provider behavior; there is no application dependency blocker or custom grant cleanup.

**Block client** sets the provider's `disabled` flag, which the provider enforces at authorization, token exchange, refresh and introspection, and preserves across CIMD metadata rediscovery. Blocking also clears stored consent, codes and credentials. **Revoke authorization** clears them without blocking. Neither can recall an already-issued JWT access token: resource servers, including administration MCP, accept it until it expires, at most fifteen minutes. Administration MCP additionally checks on every request that the token's client still exists and is not blocked. Managed clients can be renamed and have their redirect URIs or application type changed through the provider's update API; automatic clients are owned by their registration or metadata and cannot be edited by the owner. Secret rotation invalidates the previous secret immediately. Deleting a client removes its stored grants.

## Concurrency and transactions

Run only one process/Service instance against a database. Requests run concurrently; there is no service-wide FIFO queue. The provider's individual operations and database transactions define consistency. Refresh tokens rotate on use with a thirty-second reuse window: a retried refresh inside the window replays the same replacement, while a replay outside it revokes the token family. Replay invalidation covers all refresh grants for the same client ID and user ID, across sessions and resources, plus associated opaque access rows. Other clients' grants remain separate.

Administrative policy changes do not turn a multi-step provider request already in progress into a single transaction. Workflows that call several provider APIs can commit earlier steps before a later step fails; refresh the dashboard to inspect the stored state before retrying. Local block and revoke writes each use one transaction, and first-run account creation runs inside the provider's sign-up transaction. Those transactions preserve domain errors and roll back failed writes; they do not encompass concurrent provider workflows.

## Shutdown

Graceful shutdown closes admission and tracks all admitted application work, including disconnected requests, until completion before closing SQLite. Late admission receives 503.

## API keys

The API-key plugin is used unpatched. Its per-key rate limit counts up to 1,000 verifications per key until a full minute of inactivity has elapsed. Its listing reads one database page and paginates in memory, so the dashboard shows at most the first 100 keys.

## Effect boundaries

`openAuth` captures the application context for Better Auth's awaited callbacks, so supplied clocks and logging services survive that Promise boundary. Construct it at application startup, not inside a request. Local Kysely transactions are controlled transactions: the body runs in the calling fiber, commits on success and rolls back on failure or defect. Action routes run uninterruptibly so admitted provider calls settle before their request scope releases sessions or permits database shutdown.
