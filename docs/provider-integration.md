# Provider integration

The integration targets Better Auth and `@better-auth/oauth-provider` 1.7.3. Upstream documentation may describe newer releases; behavior claims below describe this repository's pinned integration and regressions.

Better Auth documents Node's built-in SQLite and its Kysely adapter. This service uses the exported `NodeSqliteDialect` with `DatabaseSync`, then shares the Kysely instance with Better Auth and a small Effect tagged-query helper. WAL, foreign keys and a five-second busy timeout are enabled. Kysely owns connection reservation, transactions and cleanup. See [SQLite integration](https://better-auth.com/docs/adapters/sqlite) and [database concepts](https://better-auth.com/docs/concepts/database).

The provider owns OAuth protocol handling, credential hashing, consent, resource CRUD, client/resource links, client registration, secret rotation and client deletion. Owner-authenticated application routes call its supported server APIs; native administrative endpoints are not publicly mounted. The provider documentation describes client and resource administration, registration and protocol options in [OAuth Provider](https://better-auth.com/docs/plugins/oauth-provider).

Application-specific behavior remains where the provider does not directly express this product's policy:

- The dashboard lists all clients, including automatic clients without an owner association. Global block and revoke controls maintain onboarding policy and clear stored authorization for a client identifier.
- Resource scope changes synchronize client scope ceilings, and automatic clients can request resources added after registration. This is dynamic application policy layered over provider resources and links.
- First-run account creation and the permanent setup marker commit in one local Kysely transaction. The marker records completed setup; it is not a runtime role system.
- Routes enforce the single-resource request contract, exact configured origin, sole-account setup and the allowed protocol endpoint surface.
- Managed clients are registered with the provider's `skip_consent` flag, and startup sets it on managed clients that predate the policy. The owner's session lasts 30 days and slides with use; together these make sign-in at one first-party application sign-in at all of them.

## Client and resource lifecycle

Resources, scopes and client access are stored in SQLite. Fresh installations start empty and restarts preserve edits. Resource identifiers remain stable; names and scopes can change. Managed clients may be registered without resource access and linked later. Each authorization and token request targets exactly one resource, with independent consent; new scopes require consent before issuance.

Client/resource unlinking is a policy change. It prevents new authorization and refresh while unlinked, retaining consent, codes and credentials. Relinking may permit those retained authorizations again. Removing a scope narrows newly issued tokens to the resource's current allowed scopes without deleting grants; a refresh may still succeed with fewer scopes. Restoring scopes can make retained authorization usable again. Deleting a resource removes its client links through provider behavior; there is no application dependency blocker or custom grant cleanup.

**Revoke authorization** explicitly clears stored consent, codes and credentials. **Block client** also disables authorization for that identifier until unblocked, including across CIMD metadata rediscovery. Unblocking does not restore old grants. To change a client redirect URI, delete and re-register. Secret rotation invalidates the previous secret immediately. Deleting a client removes its stored grants. These database mutations cannot retract JWTs at offline verifiers; access tokens remain usable until expiry, at most five minutes after issuance.

## Concurrency and transactions

Run only one process/Service instance against a database. Requests run concurrently; there is no service-wide FIFO queue. The provider's individual operations and database transactions define consistency. Refresh rotation can race with revocation and insert a replacement after revocation has completed, so a successful revocation response is not an atomic barrier against an in-flight refresh. Clients must serialize refresh and replace their stored credential atomically.

Replay invalidation covers all refresh grants for the same client ID and user ID, across sessions and resources, plus associated opaque access rows. Other clients' grants remain separate. Revocation of an already-rotated parent responds `400 invalid_request` in this provider version.

Administrative policy changes likewise do not turn a multi-step provider request already in progress into a single transaction. Workflows that call several provider APIs can commit earlier steps before a later step fails; refresh the dashboard to inspect the stored state before retrying. Local block and revoke writes each use one transaction, as does first-run account creation with its setup marker. Those transactions preserve domain errors and roll back failed writes; they do not encompass concurrent provider workflows.

## Provider patch and shutdown

The [version-pinned pnpm patch](../patches/@better-auth__oauth-provider@1.7.3.patch) retains two narrow fixes:

- Refresh-token client binding is checked before replay-family invalidation, preventing a rotated token from client A from deleting client B's family.
- Access-token signing and refresh writes both settle before an issuance error propagates, allowing graceful shutdown to drain outstanding provider writes.

These fixes preserve provider cryptography and token formats; they do not serialize requests or add transaction rollback. Failed issuance may consume a code or leave a completed grant.

Graceful shutdown closes admission and tracks all admitted application work, including disconnected requests, until completion before closing SQLite. Late admission receives 503.

## API-key listing patch

The [API-key provider patch](../patches/@better-auth__api-key@1.7.3.patch) reads database listings in explicit pages before the provider applies configuration filtering and public pagination. The pinned provider otherwise inherits Better Auth's 100-row default, even when its caller requests a larger limit. The dashboard's listing must include every owner key. Regression coverage creates 101 keys and checks complete listings, total counts, pagination beyond the first page, and omission of plaintext credentials.

## API-key rate-limit window

The API-key provider patch stores `rateLimitWindowStart` separately from `lastRequest`. The counter resets at the end of a fixed one-minute window, including the exact boundary; successful requests update activity without moving the window. Guarded database updates preserve the per-key maximum under concurrent verification, and the stored window survives restart. New keys have a null window start and begin their first counting window on verification. Tests cover sustained traffic, concurrent bursts, the boundary, and restart. The pinned provider otherwise counts until a full inactivity interval has elapsed.
