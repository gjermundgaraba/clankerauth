# Domain language

Use these names in the dashboard, API, documentation and tests.

| Term                 | Meaning                                                                                                                                                                                                                                |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Owner                | The sole local account eligible to sign in, administer this service and give consent.                                                                                                                                                  |
| Authorization server | This service: authenticates the owner, checks client access and consent, and issues tokens.                                                                                                                                            |
| Issuer               | The authorization server's exact `AUTH_BASE_URL/api/auth` identifier.                                                                                                                                                                  |
| Client               | A registered OAuth participant that requests tokens. One client ID may have access to several resources. Public clients use PKCE without a secret; confidential clients also authenticate with a secret.                               |
| Resource             | A protected target identified by an exact HTTPS audience URL, with a dashboard-managed name and scopes. It is the target of client access and consent.                                                                                 |
| Resource server      | The service that hosts a resource, validates access tokens and enforces the scopes required by its operations.                                                                                                                         |
| Scope                | A named permission defined by a resource. Identical labels on different resources can have different meaning and independent consent. `openid`, `profile`, `email` and `offline_access` are protocol scopes, not resource permissions. |
| Client access        | The administrator-controlled relation specifying which resources a client may request. It does not record the owner's consent.                                                                                                         |
| Consent              | The owner's approval for a client to receive particular scopes for one resource. Approving another resource does not replace this consent.                                                                                             |
| Access token         | The credential a client presents to a resource server. This service issues signed JWTs with audience and scope claims and a maximum lifetime of five minutes.                                                                          |
| Refresh token        | The credential a client presents to the authorization server to request replacement tokens without repeating the interactive flow. It is bound to the existing authorization and rotates when used.                                    |
| Audience             | The target named in an access token's `aud` claim. Each request targets one resource, even when the client has access to several. OIDC may additionally include the issuer's own UserInfo endpoint.                                    |

**Application** means software in general; it is not a substitute for Client or Resource. One application can act as a client, host a resource, or do both. **API** means an interface; use Resource when referring to the protected target and Resource server when referring to its host.

Qualify **grant** as an OAuth authorization grant when discussing the protocol: for example, an authorization code represents authorization that the client exchanges for tokens. Do not use Grant as an umbrella for Client access, Consent, codes and token credentials. Use **policy** with the rule it describes, such as resource scope policy or token lifetime policy. **Entry** is a generic UI or storage description, not a domain entity.

## Scopes through a request

- **Available scopes** are the permissions defined by a resource.
- **Allowed scopes** are the ceiling the client may request for that resource. Here, client access allows the resource's current available scopes, subject to the protocol rules.
- **Requested scopes** are the permissions named in an authorization or token request.
- **Approved scopes** are the permissions the owner has consented to for that client and resource.
- **Issued scopes** are the permissions actually carried in the resulting access token after the server's checks. New available or allowed scopes do not automatically become approved or issued scopes.

For example, a Notes client can have client access to both a Files resource and a Tasks resource. Both resources may define `read`. The owner can approve Files/read without approving Tasks/read. Each authorization request and resulting token targets one resource; the resource server checks its own audience and required scopes.

The database owns resources, scopes and client access. Fresh installations start empty and restarts preserve edits. Resource identifiers remain stable; names and scopes can change. A resource cannot be deleted while clients still have access. Removing client access removes that pair's consent, outstanding authorization codes and refresh credentials; re-adding access cannot revive them. Scope removal retires affected codes and credentials while preserving unrelated authorization. Existing JWTs at offline verifiers can remain usable until their expiry, at most five minutes after issuance.
