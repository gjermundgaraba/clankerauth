# @gjermundgaraba/clankerauth

The `clankerauth` command: sign in to a [clankerauth](https://github.com/gjermundgaraba/clankerauth) issuer as its owner, run every administration action over HTTP, and hand other commands access tokens for the issuer's resources. It needs Node 26 or newer and an issuer at 0.24.0 or later.

```sh
npm install --global @gjermundgaraba/clankerauth

clankerauth login https://clankerauth.home.example
clankerauth list-clients
clankerauth create-api-key --name "notes sync" \
  --permissions '{"https://notes.home.example/":["notes:read"]}' --expires-at null
clankerauth logout
```

`login <url>` signs in to the resource `url` identifies, reading it from its `/.well-known/oauth-protected-resource`: the issuer's own origin, `CLANKERAUTH_BASE_URL`, publishes administration, and an application's URL publishes its resource. It then discovers the issuer that resource names; registers the command there as a native OAuth client, a new one for each sign-in; opens the approval page in the browser and prints its URL on stderr, for a terminal with no browser to open, or alone with `--no-browser`; and listens for the redirect on a loopback port. It asks for every scope the resource publishes, `clankerauth:read clankerauth:write` for administration, unless `--scope` names fewer: `--scope clankerauth:read` lists and never changes. Beside them it asks for `offline_access`, alone for a resource that publishes no scopes. A resource must publish that document, and so be identified by an `http:` or `https:` URL, to be signed in to.

The sign-ins are kept in `$XDG_CONFIG_HOME/clankerauth/sign-ins.json`, `~/.config/clankerauth/sign-ins.json` by default, readable by their owner alone: one per resource, each with its own issuer, so signing in at a second issuer leaves the first's alone. A file the command cannot read, such as one another version wrote, counts as signed out and the next `login` replaces it. A `login` to a resource already signed in to replaces that sign-in and revokes it. A command refreshes an access token as it is about to expire and saves the rotated refresh token, so a sign-in lasts while it is used at least every 30 days; when the issuer refuses a refresh, the error names the `login` that asks for the same scopes again. Every change to the file holds its lock, so commands and programs running at once refresh an expired sign-in once, and `logout` revokes the refresh token that is current. `logout` revokes every sign-in and deletes the file, and `logout <url>` the one whose resource that URL is under alone.

Administration commands act at the issuer of the one administration sign-in kept. Signed in to administration at several issuers, name one with `CLANKERAUTH_URL`, its origin; a value that is no URL is refused.

Unattended, such as in a container with no browser or disk to keep a sign-in on, the commands take an administration key, an API key granted on the issuer's origin root, from `CLANKERAUTH_TOKEN` instead, and then act at the issuer `CLANKERAUTH_URL` names, which they require. No sign-in is read or written. The owner creates the key once, signed in:

```sh
clankerauth create-api-key --name deployer --expires-at null \
  --permissions '{"https://clankerauth.home.example/":["clankerauth:read","clankerauth:write"]}'

CLANKERAUTH_URL=https://clankerauth.home.example CLANKERAUTH_TOKEN=clankerauth_… \
  clankerauth list-api-keys
```

The issuer checks the key on every request, so disabling or deleting it ends its access at once. With `clankerauth:write` it may create and delete administration keys too, itself among them.

## Tokens for other commands

`token <url>` prints a current access token for the resource signed in to that the URL is under, the most specific when several are, and nothing else, refreshing it first when it is about to expire; without a URL it prints administration's. Another command, or a script, gets its bearer token from there instead of keeping a key; a program written with Effect uses `token` of [`@gjermundgaraba/clankerauth-sdk/credentials`](../../packages/sdk/README.md) instead, which reads and refreshes the same sign-in:

```sh
clankerauth login https://notes.home.example
curl -H "authorization: Bearer $(clankerauth token https://notes.home.example/api/list-notes)" \
  https://notes.home.example/api/list-notes
clankerauth logout https://notes.home.example
```

Every other command is an administration action, named after it in kebab case, with a flag per input field: `clankerauth <command> --help` lists them. A field that is not text takes JSON, such as `--permissions` above or `--expires-at null`. A command prints the action's result as JSON on stdout, and a refusal on stderr, exiting 1. A created API key or client secret is in that JSON once, so send it where it belongs:

```sh
clankerauth create-api-key --name "machine" \
  --permissions '{"https://creds.home.example/":["creds:machine"]}' --expires-at null \
  | jq -r .key > key
```

MIT licensed.
