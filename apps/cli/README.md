# @gjermundgaraba/clankerauth

The `clankerauth` command: sign in to a [clankerauth](https://github.com/gjermundgaraba/clankerauth) issuer as its owner, run every administration action over HTTP, and hand other commands access tokens for the issuer's resources. It needs Node 26 or newer and an issuer at 0.16.0 or later.

```sh
npm install --global @gjermundgaraba/clankerauth

clankerauth login https://clankerauth.home.example
clankerauth list-clients
clankerauth create-api-key --name "notes sync" \
  --permissions '{"https://notes.home.example/":["notes:read"]}' --expires-at null
clankerauth logout
```

`login` discovers the issuer at the URL given, which must be its own origin, `CLANKERAUTH_BASE_URL`; registers the command as a native OAuth client the first time; prints the approval URL on stderr for the owner to open; and listens for the redirect on a loopback port. It asks for `clankerauth:read clankerauth:write`, unless `--scope` names fewer: `--scope clankerauth:read` lists and never changes. The sign-ins are kept in `$XDG_CONFIG_HOME/clankerauth/credentials.json`, `~/.config/clankerauth/credentials.json` by default, readable by their owner alone; a file the command cannot read, such as one another version wrote, counts as signed out and the next `login` replaces it. A command refreshes an access token once it has expired and saves the rotated refresh token, so a sign-in lasts while it is used at least every 30 days. `logout` revokes every sign-in and deletes the file.

## Tokens for other commands

`login --resource <identifier> --scope <scopes>` signs in to one of the issuer's resources instead of administration, with its own consent and refresh token, kept beside the others. `token --resource <identifier>` prints a current access token for it, and nothing else, refreshing it first when it has expired; without `--resource` it prints administration's. Another command, or a script, gets its bearer token from there instead of keeping a key:

```sh
clankerauth login https://clankerauth.home.example \
  --resource https://notes.home.example/ --scope "notes:read notes:write"
curl -H "authorization: Bearer $(clankerauth token --resource https://notes.home.example/)" \
  https://notes.home.example/api/list-notes
clankerauth logout --resource https://notes.home.example/
```

The identifier is the resource's, exactly as the dashboard lists it. The file holds one issuer's sign-ins: signing in to another issuer revokes and forgets the kept ones first.

Every other command is an administration action, named after it in kebab case, with a flag per input field: `clankerauth <command> --help` lists them. A field that is not text takes JSON, such as `--permissions` above or `--expires-at null`. A command prints the action's result as JSON on stdout, and a refusal on stderr, exiting 1. A created API key or client secret is in that JSON once, so send it where it belongs:

```sh
clankerauth create-api-key --name "machine" \
  --permissions '{"https://creds.home.example/":["creds:machine"]}' --expires-at null \
  | jq -r .key > key
```

MIT licensed.
