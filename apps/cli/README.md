# @gjermundgaraba/clankerauth

The `clankerauth` command: sign in to a [clankerauth](https://github.com/gjermundgaraba/clankerauth) issuer as its owner and run every administration action over HTTP. It needs Node 26 or newer and an issuer at 0.16.0 or later.

```sh
npm install --global @gjermundgaraba/clankerauth

clankerauth login https://clankerauth.home.example
clankerauth list-clients
clankerauth create-api-key --name "notes sync" \
  --permissions '{"https://notes.home.example/":["notes:read"]}' --expires-at null
clankerauth logout
```

`login` discovers the issuer, registers the command as a native OAuth client the first time, and asks the owner to approve in the browser: it prints the approval URL on stderr, opens it unless `--no-browser`, and listens for the redirect on a loopback port. `--read-only` asks for `clankerauth:read` alone, which lists and never changes. The sign-in is kept in `$XDG_CONFIG_HOME/clankerauth/credentials.json`, `~/.config/clankerauth/credentials.json` by default, readable by its owner alone. A command refreshes the access token once it has expired and saves the rotated refresh token. `logout` revokes the sign-in and deletes the file.

Every other command is an administration action, named after it in kebab case, with a flag per input field: `clankerauth <command> --help` lists them. A field that is not text takes JSON, such as `--permissions` above or `--expires-at null`. A command prints the action's result as JSON on stdout, and a refusal on stderr, exiting 1. A created API key or client secret is in that JSON once, so send it where it belongs:

```sh
clankerauth create-api-key --name "machine" \
  --permissions '{"https://creds.home.example/":["creds:machine"]}' --expires-at null \
  | jq -r .key > key
```

MIT licensed.
