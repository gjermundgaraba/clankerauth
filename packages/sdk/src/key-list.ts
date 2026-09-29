/**
 * The key list: how an issuer publishes the API keys granted on one resource, so its
 * resource server verifies them offline without learning who else holds what.
 *
 * Each entry is found by, and sealed under, values derived from the key's SHA-256 digest
 * — what the issuer stores — and the resource identifier. Only a holder of the key can
 * locate or read its entry. Anyone else still sees how many entries a resource has, when
 * they come and go, and roughly how large each grant is. A digest cannot be reversed, so
 * neither the list nor the issuer's store yields a key.
 *
 * Sealing is exported for issuers, including fakes in tests; a resource server only opens.
 */
import { Schema } from "effect";
import { base64url } from "jose";

/** The list's JWT `typ`, so neither a list nor an access token can pass for the other. */
export const type = "key-list+jwt";

/**
 * How long a list decides, in seconds from its `iat`: for as long as a resource server
 * cannot read a newer one, it keeps accepting the keys this one grants. So it is also the
 * longest a revoked key stays usable during an issuer outage.
 */
export const lifetime = 24 * 60 * 60;

export const Entry = Schema.Struct({ id: Schema.String, sealed: Schema.String });

export type Entry = typeof Entry.Type;

/** The claims a list carries besides `iss`, `aud`, `iat` and `exp`. */
export const Claims = Schema.Struct({ keys: Schema.Array(Entry) });

/** What one key may do on the list's resource. */
export const Grant = Schema.Struct({
  keyId: Schema.NonEmptyString,
  ownerId: Schema.NonEmptyString,
  scopes: Schema.Array(Schema.NonEmptyString),
  /** Epoch milliseconds; `null` for a key that does not expire. */
  expiresAt: Schema.NullOr(Schema.Finite),
});

export type Grant = typeof Grant.Type;

const GrantJson = Schema.fromJsonString(Grant);

const encoder = new TextEncoder();

/** The digest an issuer stores for a key: SHA-256 of the whole key, prefix included. */
export const digest = async (key: string) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(key)));

/** One key's entry ID and sealing key on one resource. */
const derive = async (keyDigest: Uint8Array<ArrayBuffer>, resource: string) => {
  const material = await crypto.subtle.importKey("raw", keyDigest, "HKDF", false, ["deriveBits"]);

  const bits = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(),
        info: encoder.encode(`clankerauth key list\0${resource}`),
      },
      material,
      512,
    ),
  );

  return {
    id: base64url.encode(bits.subarray(0, 32)),
    key: await crypto.subtle.importKey("raw", bits.subarray(32), "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]),
  };
};

/** One key's entry on one resource, from the digest the issuer stores. */
export const seal = async (
  keyDigest: Uint8Array<ArrayBuffer>,
  resource: string,
  grant: Grant,
): Promise<Entry> => {
  const { id, key } = await derive(keyDigest, resource);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(Schema.encodeSync(GrantJson)(grant)),
  );

  const sealed = new Uint8Array(iv.length + ciphertext.byteLength);
  sealed.set(iv);
  sealed.set(new Uint8Array(ciphertext), iv.length);

  return { id, sealed: base64url.encode(sealed) };
};

/**
 * What a list grants this key on its resource, or `undefined` when the list has no entry
 * for it. Rejects only for an entry that does not open, which the issuer never writes.
 */
export const open = async (
  key: string,
  resource: string,
  entries: ReadonlyMap<string, string>,
): Promise<Grant | undefined> => {
  const derived = await derive(await digest(key), resource);
  const sealed = entries.get(derived.id);

  if (sealed === undefined) return undefined;
  const bytes = new Uint8Array(base64url.decode(sealed));

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: bytes.subarray(0, 12) },
    derived.key,
    bytes.subarray(12),
  );

  return Schema.decodeUnknownSync(GrantJson)(new TextDecoder().decode(plaintext));
};
