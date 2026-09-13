import { AuthError } from "./errors.ts";

export interface ResourceOptions {
  /** Exact audience URL of this resource, for example `https://notes.internal/api`. */
  readonly resource: string;
  /** Issuer identifier, for example `https://auth.internal/api/auth`. */
  readonly issuer: string;
  /** Scopes the resource defines. */
  readonly scopes: readonly string[];
}

/** RFC 9728 protected-resource metadata. Serve it at `/.well-known/oauth-protected-resource/<path>`. */
export const protectedResourceMetadata = ({ resource, issuer, scopes }: ResourceOptions) =>
  Response.json(
    {
      resource,
      authorization_servers: [issuer],
      scopes_supported: scopes,
      bearer_methods_supported: ["header"],
    },
    { headers: { "cache-control": "no-store" } },
  );

/** The URL where a resource publishes its metadata: the well-known path under the resource origin. */
export const metadataUrl = (resource: string) => {
  const url = new URL(resource);
  return `${url.origin}/.well-known/oauth-protected-resource${url.pathname === "/" ? "" : url.pathname}`;
};

/** A `WWW-Authenticate` challenge that lets clients discover the issuer and the scopes an operation needs. */
export const challenge = (
  error: AuthError,
  { resource, scopes }: { readonly resource: string; readonly scopes: readonly string[] },
) =>
  `Bearer resource_metadata="${metadataUrl(resource)}", error="${error.code === "forbidden" ? "insufficient_scope" : "invalid_token"}", scope="${scopes.join(" ")}"`;

/** The complete response to a failed authentication: status, JSON body, and discovery headers. */
export const failureResponse = (
  error: AuthError,
  options: { readonly resource: string; readonly scopes: readonly string[] },
) => {
  const headers = new Headers({ "cache-control": "no-store" });
  if (error.status === 401 || error.status === 403)
    headers.set("www-authenticate", challenge(error, options));
  if (error.status === 429) headers.set("retry-after", "60");
  return Response.json(
    { error: error.code, error_description: error.message },
    { status: error.status, headers },
  );
};
