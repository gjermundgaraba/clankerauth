export interface DisposableIssuerOptions {
  resources: Array<{ identifier: string; name: string; scopes: string[] }>;
  client: { name: string; redirect: string; resources: string[] };
  /**
   * Serve forward auth for apps under this domain, such as `notes.localhost`. The issuer is
   * then `http://auth.<cookieDomain>:<port>` on the same loopback listener, and the forward
   * cookie is shared with every host under the domain. Without it, the issuer is
   * `http://127.0.0.1:<port>` and the forward-auth routes are not served.
   */
  cookieDomain?: string;
  /**
   * Keep the issuer's state in this directory instead of a temporary one: the owner
   * account and password, the signing secret, the registered client and the database
   * survive `close()` and the next start. Provisioning is idempotent, so the same
   * resources and client are reused. The directory is never deleted. Treat it as the
   * whole secret of the workspace, and keep it out of version control.
   */
  dataDir?: string;
  /**
   * Listen on this port instead of a random one. A persistent workspace needs a fixed
   * one, because the origin is what browser storage, cookies and registered redirect
   * URIs are keyed by. Default `0`.
   */
  port?: number;
  /** Test hook replacing outbound CIMD metadata retrieval. Defaults to the secure transport. */
  cimdTransport?: (input: RequestInfo | URL, init?: RequestInit) => Response | Promise<Response>;
  /** Test hook observing incoming HTTP requests, including provisioning. No headers or bodies. */
  onRequest?: (request: { method: string; url: URL }) => void;
}

/** What a persistent workspace keeps between runs. Written by this package only. */
export interface Identity {
  email: string;
  password: string;
  secret: string;
  clientId?: string;
  clientSecret?: string;
}

/** A browser-equivalent owner session: the forward cookie, as a header and as pairs. */
export interface OwnerSession {
  cookie: string;
  cookies: Array<{ name: string; value: string }>;
}

export interface DisposableIssuer {
  issuer: string;
  clientId: string;
  clientSecret: string;
  owner: { email: string; password: string };
  url: string;
  /** The port the issuer listens on, which is also the apps' port under a cookie domain. */
  port: number;
  directory: string;
  /** Mint a scoped API key and return its secret. Permissions are resource identifier to scopes. */
  apiKey(options: { name?: string; permissions: Record<string, string[]> }): Promise<string>;
  /**
   * Sign the owner in and seal the forward cookie for `appOrigin`, exactly as a browser
   * does through `/forward-auth/continue`. Needs `cookieDomain`. The `cookies` array is
   * what a browser automation harness adds to a context.
   */
  ownerSession(appOrigin: string): Promise<OwnerSession>;
  /** An access token for one resource, obtained through the same forward-auth check. */
  ownerToken(options: { resource: string; appOrigin: string }): Promise<string>;
  /** Drain requests and close SQLite. Removes the directory only when it is temporary. Idempotent. */
  close(): Promise<void>;
}

/** Start an issuer on a loopback port. The caller owns signals and must await close(). */
export function startDisposableIssuer(options: DisposableIssuerOptions): Promise<DisposableIssuer>;
