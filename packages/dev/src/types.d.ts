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
  /** Test hook replacing outbound CIMD metadata retrieval. Defaults to the secure transport. */
  cimdTransport?: (input: RequestInfo | URL, init?: RequestInit) => Response | Promise<Response>;
  /** Test hook observing incoming HTTP requests, including provisioning. No headers or bodies. */
  onRequest?: (request: { method: string; url: URL }) => void;
}

export interface DisposableIssuer {
  issuer: string;
  clientId: string;
  clientSecret: string;
  owner: { email: string; password: string };
  url: string;
  directory: string;
  /** Drain requests, close SQLite, and remove all temporary identity state. Idempotent. */
  close(): Promise<void>;
}

/** Start a fresh issuer on a random loopback port. The caller owns signals and must await close(). */
export function startDisposableIssuer(options: DisposableIssuerOptions): Promise<DisposableIssuer>;
