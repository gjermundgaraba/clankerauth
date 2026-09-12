export interface DisposableIssuerOptions {
  resources: Array<{ identifier: string; name: string; scopes: string[] }>;
  client: { name: string; redirect: string; resources: string[] };
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
