export type AuthErrorCode = "unauthorized" | "forbidden" | "rate_limited" | "unavailable";

const statuses = {
  unauthorized: 401,
  forbidden: 403,
  rate_limited: 429,
  unavailable: 503,
} as const;
const messages = {
  unauthorized: "Authentication required",
  forbidden: "Insufficient scope",
  rate_limited: "Authentication rate exceeded",
  unavailable: "Authentication unavailable",
} as const;

/** Outcome of failed authentication. `status` is the HTTP status a resource server answers with. */
export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly status: (typeof statuses)[AuthErrorCode];
  constructor(code: AuthErrorCode, message: string = messages[code]) {
    super(message);
    this.name = "AuthError";
    this.code = code;
    this.status = statuses[code];
  }
}
