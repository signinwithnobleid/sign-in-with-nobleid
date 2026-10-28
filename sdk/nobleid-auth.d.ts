// Type declarations for nobleid-auth.js (the browser SDK), v2.1.1.

export interface NobleIDEndpoints {
  authorization: string;
  token: string;
  userinfo: string;
  revocation: string;
  jwks: string;
}

export interface NobleIDError extends Error {
  /** invalid_state | invalid_issuer | expired | invalid_request | invalid_token | userinfo_failed | slow_down | a provider code such as access_denied */
  code: string;
  description: string;
  status?: number;
  retryAfter?: number | string;
}

export interface AuthorizeOptions {
  clientId: string;
  redirectUri: string;
  scope?: string;
  prompt?: "none" | "login" | "consent" | "select_account";
  loginHint?: string;
  maxAge?: number;
}

export interface ButtonOptions extends Partial<AuthorizeOptions> {
  /** Your server's sign-in route (confidential client). Same-site path or https URL. */
  loginUrl?: string;
  theme?: "light" | "dark";
  size?: "sm" | "md" | "lg";
  label?: "Sign in with NobleID" | "Continue with NobleID";
  onError?: (error: NobleIDError) => void;
}

export interface CallbackResult {
  tokens: { access_token: string; token_type: string; expires_in: number; scope: string; id_token: string; refresh_token?: string };
  /** userinfo claims (or the ID token claims when userinfo: false) */
  claims: Record<string, unknown> & { sub: string };
  idTokenClaims: Record<string, unknown> & { sub: string; iss: string; aud: string | string[]; exp: number };
  /** Scopes the user actually granted. */
  scope: string[];
}

export interface NobleIDSDK {
  readonly version: string;
  readonly issuer: string;
  readonly endpoints: NobleIDEndpoints;
  /** Testing against a local mock or staging only. */
  configure(options: { issuer?: string; authorizationEndpoint?: string }): NobleIDEndpoints;
  renderButton(container: string | HTMLElement, options: ButtonOptions): HTMLElement;
  createButton(options: ButtonOptions): HTMLElement;
  renderResearcherBadge(container: string | HTMLElement, claims: Record<string, unknown>, options?: { theme?: "light" | "dark" }): HTMLElement;
  createAuthorizeUrl(options: AuthorizeOptions): Promise<string>;
  signIn(options: AuthorizeOptions): Promise<void>;
  handleCallback(options?: { clientId?: string; redirectUri?: string; userinfo?: boolean; cleanUrl?: boolean }): Promise<CallbackResult>;
  revoke(options: { clientId: string; token: string; tokenTypeHint?: "refresh_token" | "access_token" }): Promise<boolean>;
  security: {
    randomString(): string;
    codeChallengeS256(verifier: string): Promise<string>;
    decodeJwtPayloadUnverified(jwt: string): Record<string, unknown> | null;
  };
}

declare global {
  interface Window {
    NobleID: NobleIDSDK;
  }
  const NobleID: NobleIDSDK;
}

export {};
