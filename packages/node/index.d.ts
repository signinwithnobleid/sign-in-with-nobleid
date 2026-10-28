import type { Configuration, IntrospectionResponse } from "openid-client";

export declare const NOBLEID_ISSUER: "https://id.nobleid.org";
export declare const DEFAULT_SCOPE: string;

export type NobleIdScope = "openid" | "profile" | "email" | "orcid" | "affiliations" | "works" | "offline_access";

/** Error with an OAuth error code. Never carries token values. */
export declare class NobleIdError extends Error {
  readonly code: string;
  readonly description: string;
  readonly status?: number;
  /** Seconds (or an HTTP date) from Retry-After on a 429 `slow_down`, when sent. */
  readonly retryAfter?: number | string;
}

export interface CreateClientOptions {
  clientId: string;
  /** Confidential clients only. Read it from the environment; never commit it. */
  clientSecret?: string;
  /** Defaults to https://id.nobleid.org. */
  issuer?: string;
  clientAuth?: "client_secret_basic" | "client_secret_post" | "none";
  /** Permit an http://localhost issuer (a local mock). Ignored for any other host. */
  allowInsecureLocalhost?: boolean;
}

/** Keep this in your server-side session between startSignIn and finishSignIn. Use once. */
export interface SignInTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  maxAge: number | null;
  createdAt: number;
}

export interface TokenSet {
  access_token: string;
  /** Present only when offline_access was granted. Rotates on every refresh. */
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  /** The scope the user actually granted; may be narrower than requested. */
  scope?: string;
  /** Unix seconds, computed from expires_in. */
  expires_at: number;
}

/** Claims NobleID may release. Absent means "not granted" or "not known", never false. */
export interface NobleIdClaims {
  sub: string;
  nobleid: string;
  nobleid_uri: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  /** userinfo only */
  research_interests?: string[];
  /** NobleID checked a government-issued ID. */
  identity_verified?: boolean;
  /** Badge granted by NobleID staff. */
  nobleid_verified_researcher?: boolean;
  updated_at?: number;
  /** profile scope: the NobleID profile is complete. */
  profile_complete?: boolean;
  /** profile scope: "profile" < "orcid" < "authorship" ("incomplete" only on refresh). Not an identity check. */
  verification_level?: string;
  email?: string;
  /** Only link accounts by email when this is true. */
  email_verified?: boolean;
  /** Full https://orcid.org/... URI; present only when connected through ORCID sign-in. */
  orcid?: string;
  orcid_verified?: true;
  /** affiliations scope: the primary affiliation as entered; self-declared, not verified. */
  affiliation?: { name: string; ror?: string };
  /** userinfo only; self-asserted by the user, not verified. The primary one comes first. */
  affiliations?: Array<{ organization: string; role?: string; start_year?: number; ror?: string }>;
  /** userinfo only (scope works). */
  works_count?: number;
  works_endpoint?: string;
  /** userinfo only (scope works): authorships NobleID has verified. */
  verified_authorship_count?: number;
  auth_time?: number;
  /** e.g. ["pwd"], ["pwd","otp","mfa"]; check for "otp" to require a second factor. */
  amr?: string[];
  [claim: string]: unknown;
}

export interface Work {
  nobleid: string;
  ark: string;
  url: string;
  title: string;
  type: string;
  doi: string | null;
  publication_date: string | null;
  publication_year: number | null;
  version: number;
  registered_at: string;
}

export interface WorksPage {
  sub: string;
  total: number;
  limit: number;
  offset: number;
  works: Work[];
}

/**
 * The normalised profile from profileFromClaims(). Every field is present:
 * null, [] or false when the person did not share it or NobleID does not know it.
 */
export interface NobleIdProfile {
  /** Key your accounts on this. */
  sub: string;
  nobleid: string | null;
  nobleidUri: string | null;
  name: string | null;
  givenName: string | null;
  familyName: string | null;
  /** preferred_username: a suggestion only; it can change. */
  username: string | null;
  /** https only. */
  picture: string | null;
  /** http or https only. */
  website: string | null;
  /** The public NobleID profile page; null when the profile is not public. */
  profileUrl: string | null;
  researchInterests: string[];
  email: string | null;
  /** Link to an existing account by email only when this is true. */
  emailVerified: boolean;
  /** https://orcid.org/... Only when NobleID marked it proven through ORCID. */
  orcid: string | null;
  /** The main affiliation as the person entered it; not checked by NobleID. */
  affiliation: { name: string; ror: string | null } | null;
  /** Main affiliation first. Self-asserted. */
  affiliations: Array<{ organization: string; role: string | null; startYear: number | null; ror: string | null }>;
  identityVerified: boolean;
  verifiedResearcher: boolean;
  updatedAt: number | null;
}

/**
 * Build a NobleIdProfile from verified ID token claims and, optionally, the
 * userinfo response for the same `sub` (throws NobleIdError `invalid_token`
 * otherwise). Userinfo wins where both carry a claim.
 */
export declare function profileFromClaims(idTokenClaims: NobleIdClaims | Record<string, unknown>, userinfo?: NobleIdClaims | Record<string, unknown> | null): NobleIdProfile;

export declare function createNobleIdClient(options: CreateClientOptions): Promise<NobleIdClient>;

export declare class NobleIdClient {
  readonly config: Configuration;
  readonly issuer: string;
  readonly isPublic: boolean;
  startSignIn(options: {
    redirectUri: string;
    scope?: string;
    prompt?: "none" | "login" | "consent" | "select_account";
    maxAge?: number;
    loginHint?: string;
  }): Promise<{ url: string; transaction: SignInTransaction }>;
  finishSignIn(callbackUrl: string | URL, transaction: SignInTransaction | undefined): Promise<{ tokens: TokenSet; claims: NobleIdClaims; scope: string[] }>;
  userinfo(accessToken: string, expectedSub: string): Promise<NobleIdClaims>;
  works(accessToken: string, options?: { limit?: number; offset?: number }): Promise<WorksPage>;
  /**
   * Concurrent calls with the same token share one request. Pass the `sub`
   * stored at sign-in as `expectedSub`; a refresh-issued ID token for anyone
   * else is rejected (`invalid_id_token`). Its verified claims are in `claims`.
   */
  refresh(refreshToken: string, options?: { scope?: string; expectedSub?: string }): Promise<TokenSet & { claims?: NobleIdClaims }>;
  revoke(token: string, tokenTypeHint?: "refresh_token" | "access_token"): Promise<void>;
  introspect(token: string): Promise<IntrospectionResponse>;
}
