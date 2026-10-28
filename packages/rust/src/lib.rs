//! # nobleid-signin
//!
//! A thin server-side helper for "Sign in with NobleID", built on the
//! [`openidconnect`] crate with NobleID's settings already chosen:
//!
//! * discovery from `{issuer}/.well-known/openid-configuration`;
//! * ID tokens verified with **ES256 only** against the provider's JWKS (fetched
//!   again once when a token carries an unknown `kid`), plus `iss`, `aud`, `exp`
//!   and `nonce`;
//! * PKCE S256, `state` and `nonce` on every sign-in;
//! * the RFC 9207 `iss` check on every callback, *before* any `error` is surfaced;
//! * refresh-token rotation that never sends the same refresh token twice from
//!   one process at the same time;
//! * revocation (RFC 7009).
//!
//! It does no cryptography of its own. Keep tokens on your server: store the
//! [`Transaction`] from [`NobleId::start_sign_in`] in your server-side session
//! and hand it back to [`NobleId::finish_sign_in`].
//!
//! Token-holding types never print their secrets in `Debug`, and [`Error`]
//! never contains token values.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreClaimName, CoreClaimType,
    CoreClientAuthMethod, CoreErrorResponseType, CoreGenderClaim, CoreGrantType,
    CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType, CoreRevocableToken,
    CoreRevocationErrorResponse, CoreSubjectIdentifierType, CoreTokenIntrospectionResponse,
    CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, AdditionalProviderMetadata, AuthType, AuthUrl, AuthorizationCode, Client,
    ClaimsVerificationError, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    EndpointNotSet, EndpointSet, ErrorResponseType, HttpClientError, IdTokenClaims,
    IdTokenFields, IssuerUrl, JsonWebKeySet, JsonWebKeySetUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, ProviderMetadata, RedirectUrl, RequestTokenError,
    RevocationUrl, Scope, SignatureVerificationError, StandardErrorResponse,
    StandardTokenResponse, SubjectIdentifier, TokenResponse, TokenUrl, UserInfoClaims,
    UserInfoError, UserInfoUrl,
};
use serde::{Deserialize, Serialize};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub use openidconnect::{AccessToken, RefreshToken};

/// The production issuer.
pub const NOBLEID_ISSUER: &str = "https://id.nobleid.org";
/// Default scope (`openid` is always sent).
pub const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email"];
/// How long a sign-in may take between [`NobleId::start_sign_in`] and the callback.
pub const MAX_FLOW_AGE: Duration = Duration::from_secs(10 * 60);
/// Minimum gap between two JWKS re-fetches triggered by an unknown `kid`.
const JWKS_REFETCH_COOLDOWN: Duration = Duration::from_secs(30);

/* ───────────────────────────── errors ───────────────────────────── */

/// Everything that can go wrong. [`Error::code`] is the OAuth error code when
/// the provider sent one. No variant ever carries a token, code or secret.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    /// The provider answered with an OAuth error (`error`, `error_description`).
    #[error("{code}{}", .description.as_deref().map(|d| format!(": {d}")).unwrap_or_default())]
    OAuth {
        code: String,
        description: Option<String>,
        /// HTTP status, when known.
        status: Option<u16>,
        /// Seconds from `Retry-After`, when the provider sent one (rate limits).
        retry_after: Option<u64>,
    },
    /// No sign-in in progress, or `state` did not match.
    #[error("invalid_state: {0}")]
    InvalidState(&'static str),
    /// `iss` on the callback is missing or not this issuer (RFC 9207).
    #[error("invalid_issuer: the response did not come from the expected issuer")]
    InvalidIssuer,
    /// A malformed callback or argument.
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
    /// The sign-in took longer than [`MAX_FLOW_AGE`].
    #[error("expired: sign-in took too long; start again")]
    Expired,
    /// The ID token failed verification (signature, alg, iss, aud, exp, nonce, sub).
    #[error("invalid_id_token: {0}")]
    IdToken(String),
    /// The client is misconfigured (e.g. an http issuer that is not localhost).
    #[error("invalid_configuration: {0}")]
    Config(String),
    /// Network failure or an unparseable response.
    #[error("server_error: {0}")]
    Server(String),
    /// Claims that cannot belong together, e.g. userinfo for another `sub`
    /// than the ID token's ([`profile_from_claims`]).
    #[error("invalid_token: {0}")]
    Claims(String),
}

impl Error {
    /// The OAuth error code (`access_denied`, `invalid_grant`, `slow_down`, ...)
    /// or a local code (`invalid_state`, `invalid_issuer`, `invalid_request`,
    /// `expired`, `invalid_id_token`, `invalid_configuration`, `server_error`,
    /// `invalid_token`).
    pub fn code(&self) -> &str {
        match self {
            Error::OAuth { code, .. } => code,
            Error::InvalidState(_) => "invalid_state",
            Error::InvalidIssuer => "invalid_issuer",
            Error::InvalidRequest(_) => "invalid_request",
            Error::Expired => "expired",
            Error::IdToken(_) => "invalid_id_token",
            Error::Config(_) => "invalid_configuration",
            Error::Server(_) => "server_error",
            Error::Claims(_) => "invalid_token",
        }
    }

    /// The provider's `error_description`, or a short local explanation.
    pub fn description(&self) -> String {
        match self {
            Error::OAuth { description, .. } => description.clone().unwrap_or_default(),
            Error::InvalidState(d) => (*d).to_string(),
            Error::InvalidIssuer => "the response did not come from the expected issuer".into(),
            Error::InvalidRequest(d) | Error::IdToken(d) | Error::Config(d) | Error::Server(d) | Error::Claims(d) => d.clone(),
            Error::Expired => "sign-in took too long; start again".into(),
        }
    }

    /// Seconds to wait before retrying, when the provider rate-limited the call.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Error::OAuth { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    fn oauth(code: impl Into<String>, description: Option<String>, status: Option<u16>) -> Self {
        Error::OAuth { code: code.into(), description, status, retry_after: None }
    }
}

/// Error description from a token/revocation endpoint error, without any response body.
fn map_request_err<T>(e: RequestTokenError<HttpClientError<reqwest::Error>, StandardErrorResponse<T>>) -> Error
where
    T: ErrorResponseType + fmt::Display + 'static,
{
    match e {
        RequestTokenError::ServerResponse(r) => {
            Error::oauth(r.error().to_string(), r.error_description().cloned(), None)
        }
        RequestTokenError::Request(e) => Error::Server(http_err_text(&e)),
        // The unparsed body is deliberately dropped: it may contain tokens.
        RequestTokenError::Parse(e, _body) => Error::Server(format!("unparseable response: {}", e.path())),
        RequestTokenError::Other(s) => Error::Server(s),
    }
}

fn http_err_text(e: &HttpClientError<reqwest::Error>) -> String {
    match e {
        HttpClientError::Reqwest(re) => {
            let re = re.as_ref();
            if re.is_timeout() {
                "timeout".into()
            } else if re.is_connect() {
                "connection failed".into()
            } else {
                "request failed".into()
            }
        }
        other => format!("{other}"),
    }
}

fn map_claims_err(e: &ClaimsVerificationError) -> Error {
    Error::IdToken(match e {
        ClaimsVerificationError::SignatureVerification(s) => format!("signature verification failed: {s}"),
        other => other.to_string(),
    })
}

/// Parse an OAuth error body (`{"error": "...", "error_description": "..."}`).
fn error_from_body(status: u16, body: &[u8], retry_after: Option<u64>) -> Error {
    #[derive(Deserialize)]
    struct Body {
        error: Option<String>,
        error_description: Option<String>,
    }
    let parsed: Option<Body> = serde_json::from_slice(body).ok();
    let code = parsed.as_ref().and_then(|b| b.error.clone()).unwrap_or_else(|| match status {
        401 => "invalid_token".into(),
        403 => "insufficient_scope".into(),
        429 => "slow_down".into(),
        s => format!("http_{s}"),
    });
    Error::OAuth {
        code,
        description: parsed.and_then(|b| b.error_description),
        status: Some(status),
        retry_after,
    }
}

/* ───────────────────────────── claims ───────────────────────────── */

/// NobleID claims beyond the OpenID Connect standard ones. Every field is
/// optional: what you get depends on the scopes the user granted.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NobleIdClaims {
    /// `openid`: the member's NobleID (e.g. `NI...`). Key accounts on `sub`, not this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nobleid: Option<String>,
    /// `openid`: the member's public profile URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nobleid_uri: Option<String>,
    /// `profile`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_verified: Option<bool>,
    /// `profile`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nobleid_verified_researcher: Option<bool>,
    /// `orcid`: present only if the member connected ORCID through ORCID sign-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orcid: Option<String>,
    /// `orcid`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orcid_verified: Option<bool>,
    /// `profile`, userinfo only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub research_interests: Option<Vec<String>>,
    /// `profile`: the NobleID profile is complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_complete: Option<bool>,
    /// `profile`: `"profile"` < `"orcid"` < `"authorship"` (`"incomplete"` only
    /// on refresh). Not an identity check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_level: Option<String>,
    /// `affiliations`: the primary affiliation as entered. Self-declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affiliation: Option<PrimaryAffiliation>,
    /// `affiliations`, userinfo only. Self-asserted by the member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affiliations: Option<Vec<Affiliation>>,
    /// `works`, userinfo only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub works_count: Option<u64>,
    /// `works`, userinfo only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub works_endpoint: Option<String>,
    /// `works`, userinfo only: authorships NobleID has verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_authorship_count: Option<u64>,
}
impl AdditionalClaims for NobleIdClaims {}

/// The primary affiliation as the member entered it. `ror` is a
/// `https://ror.org/...` URL, present only when they chose one. Not verified.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PrimaryAffiliation {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ror: Option<String>,
}

/// One self-asserted affiliation.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Affiliation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// A four-digit year. Servers before 27 Oct 2026 sent it as a string
    /// ("2019"); that is read too, and anything else is `None` rather than
    /// an error that would fail the whole userinfo call.
    #[serde(default, deserialize_with = "de_year", skip_serializing_if = "Option::is_none")]
    pub start_year: Option<i32>,
    #[serde(default, deserialize_with = "de_year", skip_serializing_if = "Option::is_none")]
    pub end_year: Option<i32>,
    /// `https://ror.org/...`, when the member chose one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ror: Option<String>,
    /// Any fields added later.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// Verified ID-token claims (standard + [`NobleIdClaims`]).
pub type NobleIdIdTokenClaims = IdTokenClaims<NobleIdClaims, CoreGenderClaim>;
/// Claims from the userinfo endpoint (standard + [`NobleIdClaims`]).
pub type NobleIdUserInfo = UserInfoClaims<NobleIdClaims, CoreGenderClaim>;

fn de_year<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i32>, D::Error> {
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(v.as_ref().and_then(year_of))
}

fn year_of(v: &serde_json::Value) -> Option<i32> {
    match v {
        serde_json::Value::Number(n) => n.as_i64().filter(|y| (1000..=9999).contains(y)).map(|y| y as i32),
        serde_json::Value::String(s) => {
            let t = s.trim();
            (t.len() == 4 && t.bytes().all(|b| b.is_ascii_digit())).then(|| t.parse().ok()).flatten()
        }
        _ => None,
    }
}

/* ───────────────────────────── profile filling ───────────────────────────── */

/// A plain profile built from NobleID's claims, for filling your own app's
/// profile ([`profile_from_claims`]). `None`, an empty list or `false` means
/// the member did not share the value or NobleID does not know it.
///
/// Fill only empty fields with it, and never overwrite what the member
/// edited in your app (docs/profile-data.md).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Profile {
    /// The stable account key. Key your accounts on it.
    pub sub: String,
    pub nobleid: Option<String>,
    pub nobleid_uri: Option<String>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    /// `preferred_username`: a suggestion only; it can change.
    pub username: Option<String>,
    /// https only.
    pub picture: Option<String>,
    /// http or https only.
    pub website: Option<String>,
    /// The public NobleID profile page; `None` when the profile is not public.
    pub profile_url: Option<String>,
    pub research_interests: Vec<String>,
    pub email: Option<String>,
    /// Link to an existing account by email only when this is true.
    pub email_verified: bool,
    /// `https://orcid.org/...`, only when NobleID marked it proven through ORCID.
    pub orcid: Option<String>,
    /// The main affiliation as the member entered it. Not checked by NobleID.
    pub affiliation: Option<ProfileAffiliation>,
    /// The main affiliation first. Self-asserted.
    pub affiliations: Vec<ProfileAffiliationEntry>,
    pub identity_verified: bool,
    pub verified_researcher: bool,
    /// Unix seconds of the last NobleID profile change.
    pub updated_at: Option<i64>,
}

/// The main affiliation in a [`Profile`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ProfileAffiliation {
    pub name: String,
    /// `https://ror.org/...`
    pub ror: Option<String>,
}

/// One entry of [`Profile::affiliations`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ProfileAffiliationEntry {
    pub organization: String,
    pub role: Option<String>,
    pub start_year: Option<i32>,
    /// `https://ror.org/...`
    pub ror: Option<String>,
}

/// Build a [`Profile`] from the verified ID token claims and, optionally,
/// the userinfo response for the same `sub`. Userinfo wins where both carry
/// a claim: it is fresher and has more. Fails with code `invalid_token`
/// when userinfo is for another subject.
pub fn profile_from_claims(id_token: &NobleIdIdTokenClaims, userinfo: Option<&NobleIdUserInfo>) -> Result<Profile, Error> {
    let id = serde_json::to_value(id_token).map_err(|e| Error::Server(e.to_string()))?;
    let ui = userinfo.map(serde_json::to_value).transpose().map_err(|e| Error::Server(e.to_string()))?;
    profile_from_json(&id, ui.as_ref())
}

/// [`profile_from_claims`] from raw JSON claim sets (the decoded ID token
/// payload and the userinfo body). Fails with code `invalid_token` when the
/// ID token has no `sub` or userinfo is for another subject.
pub fn profile_from_json(id_token: &serde_json::Value, userinfo: Option<&serde_json::Value>) -> Result<Profile, Error> {
    use serde_json::Value;
    let empty = serde_json::Map::new();
    let id = id_token.as_object().unwrap_or(&empty);
    let ui = userinfo.and_then(Value::as_object).unwrap_or(&empty);
    let sub = text(id.get("sub")).ok_or_else(|| Error::Claims("the ID token has no sub".into()))?;
    if let Some(other) = ui.get("sub") {
        if other.as_str() != Some(sub.as_str()) {
            return Err(Error::Claims("userinfo is for another subject".into()));
        }
    }
    let get = |k: &str| ui.get(k).or_else(|| id.get(k));
    let is_true = |k: &str| get(k) == Some(&Value::Bool(true));

    let mut seen = HashSet::new();
    let research_interests = get("research_interests")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(|v| text(Some(v))).filter(|t| seen.insert(t.to_lowercase())).collect())
        .unwrap_or_default();
    let affiliation = get("affiliation").and_then(Value::as_object).and_then(|a| {
        Some(ProfileAffiliation { name: text(a.get("name"))?, ror: text(a.get("ror")).filter(|r| is_ror_uri(r)) })
    });
    let affiliations = get("affiliations")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_object)
                .filter_map(|a| {
                    Some(ProfileAffiliationEntry {
                        organization: text(a.get("organization"))?,
                        role: text(a.get("role")),
                        start_year: a.get("start_year").and_then(year_of),
                        ror: text(a.get("ror")).filter(|r| is_ror_uri(r)),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let email = text(get("email"));
    Ok(Profile {
        nobleid: text(get("nobleid")),
        nobleid_uri: url_with(get("nobleid_uri"), &["https"]),
        name: text(get("name")),
        given_name: text(get("given_name")),
        family_name: text(get("family_name")),
        username: text(get("preferred_username")),
        picture: url_with(get("picture"), &["https"]),
        website: url_with(get("website"), &["https", "http"]),
        profile_url: url_with(get("profile"), &["https"]),
        research_interests,
        email_verified: email.is_some() && is_true("email_verified"),
        email,
        orcid: text(get("orcid")).filter(|o| is_true("orcid_verified") && is_orcid_uri(o)),
        affiliation,
        affiliations,
        identity_verified: is_true("identity_verified"),
        verified_researcher: is_true("nobleid_verified_researcher"),
        updated_at: get("updated_at").and_then(Value::as_i64),
        sub,
    })
}

fn text(v: Option<&serde_json::Value>) -> Option<String> {
    v.and_then(serde_json::Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn url_with(v: Option<&serde_json::Value>, schemes: &[&str]) -> Option<String> {
    let t = text(v)?;
    if t.chars().any(char::is_whitespace) {
        return None;
    }
    let u = url::Url::parse(&t).ok()?;
    (schemes.contains(&u.scheme()) && u.host_str().is_some_and(|h| !h.is_empty())).then_some(t)
}

fn is_orcid_uri(s: &str) -> bool {
    let Some(id) = s.strip_prefix("https://orcid.org/") else { return false };
    id.len() == 19
        && id.chars().enumerate().all(|(i, c)| match i {
            4 | 9 | 14 => c == '-',
            18 => c.is_ascii_digit() || c == 'X',
            _ => c.is_ascii_digit(),
        })
}

fn is_ror_uri(s: &str) -> bool {
    let Some(id) = s.strip_prefix("https://ror.org/") else { return false };
    let b = id.as_bytes();
    b.len() == 9
        && b[0] == b'0'
        && b[1..7].iter().all(|c| c.is_ascii_digit() || (c.is_ascii_lowercase() && !matches!(c, b'i' | b'l' | b'o' | b'u')))
        && b[7..].iter().all(u8::is_ascii_digit)
}

/* ───────────────────────────── openidconnect types ───────────────────────────── */

/// Discovery fields the core metadata type does not carry.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExtraProviderMetadata {
    revocation_endpoint: Option<RevocationUrl>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: Option<bool>,
}
impl AdditionalProviderMetadata for ExtraProviderMetadata {}

type NobleIdProviderMetadata = ProviderMetadata<
    ExtraProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

type NobleIdTokenResponse = StandardTokenResponse<
    IdTokenFields<NobleIdClaims, EmptyExtraTokenFields, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>,
    CoreTokenType,
>;

type OidcClient = Client<
    NobleIdClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    NobleIdTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,    // authorization
    EndpointNotSet, // device authorization
    EndpointNotSet, // introspection
    EndpointNotSet, // revocation (done in `revoke`, see there)
    EndpointSet,    // token
    EndpointSet,    // userinfo
>;

/* ───────────────────────────── public data types ───────────────────────────── */

/// How the client authenticates at the token endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuth {
    /// `client_secret_basic` (id and secret form-urlencoded, then base64). The default.
    SecretBasic,
    /// `client_secret_post`.
    SecretPost,
}

/// Settings for [`NobleId::discover`].
#[derive(Clone)]
pub struct Config {
    /// `https://id.nobleid.org` in production. `http://` is accepted only for
    /// `localhost` / `127.0.0.1` / `[::1]` (a local mock).
    pub issuer: String,
    /// Your client id (`nbcl_...`).
    pub client_id: String,
    /// Confidential clients only. Read it from the environment, never from source.
    pub client_secret: Option<String>,
    /// Your registered redirect URI, exactly.
    pub redirect_uri: String,
    /// Token-endpoint client authentication (ignored for public clients).
    pub client_auth: ClientAuth,
}

impl Config {
    pub fn new(issuer: impl Into<String>, client_id: impl Into<String>, client_secret: Option<String>, redirect_uri: impl Into<String>) -> Self {
        Config {
            issuer: issuer.into(),
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            client_auth: ClientAuth::SecretBasic,
        }
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret.as_ref().map(|_| "[redacted]"))
            .field("redirect_uri", &self.redirect_uri)
            .field("client_auth", &self.client_auth)
            .finish()
    }
}

/// A sign-in in progress. Keep it in your **server-side** session (never in a
/// URL or a client-readable cookie) and pass it to [`NobleId::finish_sign_in`]
/// exactly once. It is `Serialize`/`Deserialize` so any session store can hold it.
#[derive(Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// The `state` sent on the authorization request.
    pub state: String,
    /// The `nonce` sent on the authorization request.
    pub nonce: String,
    /// The PKCE code verifier (the S256 challenge was sent).
    pub pkce_verifier: String,
    /// Unix time (seconds) when the sign-in started.
    pub created_at: u64,
    /// The scopes that were requested.
    pub scopes: Vec<String>,
}

impl fmt::Debug for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("state", &"[redacted]")
            .field("nonce", &"[redacted]")
            .field("pkce_verifier", &"[redacted]")
            .field("created_at", &self.created_at)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Tokens from the token endpoint. `Debug` never prints token values.
#[derive(Clone)]
pub struct TokenSet {
    pub access_token: AccessToken,
    /// Present only when `offline_access` was granted. It rotates on every use.
    pub refresh_token: Option<RefreshToken>,
    /// The raw ID token (a JWT). Use [`TokenSet::id_token`] to read it.
    id_token: Option<String>,
    /// When the access token expires, from `expires_in` (never hardcoded).
    pub expires_at: Option<SystemTime>,
    /// The scopes actually granted. The user may untick any scope except `openid`.
    pub scopes: Vec<String>,
}

impl TokenSet {
    /// The raw ID token. Treat it as a secret.
    pub fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }
    /// Whether `scope` was granted.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"[redacted]")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "[redacted]"))
            .field("id_token", &self.id_token.as_ref().map(|_| "[redacted]"))
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// The result of a completed sign-in.
#[derive(Clone, Debug)]
pub struct SignIn {
    pub tokens: TokenSet,
    /// Verified ID-token claims. Key your account on `claims.subject()`, never on email.
    pub claims: NobleIdIdTokenClaims,
}

/// The result of a refresh.
#[derive(Clone, Debug)]
pub struct Refreshed {
    /// The new tokens. Store the new refresh token; the old one is now used up.
    pub tokens: TokenSet,
    /// Claims of the refresh-issued ID token, verified (no nonce, auth_time or amr on these).
    pub claims: Option<NobleIdIdTokenClaims>,
}

/// Which token [`NobleId::revoke`] is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenTypeHint {
    AccessToken,
    RefreshToken,
}

/// One page of `/oauth/works`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorksPage {
    pub sub: String,
    pub total: u64,
    pub limit: u32,
    pub offset: u64,
    pub works: Vec<Work>,
}

/// One registered work.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Work {
    pub nobleid: String,
    /// `ark:/48914/...`
    pub ark: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default, rename = "type")]
    pub work_type: Option<String>,
    #[serde(default)]
    pub doi: Option<String>,
    #[serde(default)]
    pub publication_date: Option<String>,
    #[serde(default)]
    pub publication_year: Option<i32>,
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub registered_at: Option<String>,
    /// Any fields added later.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/* ───────────────────────────── the client ───────────────────────────── */

struct Endpoints {
    issuer: IssuerUrl,
    auth: AuthUrl,
    token: TokenUrl,
    userinfo: UserInfoUrl,
    revocation: RevocationUrl,
    jwks_uri: JsonWebKeySetUrl,
}

/// The outcome of one refresh request, shared by every caller waiting on it.
type RefreshOutcome = Option<Result<Arc<NobleIdTokenResponse>, Error>>;
type RefreshMap = Arc<Mutex<HashMap<[u8; 32], tokio::sync::watch::Receiver<RefreshOutcome>>>>;

/// A discovered NobleID client. Cheap to share (`Arc` it); create it once at startup.
pub struct NobleId {
    cfg: Config,
    ep: Endpoints,
    http: reqwest::Client,
    client: RwLock<Arc<OidcClient>>,
    last_jwks_fetch: Mutex<Option<Instant>>,
    refreshing: RefreshMap,
}

impl fmt::Debug for NobleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NobleId").field("config", &self.cfg).finish_non_exhaustive()
    }
}

fn is_local_http(u: &url::Url) -> bool {
    u.scheme() == "http"
        && match u.host() {
            Some(url::Host::Domain(d)) => d == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        }
}

fn check_endpoint(issuer_is_local: bool, name: &str, u: &url::Url) -> Result<(), Error> {
    if u.scheme() == "https" || (issuer_is_local && is_local_http(u)) {
        Ok(())
    } else {
        Err(Error::Config(format!("{name} must be https")))
    }
}

/// Check a parsed discovery document: `issuer` equals ours exactly, ES256 is
/// offered, every endpoint is present and https (http only for a localhost mock).
/// Runs before the JWKS is fetched.
fn check_discovered(meta: &NobleIdProviderMetadata, issuer: &IssuerUrl, local: bool) -> Result<Endpoints, Error> {
    if meta.issuer().as_str() != issuer.as_str() {
        return Err(Error::Config("the discovery document's issuer does not match".into()));
    }
    let algs = meta.id_token_signing_alg_values_supported();
    if !algs.contains(&CoreJwsSigningAlgorithm::EcdsaP256Sha256) {
        return Err(Error::Config("the provider does not offer ES256 ID tokens".into()));
    }
    let ep = Endpoints {
        issuer: meta.issuer().clone(),
        auth: meta.authorization_endpoint().clone(),
        token: meta.token_endpoint().cloned().ok_or_else(|| Error::Config("no token_endpoint".into()))?,
        userinfo: meta.userinfo_endpoint().cloned().ok_or_else(|| Error::Config("no userinfo_endpoint".into()))?,
        revocation: meta
            .additional_metadata()
            .revocation_endpoint
            .clone()
            .ok_or_else(|| Error::Config("no revocation_endpoint".into()))?,
        jwks_uri: meta.jwks_uri().clone(),
    };
    check_endpoint(local, "authorization_endpoint", ep.auth.url())?;
    check_endpoint(local, "token_endpoint", ep.token.url())?;
    check_endpoint(local, "userinfo_endpoint", ep.userinfo.url())?;
    check_endpoint(local, "revocation_endpoint", ep.revocation.url())?;
    check_endpoint(local, "jwks_uri", ep.jwks_uri.url())?;
    Ok(ep)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Constant-time string comparison (hashes first, so lengths do not leak either).
fn same_secret(a: &str, b: &str) -> bool {
    let ha = Sha256::digest(a.as_bytes());
    let hb = Sha256::digest(b.as_bytes());
    bool::from(ha[..].ct_eq(&hb[..]))
}

impl NobleId {
    /// Fetch the discovery document and JWKS, and build a client. The
    /// document's `issuer` and endpoints are checked before the JWKS is fetched.
    ///
    /// `http://` issuers are refused unless the host is `localhost`, `127.0.0.1`
    /// or `[::1]` (the local mock).
    pub async fn discover(cfg: Config) -> Result<Self, Error> {
        if cfg.client_id.is_empty() {
            return Err(Error::Config("client_id is required".into()));
        }
        let issuer_url = url::Url::parse(&cfg.issuer).map_err(|_| Error::Config("issuer is not a URL".into()))?;
        let local = is_local_http(&issuer_url);
        if issuer_url.scheme() != "https" && !local {
            return Err(Error::Config("the issuer must be https (http is allowed only for a localhost mock)".into()));
        }
        RedirectUrl::new(cfg.redirect_uri.clone()).map_err(|_| Error::Config("redirect_uri is not a URL".into()))?;

        // openidconnect recommends disabling redirects (SSRF). rustls, no native TLS.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("nobleid-signin-rust/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| Error::Config("could not build the HTTP client".into()))?;

        let issuer = IssuerUrl::new(cfg.issuer.clone()).map_err(|_| Error::Config("issuer is not a URL".into()))?;
        // Discovery is fetched here rather than with `discover_async`, so that the
        // issuer and every endpoint are checked *before* anything is fetched from
        // the document's `jwks_uri`.
        let discovery_url = issuer
            .join(".well-known/openid-configuration")
            .map_err(|_| Error::Config("issuer is not a URL".into()))?;
        let res = http
            .get(discovery_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| Error::Server(format!("discovery failed: {}", if e.is_timeout() { "timeout" } else { "request failed" })))?;
        if res.status().as_u16() != 200 {
            return Err(Error::Server(format!("discovery failed: HTTP {}", res.status().as_u16())));
        }
        let body = res.bytes().await.map_err(|_| Error::Server("discovery failed: could not read the response".into()))?;
        let meta: NobleIdProviderMetadata =
            serde_json::from_slice(&body).map_err(|_| Error::Server("discovery failed: unparseable document".into()))?;
        let ep = check_discovered(&meta, &issuer, local)?;
        let jwks: JsonWebKeySet<CoreJsonWebKey> = JsonWebKeySet::fetch_async(&ep.jwks_uri, &http)
            .await
            .map_err(|e| Error::Server(format!("JWKS fetch failed: {e}")))?;
        let client = build_client(&cfg, &ep, jwks)?;
        Ok(NobleId {
            cfg,
            ep,
            http,
            client: RwLock::new(Arc::new(client)),
            last_jwks_fetch: Mutex::new(None),
            refreshing: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// The issuer, exactly as discovered.
    pub fn issuer(&self) -> &str {
        self.ep.issuer.as_str()
    }

    fn client(&self) -> Arc<OidcClient> {
        self.client.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Build the authorization URL. Returns `(url, transaction)`: redirect the
    /// browser to `url`, keep `transaction` in the server-side session.
    ///
    /// `openid` is always sent; each scope goes in as its own value (the URL
    /// carries them space-separated).
    pub fn start_sign_in(&self, scopes: &[&str]) -> (url::Url, Transaction) {
        let client = self.client();
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut req = client.authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random);
        let mut seen = HashSet::new();
        let mut requested = vec!["openid".to_string()];
        for s in scopes.iter().flat_map(|s| s.split_whitespace()) {
            if s != "openid" && seen.insert(s.to_string()) {
                req = req.add_scope(Scope::new(s.to_string()));
                requested.push(s.to_string());
            }
        }
        let (url, state, nonce) = req.set_pkce_challenge(challenge).url();
        let tx = Transaction {
            state: state.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: verifier.secret().clone(),
            created_at: now_secs(),
            scopes: requested,
        };
        (url, tx)
    }

    /// Complete sign-in on the redirect URI.
    ///
    /// `query` is the raw query string of the callback request (without `?`).
    /// `transaction` is what [`start_sign_in`](Self::start_sign_in) returned; take
    /// it out of the session before calling, so it is used once whatever happens.
    ///
    /// Checks, in this order: a sign-in is in progress, `state` matches
    /// (constant time), `iss` equals the issuer (missing `iss` is rejected),
    /// then surfaces any `error`, then requires `code`, then the flow age
    /// (at most [`MAX_FLOW_AGE`]). Only then is the code exchanged (with the PKCE
    /// verifier) and the ID token verified: ES256 signature via the JWKS, `iss`,
    /// `aud`, `exp` and `nonce`.
    pub async fn finish_sign_in(&self, query: &str, transaction: Option<Transaction>) -> Result<SignIn, Error> {
        let params = CallbackParams::parse(query)?;
        let tx = transaction.ok_or(Error::InvalidState("no sign-in in progress"))?;
        params.check(&tx, self.issuer(), now_secs())?;
        let code = params.code.expect("checked");

        let client = self.client();
        let resp = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(tx.pkce_verifier.clone()))
            .request_async(&self.http)
            .await
            .map_err(map_request_err)?;

        let id_token = resp.id_token().ok_or_else(|| Error::IdToken("the token response has no id_token".into()))?;
        let nonce = Nonce::new(tx.nonce.clone());
        let claims = self
            .verify_id_token(|c| {
                // ES256 only. iss, aud and exp are checked by default.
                let v = c.id_token_verifier().set_allowed_algs(vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256]);
                id_token.claims(&v, &nonce).cloned()
            })
            .await?;

        let tokens = token_set(&resp, &tx.scopes);
        Ok(SignIn { tokens, claims })
    }

    /// Verify with the current JWKS; on an unknown `kid`, fetch the JWKS again once and retry.
    async fn verify_id_token<F>(&self, f: F) -> Result<NobleIdIdTokenClaims, Error>
    where
        F: Fn(&OidcClient) -> Result<NobleIdIdTokenClaims, ClaimsVerificationError>,
    {
        let first = f(&self.client());
        match first {
            Ok(c) => Ok(c),
            Err(ClaimsVerificationError::SignatureVerification(SignatureVerificationError::NoMatchingKey)) => {
                self.refetch_jwks().await?;
                f(&self.client()).map_err(|e| map_claims_err(&e))
            }
            Err(e) => Err(map_claims_err(&e)),
        }
    }

    async fn refetch_jwks(&self) -> Result<(), Error> {
        {
            let mut last = self.last_jwks_fetch.lock().unwrap_or_else(|p| p.into_inner());
            if last.is_some_and(|t| t.elapsed() < JWKS_REFETCH_COOLDOWN) {
                return Err(Error::IdToken("signed with an unknown key".into()));
            }
            *last = Some(Instant::now());
        }
        let jwks: JsonWebKeySet<CoreJsonWebKey> = JsonWebKeySet::fetch_async(&self.ep.jwks_uri, &self.http)
            .await
            .map_err(|e| Error::Server(format!("JWKS fetch failed: {e}")))?;
        let client = build_client(&self.cfg, &self.ep, jwks)?;
        *self.client.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(client);
        Ok(())
    }

    /// Read the userinfo endpoint (GET, `Authorization: Bearer`). Pass the ID
    /// token's `sub` as `expected_sub`; a different `sub` is rejected.
    /// Userinfo-only claims (`research_interests`, `affiliations`, `works_count`,
    /// `works_endpoint`, `verified_authorship_count`) are in `additional_claims()`.
    pub async fn userinfo(&self, access_token: &AccessToken, expected_sub: Option<&str>) -> Result<NobleIdUserInfo, Error> {
        let client = self.client();
        client
            .user_info(access_token.clone(), expected_sub.map(|s| SubjectIdentifier::new(s.to_string())))
            .request_async(&self.http)
            .await
            .map_err(|e| match e {
                UserInfoError::Response(status, body, _) => error_from_body(status.as_u16(), &body, None),
                UserInfoError::ClaimsVerification(c) => map_claims_err(&c),
                UserInfoError::Request(e) => Error::Server(http_err_text(&e)),
                UserInfoError::Parse(e) => Error::Server(format!("unparseable userinfo response: {}", e.path())),
                other => Error::Server(other.to_string()),
            })
    }

    /// List the member's registered works (needs the `works` scope).
    /// `limit` is 1..=100.
    pub async fn works(&self, access_token: &AccessToken, limit: u32, offset: u64) -> Result<WorksPage, Error> {
        if !(1..=100).contains(&limit) {
            return Err(Error::InvalidRequest("limit must be 1..=100".into()));
        }
        let mut url = self.ep.issuer.join("oauth/works").map_err(|_| Error::Config("bad issuer".into()))?;
        url.query_pairs_mut().append_pair("limit", &limit.to_string()).append_pair("offset", &offset.to_string());
        let res = self
            .http
            .get(url)
            .bearer_auth(access_token.secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| Error::Server(if e.is_timeout() { "timeout".into() } else { "request failed".into() }))?;
        let status = res.status().as_u16();
        let retry_after = retry_after(res.headers());
        let body = res.bytes().await.map_err(|_| Error::Server("could not read the response".into()))?;
        if !(200..300).contains(&status) {
            return Err(error_from_body(status, &body, retry_after));
        }
        serde_json::from_slice(&body).map_err(|_| Error::Server("unparseable works response".into()))
    }

    /// Use a refresh token. NobleID **rotates** refresh tokens: store the new
    /// one and discard the old one. Presenting a used refresh token again ends
    /// the whole session (every token from that sign-in), so:
    ///
    /// * concurrent calls in this process with the same token share one request,
    ///   which runs in its own task: a caller that is cancelled (dropped) does not
    ///   cancel it, and nobody re-sends the token;
    /// * across processes or hosts, serialise refreshes yourself (for example a
    ///   per-session lock in your session store) and re-read the stored token
    ///   after taking the lock.
    ///
    /// Needs a Tokio runtime. On [`Error::OAuth`] with code `invalid_grant`, sign
    /// the user out. The refresh-issued ID token is verified for each caller, and
    /// `expected_sub`, when given, must equal its `sub` (pass the `sub` you stored
    /// at sign-in). An `expected_sub` with no ID token in the response is accepted:
    /// the token endpoint only answers for the refresh token's own subject.
    pub async fn refresh(&self, refresh_token: &RefreshToken, expected_sub: Option<&str>) -> Result<Refreshed, Error> {
        let resp = self.refresh_shared(refresh_token).await?;
        let claims = match resp.id_token() {
            Some(id_token) => {
                // Refresh-issued ID tokens carry no nonce: accept its absence, reject a stray one.
                let c = self
                    .verify_id_token(|c| {
                        let v = c.id_token_verifier().set_allowed_algs(vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256]);
                        id_token.claims(&v, |n: Option<&Nonce>| if n.is_none() { Ok(()) } else { Err("unexpected nonce".to_string()) }).cloned()
                    })
                    .await?;
                if let Some(sub) = expected_sub {
                    if !same_secret(c.subject().as_str(), sub) {
                        return Err(Error::IdToken("the refreshed ID token is for another subject".into()));
                    }
                }
                Some(c)
            }
            None => None,
        };
        // If the provider omits `scope`, the grant is unchanged; we cannot know the
        // original here, so report what we were told (possibly empty).
        Ok(Refreshed { tokens: token_set(&resp, &[]), claims })
    }

    /// One token-endpoint request per refresh token in flight, run detached and
    /// shared with every concurrent caller. Only in-flight callers share it: once
    /// it finishes the entry is gone, so a later replay of the used token is sent
    /// (and refused by the provider) rather than answered from memory.
    async fn refresh_shared(&self, refresh_token: &RefreshToken) -> Result<Arc<NobleIdTokenResponse>, Error> {
        let key: [u8; 32] = Sha256::digest(refresh_token.secret().as_bytes()).into();
        let mut rx = {
            let mut map = self.refreshing.lock().unwrap_or_else(|p| p.into_inner());
            match map.get(&key) {
                Some(rx) => rx.clone(),
                None => {
                    let (tx, rx) = tokio::sync::watch::channel::<RefreshOutcome>(None);
                    map.insert(key, rx.clone());
                    let client = self.client();
                    let http = self.http.clone();
                    let token = refresh_token.clone();
                    let map_ref = Arc::clone(&self.refreshing);
                    tokio::spawn(async move {
                        // Removes the entry even if this task panics, so the token
                        // is not stuck behind a dead request.
                        let guard = RemoveOnDrop(map_ref, key);
                        let result = client
                            .exchange_refresh_token(&token)
                            .request_async(&http)
                            .await
                            .map(Arc::new)
                            .map_err(map_request_err);
                        // Publish first, then remove: a caller arriving in between
                        // gets this result instead of sending the spent token again.
                        let _ = tx.send(Some(result));
                        drop(guard);
                    });
                    rx
                }
            }
        };
        let outcome = rx
            .wait_for(|v| v.is_some())
            .await
            .map_err(|_| Error::Server("the refresh request was abandoned".into()))?;
        outcome.clone().expect("checked by wait_for")
    }

    /// Revoke a token (RFC 7009). Revoking the refresh token also ends the
    /// access tokens issued from it. NobleID has no end-session endpoint: to sign
    /// out, revoke the refresh token (and the access token), then clear your session.
    ///
    /// This one request is made here rather than by `oauth2`, whose revocation
    /// helper refuses any non-https endpoint (which rules out a localhost mock).
    /// Client authentication is the same as at the token endpoint.
    pub async fn revoke(&self, token: &str, hint: TokenTypeHint) -> Result<(), Error> {
        let mut form: Vec<(&str, &str)> = vec![
            ("token", token),
            (
                "token_type_hint",
                match hint {
                    TokenTypeHint::AccessToken => "access_token",
                    TokenTypeHint::RefreshToken => "refresh_token",
                },
            ),
        ];
        let mut req = self.http.post(self.ep.revocation.url().clone()).header(reqwest::header::ACCEPT, "application/json");
        match (&self.cfg.client_secret, self.cfg.client_auth) {
            (Some(secret), ClientAuth::SecretBasic) => {
                // RFC 6749 2.3.1: form-urlencode id and secret, then base64.
                let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
                let cred = BASE64_STANDARD.encode(format!("{}:{}", enc(&self.cfg.client_id), enc(secret)));
                req = req.header(reqwest::header::AUTHORIZATION, format!("Basic {cred}"));
            }
            (Some(secret), ClientAuth::SecretPost) => {
                form.push(("client_id", &self.cfg.client_id));
                form.push(("client_secret", secret));
            }
            (None, _) => form.push(("client_id", &self.cfg.client_id)),
        }
        let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
        let res = req
            .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| Error::Server(if e.is_timeout() { "timeout".into() } else { "request failed".into() }))?;
        let status = res.status().as_u16();
        if (200..300).contains(&status) {
            return Ok(());
        }
        let retry_after = retry_after(res.headers());
        let body = res.bytes().await.unwrap_or_default();
        Err(error_from_body(status, &body, retry_after))
    }
}

struct RemoveOnDrop(RefreshMap, [u8; 32]);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.1);
    }
}

fn retry_after(h: &reqwest::header::HeaderMap) -> Option<u64> {
    h.get(reqwest::header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok())
}

fn build_client(cfg: &Config, ep: &Endpoints, jwks: JsonWebKeySet<CoreJsonWebKey>) -> Result<OidcClient, Error> {
    let redirect = RedirectUrl::new(cfg.redirect_uri.clone()).map_err(|_| Error::Config("redirect_uri is not a URL".into()))?;
    let mut c = Client::new(ClientId::new(cfg.client_id.clone()), ep.issuer.clone(), jwks)
        .set_auth_uri(ep.auth.clone())
        .set_token_uri(ep.token.clone())
        .set_user_info_url(ep.userinfo.clone())
        .set_redirect_uri(redirect);
    if let Some(secret) = &cfg.client_secret {
        c = c.set_client_secret(ClientSecret::new(secret.clone())).set_auth_type(match cfg.client_auth {
            ClientAuth::SecretBasic => AuthType::BasicAuth,
            ClientAuth::SecretPost => AuthType::RequestBody,
        });
    } else {
        // Public client: client_id goes in the body, no secret.
        c = c.set_auth_type(AuthType::RequestBody);
    }
    Ok(c)
}

fn token_set(resp: &NobleIdTokenResponse, requested: &[String]) -> TokenSet {
    let scopes = match resp.scopes() {
        Some(s) => s.iter().map(|s| s.to_string()).collect(),
        // RFC 6749 5.1: an omitted scope means "as requested".
        None => requested.to_vec(),
    };
    TokenSet {
        access_token: resp.access_token().clone(),
        refresh_token: resp.refresh_token().cloned(),
        id_token: resp.id_token().map(|t| t.to_string()),
        expires_at: resp.expires_in().map(|d| SystemTime::now() + d),
        scopes,
    }
}

/* ───────────────────────────── callback checks ───────────────────────────── */

#[derive(Default)]
struct CallbackParams {
    state: Option<String>,
    iss: Option<String>,
    code: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

impl CallbackParams {
    fn parse(query: &str) -> Result<Self, Error> {
        let mut p = CallbackParams::default();
        for (k, v) in url::form_urlencoded::parse(query.trim_start_matches('?').as_bytes()) {
            let slot = match k.as_ref() {
                "state" => &mut p.state,
                "iss" => &mut p.iss,
                "code" => &mut p.code,
                "error" => &mut p.error,
                "error_description" => &mut p.error_description,
                _ => continue,
            };
            if slot.is_some() {
                return Err(Error::InvalidRequest(format!("repeated parameter: {k}")));
            }
            *slot = Some(v.into_owned());
        }
        Ok(p)
    }

    /// The callback checks, in order. Pure, so it is unit-tested below.
    fn check(&self, tx: &Transaction, issuer: &str, now: u64) -> Result<(), Error> {
        match &self.state {
            Some(s) if same_secret(s, &tx.state) => {}
            _ => return Err(Error::InvalidState("state does not match")),
        }
        match &self.iss {
            Some(i) if i == issuer => {}
            _ => return Err(Error::InvalidIssuer),
        }
        if let Some(code) = &self.error {
            return Err(Error::oauth(code.clone(), self.error_description.clone(), None));
        }
        if self.code.as_deref().unwrap_or("").is_empty() {
            return Err(Error::InvalidRequest("no authorization code".into()));
        }
        if now.saturating_sub(tx.created_at) > MAX_FLOW_AGE.as_secs() {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISS: &str = "https://id.nobleid.org";

    fn tx(now: u64) -> Transaction {
        Transaction { state: "s-123".into(), nonce: "n".into(), pkce_verifier: "v".into(), created_at: now, scopes: vec!["openid".into()] }
    }

    fn check(q: &str) -> Result<(), Error> {
        CallbackParams::parse(q)?.check(&tx(1000), ISS, 1000)
    }

    #[test]
    fn happy_path() {
        assert!(check("code=c&state=s-123&iss=https%3A%2F%2Fid.nobleid.org").is_ok());
    }

    #[test]
    fn state_is_checked_first() {
        // wrong state + wrong iss + error: the state failure wins
        let e = check("error=access_denied&state=nope&iss=https%3A%2F%2Fevil.example").unwrap_err();
        assert_eq!(e.code(), "invalid_state");
        assert_eq!(check("code=c&iss=https%3A%2F%2Fid.nobleid.org").unwrap_err().code(), "invalid_state");
    }

    #[test]
    fn iss_is_checked_before_error() {
        let e = check("error=access_denied&state=s-123&iss=https%3A%2F%2Fevil.example").unwrap_err();
        assert_eq!(e.code(), "invalid_issuer");
        let e = check("error=access_denied&state=s-123").unwrap_err();
        assert_eq!(e.code(), "invalid_issuer", "missing iss must be rejected");
    }

    #[test]
    fn error_is_surfaced_after_state_and_iss() {
        let e = check("error=access_denied&error_description=no&state=s-123&iss=https%3A%2F%2Fid.nobleid.org").unwrap_err();
        assert_eq!(e.code(), "access_denied");
        assert_eq!(e.to_string(), "access_denied: no");
    }

    #[test]
    fn code_required_then_age() {
        assert_eq!(check("state=s-123&iss=https%3A%2F%2Fid.nobleid.org").unwrap_err().code(), "invalid_request");
        let p = CallbackParams::parse("code=c&state=s-123&iss=https%3A%2F%2Fid.nobleid.org").unwrap();
        assert_eq!(p.check(&tx(1000), ISS, 1000 + 601).unwrap_err().code(), "expired");
        assert!(p.check(&tx(1000), ISS, 1000 + 600).is_ok());
    }

    #[test]
    fn repeated_parameters_are_rejected() {
        assert_eq!(check("code=c&state=s-123&state=s-123&iss=x").unwrap_err().code(), "invalid_request");
    }

    #[test]
    fn local_http_only() {
        assert!(is_local_http(&url::Url::parse("http://localhost:9400").unwrap()));
        assert!(is_local_http(&url::Url::parse("http://127.0.0.1:9400").unwrap()));
        assert!(!is_local_http(&url::Url::parse("http://id.nobleid.org").unwrap()));
        assert!(!is_local_http(&url::Url::parse("http://localhost.evil.example").unwrap()));
    }

    #[tokio::test]
    async fn http_issuer_refused() {
        let e = NobleId::discover(Config::new("http://id.nobleid.org", "nbcl_x", None, "http://localhost/callback")).await.unwrap_err();
        assert_eq!(e.code(), "invalid_configuration");
    }

    /// A tiny HTTP server for the discovery and refresh tests. `doc` is the
    /// discovery document with `{base}` standing for the server's own URL.
    /// Returns the issuer URL and per-path hit counters.
    async fn mock(doc: &'static str, token_delay: Duration) -> (String, Arc<Mutex<HashMap<String, usize>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let hits: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
        let (b, h) = (base.clone(), hits.clone());
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let (b, h) = (b.clone(), h.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
                    *h.lock().unwrap().entry(path.clone()).or_default() += 1;
                    let body = match path.as_str() {
                        "/.well-known/openid-configuration" => doc.replace("{base}", &b),
                        "/jwks" => r#"{"keys":[]}"#.to_string(),
                        "/token" => {
                            tokio::time::sleep(token_delay).await;
                            r#"{"access_token":"AT2","token_type":"Bearer","expires_in":60,"refresh_token":"RT2","scope":"openid"}"#.to_string()
                        }
                        _ => "{}".to_string(),
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        (base, hits)
    }

    const GOOD_DOC: &str = r#"{"issuer":"{base}","authorization_endpoint":"{base}/authorize","token_endpoint":"{base}/token",
        "userinfo_endpoint":"{base}/userinfo","revocation_endpoint":"{base}/revoke","jwks_uri":"{base}/jwks",
        "response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["ES256"]}"#;

    fn hits(h: &Arc<Mutex<HashMap<String, usize>>>, path: &str) -> usize {
        h.lock().unwrap().get(path).copied().unwrap_or(0)
    }

    #[tokio::test]
    async fn discovery_checks_run_before_the_jwks_fetch() {
        let wrong_issuer: &str = r#"{"issuer":"https://evil.example","authorization_endpoint":"{base}/authorize","token_endpoint":"{base}/token",
            "userinfo_endpoint":"{base}/userinfo","revocation_endpoint":"{base}/revoke","jwks_uri":"{base}/jwks",
            "response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["ES256"]}"#;
        let plain_http: &str = r#"{"issuer":"{base}","authorization_endpoint":"{base}/authorize","token_endpoint":"http://evil.example/token",
            "userinfo_endpoint":"{base}/userinfo","revocation_endpoint":"{base}/revoke","jwks_uri":"{base}/jwks",
            "response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["ES256"]}"#;
        for doc in [wrong_issuer, plain_http] {
            let doc: &'static str = Box::leak(doc.to_string().into_boxed_str());
            let (base, h) = mock(doc, Duration::ZERO).await;
            let e = NobleId::discover(Config::new(base, "nbcl_x", None, "http://localhost/cb")).await.unwrap_err();
            assert_eq!(e.code(), "invalid_configuration", "{e}");
            assert_eq!(hits(&h, "/jwks"), 0, "the JWKS must not be fetched before the checks pass");
        }
        let (base, h) = mock(GOOD_DOC, Duration::ZERO).await;
        NobleId::discover(Config::new(base, "nbcl_x", None, "http://localhost/cb")).await.unwrap();
        assert_eq!(hits(&h, "/jwks"), 1);
    }

    #[tokio::test]
    async fn a_cancelled_refresh_is_not_sent_again() {
        let (base, h) = mock(GOOD_DOC, Duration::from_millis(300)).await;
        let n = Arc::new(NobleId::discover(Config::new(base, "nbcl_x", None, "http://localhost/cb")).await.unwrap());
        let rt = RefreshToken::new("RT1".into());
        // The first caller gives up (is dropped) while the request is in flight.
        let cancelled = tokio::time::timeout(Duration::from_millis(50), n.refresh(&rt, None)).await;
        assert!(cancelled.is_err());
        // A second caller with the same token joins the request still in flight.
        let r = n.refresh(&rt, Some("someone")).await.unwrap();
        assert_eq!(r.tokens.refresh_token.as_ref().unwrap().secret(), "RT2");
        // Concurrent callers share it too.
        let rt3 = RefreshToken::new("RT3".into());
        let (a, b) = tokio::join!(n.refresh(&rt3, None), n.refresh(&rt3, None));
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(hits(&h, "/token"), 2, "one request per refresh token");
        assert!(n.refreshing.lock().unwrap().is_empty(), "finished requests are not kept");
    }

    #[test]
    fn debug_never_prints_secrets() {
        let t = TokenSet {
            access_token: AccessToken::new("AT-SECRET".into()),
            refresh_token: Some(RefreshToken::new("RT-SECRET".into())),
            id_token: Some("ID-SECRET".into()),
            expires_at: None,
            scopes: vec![],
        };
        let s = format!("{t:?} {:?}", tx(0));
        assert!(!s.contains("SECRET") && !s.contains("s-123"), "{s}");
        let c = Config::new(ISS, "nbcl_x", Some("CS-SECRET".into()), "http://localhost/cb");
        assert!(!format!("{c:?}").contains("CS-SECRET"));
    }

    // ── profile_from_claims ──────────────────────────────────────────────

    /// Parse a userinfo body the way [`NobleId::userinfo`] does.
    fn userinfo_from(v: &serde_json::Value) -> NobleIdUserInfo {
        NobleIdUserInfo::from_json::<std::io::Error>(&serde_json::to_vec(v).unwrap(), None).unwrap()
    }

    /// The shared cases in test/profile-vectors.json (the kit's root),
    /// which every helper's tests also read.
    #[test]
    fn profile_from_json_shared_cases() {
        let v: serde_json::Value = serde_json::from_str(include_str!("../../../test/profile-vectors.json")).unwrap();
        for c in v["cases"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let got = profile_from_json(&c["id_token"], c.get("userinfo"));
            match c.get("error").and_then(|e| e.as_str()) {
                Some(code) => assert_eq!(got.unwrap_err().code(), code, "{name}"),
                None => {
                    let want: Profile = serde_json::from_value(c["profile"].clone()).unwrap();
                    assert_eq!(got.unwrap(), want, "{name}");
                }
            }
        }
    }

    #[test]
    fn profile_from_typed_claims_matches_the_json_form() {
        let id = serde_json::json!({
            "iss": ISS, "aud": "nbcl_x", "exp": 4102444800u64, "iat": 1761523200u64,
            "sub": "u-1", "name": "Ada Lovelace", "picture": "https://cdn.example.org/a.png",
            "email": "ada@uni.example.edu", "email_verified": true,
            "orcid": "https://orcid.org/0000-0002-1825-0097", "orcid_verified": true,
            "affiliation": { "name": "University of Copenhagen", "ror": "https://ror.org/035b05819" }
        });
        let ui = serde_json::json!({
            "sub": "u-1", "research_interests": ["Bibliometrics"],
            "affiliations": [{ "organization": "University of Copenhagen", "role": "Associate Professor", "start_year": "2019" }]
        });
        let typed_id: NobleIdIdTokenClaims = serde_json::from_value(id.clone()).unwrap();
        let typed_ui = userinfo_from(&ui);
        let p = profile_from_claims(&typed_id, Some(&typed_ui)).unwrap();
        assert_eq!(p, profile_from_json(&id, Some(&ui)).unwrap());
        assert_eq!(p.orcid.as_deref(), Some("https://orcid.org/0000-0002-1825-0097"));
        assert_eq!(p.affiliations[0].start_year, Some(2019));
        assert_eq!(p.affiliation.unwrap().ror.as_deref(), Some("https://ror.org/035b05819"));
        let other = userinfo_from(&serde_json::json!({ "sub": "u-2" }));
        assert_eq!(profile_from_claims(&typed_id, Some(&other)).unwrap_err().code(), "invalid_token");
    }

    /// A string start_year (servers before 27 Oct 2026) used to fail the
    /// whole userinfo call.
    #[test]
    fn userinfo_with_a_string_or_odd_start_year_still_parses() {
        let ui = userinfo_from(&serde_json::json!({
            "sub": "u", "affiliations": [
                { "organization": "A", "role": null, "start_year": "2019" },
                { "organization": "B", "start_year": "c. 2019" },
                { "organization": "C", "start_year": 2021, "ror": "https://ror.org/035b05819" }
            ]
        }));
        let list = ui.additional_claims().affiliations.clone().unwrap();
        assert_eq!(list.iter().map(|a| a.start_year).collect::<Vec<_>>(), vec![Some(2019), None, Some(2021)]);
        assert_eq!(list[2].ror.as_deref(), Some("https://ror.org/035b05819"));
    }
}
