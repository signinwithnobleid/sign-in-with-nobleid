//! Minimal "Sign in with NobleID" web app: axum + nobleid-signin (which wraps
//! the openidconnect crate). Confidential client: the secret and the tokens stay
//! on this server; the browser only gets an opaque session cookie.
//!
//!   ISSUER=https://id.nobleid.org CLIENT_ID=... CLIENT_SECRET=... \
//!   REDIRECT_URI=http://localhost:3000/callback cargo run --release

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Form, RawQuery, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, LOCATION, ORIGIN, REFERRER_POLICY, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use nobleid_signin::{Config, Error as NobleIdError, NobleId, TokenSet, TokenTypeHint, Transaction};
use serde_json::{Map, Value};

const DEFAULT_SCOPE: &str = "openid profile email orcid affiliations works offline_access";
/// A session unused for this long is dropped (as in the Go example).
const SESSION_IDLE: Duration = Duration::from_secs(8 * 60 * 60);

/* ── a tiny in-memory session store (use a real one in production) ── */

struct Session {
    csrf: String,
    transaction: Option<Transaction>,
    user: Option<Map<String, Value>>,
    sub: Option<String>,
    tokens: Option<TokenSet>,
    last_seen: Instant,
}

impl Default for Session {
    fn default() -> Self {
        Session { csrf: String::new(), transaction: None, user: None, sub: None, tokens: None, last_seen: Instant::now() }
    }
}

impl Session {
    fn expired(&self) -> bool {
        self.last_seen.elapsed() > SESSION_IDLE
    }
}

struct App {
    nobleid: NobleId,
    scopes: Vec<String>,
    app_origin: String,
    secure_cookie: bool,
    sessions: Mutex<HashMap<String, Session>>,
}

type Shared = Arc<App>;

fn random_id() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS random number generator");
    URL_SAFE_NO_PAD.encode(b)
}

impl App {
    /// Over https the __Host- prefix pins the cookie to this exact origin.
    fn cookie_name(&self) -> &'static str {
        if self.secure_cookie { "__Host-sid" } else { "sid" }
    }
    fn cookie(&self, sid: &str) -> String {
        format!("{}={sid}; Path=/; HttpOnly; SameSite=Lax{}", self.cookie_name(), if self.secure_cookie { "; Secure" } else { "" })
    }
    fn clear_cookie(&self) -> String {
        format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}", self.cookie_name(), if self.secure_cookie { "; Secure" } else { "" })
    }

    /// Find the session for this request, or start one. Returns (sid, Set-Cookie if new).
    fn session_id(&self, headers: &HeaderMap) -> (String, Option<String>) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(sid) = cookie_sid(headers, self.cookie_name()) {
            match sessions.get_mut(&sid) {
                Some(s) if !s.expired() => {
                    s.last_seen = Instant::now();
                    return (sid, None);
                }
                Some(_) => {
                    sessions.remove(&sid); // idle too long: start over, signed out
                }
                None => {}
            }
        }
        let sid = random_id();
        sessions.insert(sid.clone(), Session { csrf: random_id(), ..Default::default() });
        let set = self.cookie(&sid);
        (sid, Some(set))
    }

    /// Drop every session that has been idle for longer than SESSION_IDLE.
    fn prune(&self) {
        self.sessions.lock().unwrap().retain(|_, s| !s.expired());
    }

    fn with<R>(&self, sid: &str, f: impl FnOnce(&mut Session) -> R) -> R {
        let mut sessions = self.sessions.lock().unwrap();
        let s = sessions.entry(sid.to_string()).or_insert_with(|| Session { csrf: random_id(), ..Default::default() });
        f(s)
    }
}

fn cookie_sid(headers: &HeaderMap, name: &str) -> Option<String> {
    for v in headers.get_all(COOKIE) {
        let Ok(v) = v.to_str() else { continue };
        for part in v.split(';') {
            if let Some(val) = part.trim().strip_prefix(name).and_then(|p| p.strip_prefix('=')) {
                if val.len() == 43 && val.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/* ── html ── */

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

fn page(status: StatusCode, body: &str, set_cookie: Option<String>) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>NobleID example</title></head><body style=\"font-family:system-ui;max-width:48rem;margin:2rem auto;padding:0 1rem\">{body}</body></html>"
    );
    let mut res = (status, html).into_response();
    let h = res.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; img-src https:; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"));
    h.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    if let Some(c) = set_cookie {
        h.append(SET_COOKIE, HeaderValue::from_str(&c).unwrap());
    }
    res
}

fn redirect(location: &str, cookies: &[String]) -> Response {
    let mut res = StatusCode::SEE_OTHER.into_response();
    let h = res.headers_mut();
    h.insert(LOCATION, HeaderValue::from_str(location).unwrap());
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for c in cookies {
        h.append(SET_COOKIE, HeaderValue::from_str(c).unwrap());
    }
    res
}

fn form(action: &str, label: &str, csrf: &str) -> String {
    format!("<form method=\"post\" action=\"{action}\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button>{label}</button></form>", esc(csrf))
}

fn error_page(e: &NobleIdError, set_cookie: Option<String>) -> Response {
    let d = e.description();
    let d = if d.is_empty() { String::new() } else { format!(": {}", esc(&d)) };
    page(
        StatusCode::BAD_REQUEST,
        &format!("<h1>Sign-in failed</h1><p id=\"error\">{}{d}</p><p><a href=\"/\">Back</a></p>", esc(e.code())),
        set_cookie,
    )
}

fn server_error(what: &str) -> Response {
    eprintln!("request failed: {what}"); // never log tokens or codes
    page(StatusCode::INTERNAL_SERVER_ERROR, "<p id=\"error\">server_error</p>", None)
}

/* ── routes ── */

async fn home(State(app): State<Shared>, headers: HeaderMap) -> Response {
    let (sid, set) = app.session_id(&headers);
    let view = app.with(&sid, |s| match (&s.user, &s.tokens) {
        (Some(user), Some(tokens)) => {
            let mut shown = user.clone();
            shown.insert("granted_scope".into(), Value::String(tokens.scopes.join(" ")));
            let name = user
                .get("name")
                .or_else(|| user.get("nobleid"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            Some((name, serde_json::to_string_pretty(&shown).unwrap_or_default(), tokens.refresh_token.is_some(), s.csrf.clone()))
        }
        _ => None,
    });
    match view {
        None => page(
            StatusCode::OK,
            "<h1>NobleID example (Rust)</h1><p id=\"signed-out\">You are signed out.</p><p><a href=\"/login\">Sign in with NobleID</a></p>",
            set,
        ),
        Some((name, json, can_refresh, csrf)) => page(
            StatusCode::OK,
            &format!(
                "<h1>Signed in</h1><p>Hello, {}.</p><pre id=\"claims\">{}</pre><p><a href=\"/works\">My works</a> {} {}</p>",
                esc(&name),
                esc(&json),
                if can_refresh { form("/refresh", "Refresh tokens", &csrf) } else { String::new() },
                form("/logout", "Sign out", &csrf)
            ),
            set,
        ),
    }
}

async fn login(State(app): State<Shared>, headers: HeaderMap) -> Response {
    let (sid, set) = app.session_id(&headers);
    let scopes: Vec<&str> = app.scopes.iter().map(String::as_str).collect();
    let (url, transaction) = app.nobleid.start_sign_in(&scopes);
    app.with(&sid, |s| s.transaction = Some(transaction));
    redirect(url.as_str(), &set.into_iter().collect::<Vec<_>>())
}

async fn callback(State(app): State<Shared>, headers: HeaderMap, RawQuery(query): RawQuery) -> Response {
    let (sid, set) = app.session_id(&headers);
    // Single use, whatever happens next.
    let transaction = app.with(&sid, |s| s.transaction.take());
    let signin = match app.nobleid.finish_sign_in(query.as_deref().unwrap_or(""), transaction).await {
        Ok(s) => s,
        Err(e) => return error_page(&e, set),
    };
    let sub = signin.claims.subject().to_string();
    let info = match app.nobleid.userinfo(&signin.tokens.access_token, Some(&sub)).await {
        Ok(i) => i,
        Err(e) => return error_page(&e, set),
    };
    // ID-token claims merged with the userinfo response. Key accounts on `sub`;
    // only trust `email` for linking when `email_verified` is true.
    let mut user = match serde_json::to_value(&signin.claims) {
        Ok(Value::Object(m)) => m,
        _ => return server_error("could not read claims"),
    };
    if let Ok(Value::Object(m)) = serde_json::to_value(&info) {
        user.extend(m);
    }

    // A new session id after sign-in; the old session is dropped.
    let new_sid = random_id();
    {
        let mut sessions = app.sessions.lock().unwrap();
        sessions.remove(&sid);
        sessions.insert(
            new_sid.clone(),
            Session { csrf: random_id(), user: Some(user), sub: Some(sub), tokens: Some(signin.tokens), ..Default::default() },
        );
    }
    redirect("/", &[app.cookie(&new_sid)])
}

async fn works(State(app): State<Shared>, headers: HeaderMap) -> Response {
    let (sid, set) = app.session_id(&headers);
    let Some(tokens) = app.with(&sid, |s| s.tokens.clone()) else {
        return redirect("/", &set.into_iter().collect::<Vec<_>>());
    };
    if !tokens.has_scope("works") {
        return page(StatusCode::OK, "<p>The works scope was not granted.</p><p><a href=\"/\">Back</a></p>", set);
    }
    match app.nobleid.works(&tokens.access_token, 50, 0).await {
        Ok(w) => page(
            StatusCode::OK,
            &format!("<h1>Works</h1><pre id=\"works\">{}</pre><p><a href=\"/\">Back</a></p>", esc(&serde_json::to_string_pretty(&w).unwrap_or_default())),
            set,
        ),
        Err(e) => error_page(&e, set),
    }
}

/// CSRF: the hidden token must match the session's, and a cross-site Origin is refused.
fn csrf_ok(app: &App, sid: &str, headers: &HeaderMap, f: &HashMap<String, String>) -> bool {
    if let Some(o) = headers.get(ORIGIN) {
        if o.to_str().ok() != Some(app.app_origin.as_str()) {
            return false;
        }
    }
    let expected = app.with(sid, |s| s.csrf.clone());
    match f.get("csrf") {
        Some(given) => !expected.is_empty() && given.len() == expected.len() && given.bytes().zip(expected.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0,
        None => false,
    }
}

async fn refresh(State(app): State<Shared>, headers: HeaderMap, Form(f): Form<HashMap<String, String>>) -> Response {
    let (sid, set) = app.session_id(&headers);
    if !csrf_ok(&app, &sid, &headers, &f) {
        return page(StatusCode::FORBIDDEN, "<p id=\"error\">forbidden</p>", set);
    }
    let (tokens, sub) = app.with(&sid, |s| (s.tokens.clone(), s.sub.clone()));
    let Some(rt) = tokens.as_ref().and_then(|t| t.refresh_token.clone()) else {
        return redirect("/", &set.into_iter().collect::<Vec<_>>());
    };
    // The library shares one request between concurrent refreshes of the same
    // token in this process. With several processes, lock per session here.
    match app.nobleid.refresh(&rt, sub.as_deref()).await {
        Ok(r) => {
            app.with(&sid, |s| {
                if let Some(old) = &s.tokens {
                    // Only replace the tokens we refreshed (store the rotated refresh token).
                    if old.refresh_token.as_ref().map(|t| t.secret()) == Some(rt.secret()) {
                        let mut t = r.tokens;
                        if t.scopes.is_empty() {
                            t.scopes = old.scopes.clone();
                        }
                        s.tokens = Some(t);
                    }
                }
            });
            redirect("/", &set.into_iter().collect::<Vec<_>>())
        }
        Err(e) => {
            // invalid_grant: the user removed the app, or the session ended. Any
            // other failure (a rejected ID token, a different sub) may come after
            // the provider already rotated the refresh token, so the one we hold
            // could be spent. Either way, sign out locally.
            app.sessions.lock().unwrap().remove(&sid);
            if e.code() == "invalid_grant" {
                redirect("/", &[app.clear_cookie()])
            } else {
                error_page(&e, Some(app.clear_cookie()))
            }
        }
    }
}

async fn logout(State(app): State<Shared>, headers: HeaderMap, Form(f): Form<HashMap<String, String>>) -> Response {
    let (sid, set) = app.session_id(&headers);
    if !csrf_ok(&app, &sid, &headers, &f) {
        return page(StatusCode::FORBIDDEN, "<p id=\"error\">forbidden</p>", set);
    }
    // NobleID has no end-session endpoint: revoke the tokens, then clear our session.
    let tokens = app.sessions.lock().unwrap().remove(&sid).and_then(|s| s.tokens);
    if let Some(t) = tokens {
        if let Some(rt) = &t.refresh_token {
            if let Err(e) = app.nobleid.revoke(rt.secret(), TokenTypeHint::RefreshToken).await {
                eprintln!("revoke refresh token: {}", e.code());
            }
        }
        if let Err(e) = app.nobleid.revoke(t.access_token.secret(), TokenTypeHint::AccessToken).await {
            eprintln!("revoke access token: {}", e.code());
        }
    }
    redirect("/", &[app.clear_cookie()])
}

async fn not_found() -> Response {
    page(StatusCode::NOT_FOUND, "<p>Not found</p>", None)
}

#[tokio::main]
async fn main() {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let issuer = env("ISSUER").unwrap_or_else(|| nobleid_signin::NOBLEID_ISSUER.to_string());
    let (Some(client_id), Some(client_secret)) = (env("CLIENT_ID"), env("CLIENT_SECRET")) else {
        eprintln!("Set CLIENT_ID and CLIENT_SECRET (see .env.example).");
        std::process::exit(1);
    };
    let redirect_uri = env("REDIRECT_URI").unwrap_or_else(|| "http://localhost:3000/callback".into());
    let port: u16 = env("PORT").and_then(|p| p.parse().ok()).unwrap_or(3000);
    let scope = env("SCOPE").unwrap_or_else(|| DEFAULT_SCOPE.into());

    let redirect_url = url::Url::parse(&redirect_uri).expect("REDIRECT_URI must be a URL");
    let app_origin = redirect_url.origin().ascii_serialization();
    let callback_path = redirect_url.path().to_string();

    let nobleid = match NobleId::discover(Config::new(issuer, client_id, Some(client_secret), redirect_uri)).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("discovery failed: {e}");
            std::process::exit(1);
        }
    };

    let app = Arc::new(App {
        nobleid,
        scopes: scope.split_whitespace().map(String::from).collect(),
        secure_cookie: app_origin.starts_with("https:"),
        app_origin: app_origin.clone(),
        sessions: Mutex::new(HashMap::new()),
    });

    // Sweep idle sessions so the in-memory store does not grow without bound.
    let sweeper = app.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10 * 60));
        loop {
            tick.tick().await;
            sweeper.prune();
        }
    });

    let router = Router::new()
        .route("/", get(home))
        .route("/login", get(login))
        .route(&callback_path, get(callback))
        .route("/works", get(works))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .fallback(not_found)
        .with_state(app);

    // Loopback only (IPv4 and, where available, IPv6), so "localhost" works either way.
    let mut tasks = Vec::new();
    for addr in [SocketAddr::from(([127, 0, 0, 1], port)), SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port))] {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                let r = router.clone();
                tasks.push(tokio::spawn(async move { axum::serve(l, r).await }));
            }
            Err(e) if addr.is_ipv6() => eprintln!("not listening on {addr}: {e}"),
            Err(e) => {
                eprintln!("cannot listen on {addr}: {e}");
                std::process::exit(1);
            }
        }
    }
    println!("example listening on {app_origin} (port {port})");
    for t in tasks {
        let _ = t.await;
    }
}
