// Minimal "Sign in with NobleID" web app: ASP.NET Core minimal APIs, cookie
// authentication and Microsoft.AspNetCore.Authentication.OpenIdConnect.
// Confidential client: the secret and the tokens stay on the server (in an
// in-memory ticket store); the browser only holds an encrypted, HttpOnly
// cookie carrying the key of its server-side session.
//
//   ISSUER=https://id.nobleid.org CLIENT_ID=... CLIENT_SECRET=... \
//   REDIRECT_URI=http://localhost:3000/signin-oidc dotnet run

using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Unicode;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

const string Oidc = "nobleid";
const string Cookie = CookieAuthenticationDefaults.AuthenticationScheme;

var issuer = Env("ISSUER") ?? "https://id.nobleid.org";
var clientId = Env("CLIENT_ID");
var clientSecret = Env("CLIENT_SECRET");
var redirectUriText = Env("REDIRECT_URI") ?? "http://localhost:3000/signin-oidc"; // sent exactly as registered
var redirectUri = new Uri(redirectUriText);
var port = int.Parse(Env("PORT") ?? "3000", CultureInfo.InvariantCulture);
var scopes = (Env("SCOPE") ?? "openid profile email orcid affiliations works offline_access")
    .Split(' ', StringSplitOptions.RemoveEmptyEntries);

if (clientId is null || clientSecret is null)
{
    Console.Error.WriteLine("Set CLIENT_ID and CLIENT_SECRET (see .env.example).");
    return 1;
}

var issuerUri = new Uri(issuer);
// http is accepted only for a local mock provider.
var localHttp = issuerUri.Scheme == "http" && (issuerUri.Host is "localhost" or "127.0.0.1" or "[::1]");
if (issuerUri.Scheme != "https" && !localHttp)
{
    Console.Error.WriteLine("ISSUER must be https (http is allowed only for a localhost mock).");
    return 1;
}
// redirect_uri, the CSRF origin and the cookie Secure flag come from REDIRECT_URI, never
// from the request's Host or scheme (which a client or a proxy can change). Cookies are
// Secure unless the app is explicitly served on http://localhost.
var localApp = redirectUri.Scheme == "http" && (redirectUri.Host is "localhost" or "127.0.0.1" or "[::1]");
if (redirectUri.Scheme != "https" && !localApp)
{
    Console.Error.WriteLine("REDIRECT_URI must be https (http is allowed only for localhost).");
    return 1;
}
var cookieSecure = localApp ? CookieSecurePolicy.None : CookieSecurePolicy.Always;
var appOrigin = redirectUri.GetLeftPart(UriPartial.Authority);
// Over https the __Host- prefix pins a cookie to this exact origin (Secure, Path=/, no Domain).
var cookiePrefix = localApp ? "" : "__Host-";

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://localhost:{port}");
builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);

var dp = builder.Services.AddDataProtection().SetApplicationName("nobleid-example");
// In production also encrypt the keys at rest: ProtectKeysWithCertificate, ProtectKeysWithAzureKeyVault,
// ProtectKeysWithDpapi and so on. Whoever can read unprotected keys can forge an auth cookie.
if (Env("DATA_PROTECTION_KEYS_DIR") is { } keysDir) dp.PersistKeysToFileSystem(new DirectoryInfo(keysDir));

builder.Services.AddHttpClient(Oidc, c => c.Timeout = TimeSpan.FromSeconds(15));
builder.Services.AddAntiforgery(o =>
{
    o.Cookie.Name = cookiePrefix + "nobleid_example_csrf";
    o.Cookie.SecurePolicy = cookieSecure;
});

builder.Services
    .AddAuthentication(o =>
    {
        o.DefaultScheme = Cookie;
        o.DefaultChallengeScheme = Oidc;
    })
    .AddCookie(Cookie, o =>
    {
        o.Cookie.Name = cookiePrefix + "nobleid_example";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.Cookie.SecurePolicy = cookieSecure;
        o.ExpireTimeSpan = TimeSpan.FromHours(8);
        o.SlidingExpiration = false;
        // Keep the ticket (claims and tokens) on the server; the cookie carries only its key,
        // and sign-out deletes the ticket. In-memory: a restart signs everyone out, and several
        // instances need a shared ITicketStore (for example one backed by IDistributedCache).
        o.SessionStore = new MemoryTicketStore();
    })
    .AddOpenIdConnect(Oidc, o =>
    {
        o.Authority = issuer;
        o.MetadataAddress = issuer + "/.well-known/openid-configuration";
        o.RequireHttpsMetadata = !localHttp;
        o.ClientId = clientId;
        o.ClientSecret = clientSecret; // the handler sends it as client_secret_post when redeeming the code
        o.CallbackPath = redirectUri.AbsolutePath;

        o.ResponseType = OpenIdConnectResponseType.Code;
        o.ResponseMode = OpenIdConnectResponseMode.Query; // the default, form_post, is not supported
        o.UsePkce = true; // S256
        o.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable; // plain authorize redirect
        o.DisableTelemetry = true;
        o.Scope.Clear();
        foreach (var s in scopes) o.Scope.Add(s);

        o.SaveTokens = true;
        o.GetClaimsFromUserInfoEndpoint = true;
        o.MapInboundClaims = false; // keep `sub`, `email`, ... as sent
        o.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256]; // ES256 only
        o.TokenValidationParameters.ValidIssuer = issuer;
        o.TokenValidationParameters.NameClaimType = "name";

        // State, nonce and correlation cookies: Lax so they come back on the top-level
        // redirect from NobleID, Secure unless the app runs on http://localhost.
        o.CorrelationCookie.SameSite = SameSiteMode.Lax;
        o.CorrelationCookie.SecurePolicy = cookieSecure;
        o.NonceCookie.SameSite = SameSiteMode.Lax;
        o.NonceCookie.SecurePolicy = cookieSecure;

        o.Events = new OpenIdConnectEvents
        {
            // The handler would build redirect_uri from the request's scheme and Host; send the
            // configured one instead (it is also what the code redemption below uses).
            OnRedirectToIdentityProvider = ctx =>
            {
                ctx.ProtocolMessage.RedirectUri = redirectUriText;
                return Task.CompletedTask;
            },

            OnAuthorizationCodeReceived = ctx =>
            {
                if (ctx.TokenEndpointRequest is { } req) req.RedirectUri = redirectUriText;
                return Task.CompletedTask;
            },

            // Runs before the handler looks at `error` or `code`. Order: a sign-in started
            // by this browser (state + correlation cookie), then RFC 9207 `iss`.
            OnMessageReceived = ctx =>
            {
                // The handler has already decrypted `state` into ctx.Properties (null when it was
                // not issued by this app). The correlation cookie ("N" is the handler's marker)
                // binds it to this browser; the handler re-checks it after this event as well.
                var props = ctx.Properties;
                if (props is null
                    || !props.Items.TryGetValue(".xsrf", out var correlationId)
                    || correlationId is null
                    || ctx.Request.Cookies[ctx.Options.CorrelationCookie.Name + correlationId] != "N")
                {
                    ctx.Fail(new SignInError("invalid_state", "No matching sign-in is in progress in this browser."));
                    return Task.CompletedTask;
                }
                var iss = ctx.Request.Query["iss"];
                if (iss.Count != 1 || !string.Equals(iss[0], issuer, StringComparison.Ordinal))
                {
                    ctx.Fail(new SignInError("invalid_issuer", "The response did not come from the expected issuer."));
                }
                return Task.CompletedTask;
            },

            OnTokenValidated = ctx =>
            {
                // The ID token is verified at this point; keep its claims and the granted scope.
                var idToken = ctx.TokenEndpointResponse?.IdToken;
                if (idToken is not null)
                    ctx.Properties!.Items["id_claims"] = Base64UrlEncoder.Decode(new JsonWebToken(idToken).EncodedPayload);
                // The user may untick scopes: read what was granted, not what was asked for.
                ctx.Properties!.Items["scope"] = ctx.TokenEndpointResponse?.Scope ?? "";
                return Task.CompletedTask;
            },

            OnUserInformationReceived = ctx =>
            {
                // Keep the raw userinfo JSON (arrays and userinfo-only claims included).
                ctx.Properties!.Items["userinfo"] = ctx.User.RootElement.GetRawText();
                return Task.CompletedTask;
            },

            OnRemoteFailure = async ctx =>
            {
                var f = ctx.Failure;
                var code = f switch
                {
                    SignInError e => e.Code,
                    { } ex when ex.Data["error"] is string s && s.Length > 0 => s,
                    OpenIdConnectProtocolInvalidNonceException => "invalid_nonce",
                    SecurityTokenInvalidAudienceException => "invalid_audience",
                    SecurityTokenException or OpenIdConnectProtocolException => "invalid_id_token",
                    { Message: var m } when m.Contains("Correlation", StringComparison.Ordinal) => "invalid_state",
                    _ => "sign_in_failed",
                };
                var description = f is SignInError se ? se.Message : f?.Data["error_description"] as string;
                ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("NobleID").LogWarning("sign-in failed: {Code} ({Type})", code, f?.GetType().Name);
                ctx.HandleResponse(); // nothing was signed in
                await WriteHtml(ctx.Response, 400,
                    $"<h1>Sign-in failed</h1><p id=\"error\">{H(code)}{(string.IsNullOrEmpty(description) ? "" : ": " + H(description))}</p><p><a href=\"/\">Back</a></p>");
            },
        };
    });

var app = builder.Build();
app.UseAuthentication();

/* ── routes ── */

app.MapGet("/", async (HttpContext ctx, IAntiforgery af) =>
{
    var auth = await ctx.AuthenticateAsync(Cookie);
    if (!auth.Succeeded)
        return Html(200, "<h1>NobleID example (ASP.NET Core)</h1><p id=\"signed-out\">You are signed out.</p><p><a href=\"/login\">Sign in with NobleID</a></p>");

    var p = auth.Properties!;
    var claims = ParseObject(p.GetString("id_claims"));
    foreach (var (k, v) in ParseObject(p.GetString("userinfo")))
        claims[k] = v?.DeepClone();
    claims["granted_scope"] = p.GetString("scope") ?? "";

    var csrf = af.GetAndStoreTokens(ctx);
    var name = claims["name"]?.ToString() ?? claims["nobleid"]?.ToString() ?? "";
    return Html(200,
        $"<h1>Signed in</h1><p>Hello, {H(name)}.</p>" +
        $"<pre id=\"claims\">{H(claims.ToJsonString(Json))}</pre>" +
        "<p><a href=\"/works\">My works</a> " +
        (p.GetTokenValue("refresh_token") is null ? "" : Form("/refresh", "Refresh tokens", csrf)) + " " +
        Form("/logout", "Sign out", csrf) + "</p>");
});

app.MapGet("/login", () =>
    Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, [Oidc]));

app.MapGet("/works", async (HttpContext ctx, IHttpClientFactory http) =>
{
    var auth = await ctx.AuthenticateAsync(Cookie);
    if (!auth.Succeeded) return Results.Redirect("/");
    var granted = (auth.Properties!.GetString("scope") ?? "").Split(' ');
    if (!granted.Contains("works")) return Html(200, "<p>The works scope was not granted.</p><p><a href=\"/\">Back</a></p>");

    using var req = new HttpRequestMessage(HttpMethod.Get, issuer + "/oauth/works?limit=50&offset=0");
    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth.Properties.GetTokenValue("access_token"));
    using var res = await http.CreateClient(Oidc).SendAsync(req);
    var body = await res.Content.ReadAsStringAsync();
    if (!res.IsSuccessStatusCode)
        // 401 invalid_token: the access token expired (use Refresh); 429 slow_down: back off.
        return Html((int)res.StatusCode, $"<p id=\"error\">{H(ErrorCode(body, res))}</p><p><a href=\"/\">Back</a></p>");
    var works = JsonNode.Parse(body);
    return Html(200, $"<h1>Works</h1><pre id=\"works\">{H(works?.ToJsonString(Json) ?? "null")}</pre><p><a href=\"/\">Back</a></p>");
});

app.MapPost("/refresh", async (HttpContext ctx, IAntiforgery af, IHttpClientFactory http, IOptionsMonitor<OpenIdConnectOptions> oidc) =>
{
    if (!await ValidPost(ctx, af)) return Html(403, "<p id=\"error\">forbidden</p>");
    var auth = await ctx.AuthenticateAsync(Cookie);
    var refreshToken = auth.Properties?.GetTokenValue("refresh_token");
    if (!auth.Succeeded || refreshToken is null) return Results.Redirect("/");

    var config = await Config(oidc);
    var result = await Refresher.Refresh(refreshToken, () => TokenRequest(http, config.TokenEndpoint,
        new() { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken }));

    if (result.Error == "invalid_grant")
    {
        // The user removed the app or the session ended: sign out locally.
        await ctx.SignOutAsync(Cookie);
        return Results.Redirect("/");
    }
    // From here on, a failure may come after NobleID already rotated the refresh token,
    // so the one we hold could be spent: sign out locally before showing the error.
    if (result.Error is not null || result.Json is null)
    {
        await ctx.SignOutAsync(Cookie);
        return Html(result.Status >= 400 ? result.Status : 502, $"<p id=\"error\">{H(result.Error ?? "server_error")}</p><p><a href=\"/\">Back</a></p>");
    }

    var t = result.Json;
    var props = auth.Properties!;
    // A refresh-issued ID token has no nonce or auth_time; verify it and that `sub` is unchanged.
    if (t["id_token"]?.GetValue<string>() is { } newIdToken)
    {
        var sub = auth.Principal!.FindFirstValue("sub");
        if (!await IdTokenValid(newIdToken, sub, oidc))
        {
            await ctx.SignOutAsync(Cookie);
            return Html(502, "<p id=\"error\">invalid_id_token</p>");
        }
        SetToken(props, "id_token", newIdToken);
    }
    SetToken(props, "access_token", t["access_token"]!.GetValue<string>());
    // Refresh tokens rotate: store the new one; the old one is now spent.
    if (t["refresh_token"]?.GetValue<string>() is { } rotated) SetToken(props, "refresh_token", rotated);
    if (t["expires_in"]?.GetValue<int>() is { } expiresIn)
        SetToken(props, "expires_at", DateTimeOffset.UtcNow.AddSeconds(expiresIn).ToString("o", CultureInfo.InvariantCulture));
    if (t["scope"]?.GetValue<string>() is { } scope) props.Items["scope"] = scope;

    props.IssuedUtc = null;
    props.ExpiresUtc = null;
    await ctx.SignInAsync(Cookie, auth.Principal!, props); // re-issue the cookie with the new tokens
    return Results.Redirect("/");
});

app.MapPost("/logout", async (HttpContext ctx, IAntiforgery af, IHttpClientFactory http, IOptionsMonitor<OpenIdConnectOptions> oidc) =>
{
    if (!await ValidPost(ctx, af)) return Html(403, "<p id=\"error\">forbidden</p>");
    var auth = await ctx.AuthenticateAsync(Cookie);
    if (auth.Succeeded)
    {
        // NobleID has no end-session endpoint: revoke the tokens, then clear our cookie.
        var config = await Config(oidc);
        if (config.RevocationEndpoint is { Length: > 0 } revocation)
        {
            foreach (var (name, hint) in new[] { ("refresh_token", "refresh_token"), ("access_token", "access_token") })
                if (auth.Properties!.GetTokenValue(name) is { } token)
                    await TokenRequest(http, revocation, new() { ["token"] = token, ["token_type_hint"] = hint });
        }
    }
    await ctx.SignOutAsync(Cookie); // local only: no OIDC sign-out
    return Results.Redirect("/");
});

app.Run();
return 0;

/* ── helpers ── */

static string? Env(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } v ? v : null;

static string H(string s) => Html5.Encode(s);

static JsonObject ParseObject(string? json) =>
    json is null ? new JsonObject() : JsonNode.Parse(json) as JsonObject ?? new JsonObject();

static IResult Html(int status, string body) => new HtmlResult(status, body);

static async Task WriteHtml(HttpResponse res, int status, string body)
{
    res.StatusCode = status;
    HtmlResult.SetHeaders(res);
    await res.WriteAsync(HtmlResult.Page(body));
}

static string Form(string action, string label, AntiforgeryTokenSet csrf) =>
    $"<form method=\"post\" action=\"{action}\" style=\"display:inline\">" +
    $"<input type=\"hidden\" name=\"{H(csrf.FormFieldName)}\" value=\"{H(csrf.RequestToken ?? "")}\">" +
    $"<button>{H(label)}</button></form>";

// CSRF: same-origin Origin header (when sent) and the antiforgery token.
async Task<bool> ValidPost(HttpContext ctx, IAntiforgery af)
{
    var origin = ctx.Request.Headers.Origin.ToString();
    if (origin.Length > 0 && !string.Equals(origin, appOrigin, StringComparison.Ordinal)) return false;
    return await af.IsRequestValidAsync(ctx);
}

static async Task<OpenIdConnectConfiguration> Config(IOptionsMonitor<OpenIdConnectOptions> oidc) =>
    await oidc.Get(Oidc).ConfigurationManager!.GetConfigurationAsync(CancellationToken.None);

// Token and revocation requests: client_secret_basic, with the id and secret
// form-urlencoded before base64 (RFC 6749 section 2.3.1). Body is form-urlencoded.
async Task<TokenResult> TokenRequest(IHttpClientFactory http, string endpoint, Dictionary<string, string> form)
{
    using var req = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new FormUrlEncodedContent(form) };
    var basic = WebUtility.UrlEncode(clientId) + ":" + WebUtility.UrlEncode(clientSecret);
    req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(basic)));
    req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    try
    {
        using var res = await http.CreateClient(Oidc).SendAsync(req);
        var body = await res.Content.ReadAsStringAsync();
        if (!res.IsSuccessStatusCode) return new TokenResult((int)res.StatusCode, null, ErrorCode(body, res));
        return new TokenResult((int)res.StatusCode, body.Length == 0 ? null : JsonNode.Parse(body) as JsonObject, null);
    }
    catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
    {
        return new TokenResult(502, null, "server_error");
    }
}

static string ErrorCode(string body, HttpResponseMessage res)
{
    try
    {
        if (JsonNode.Parse(body)?["error"]?.GetValue<string>() is { Length: > 0 } e) return e;
    }
    catch (JsonException) { }
    return "http_" + (int)res.StatusCode;
}

async Task<bool> IdTokenValid(string idToken, string? sub, IOptionsMonitor<OpenIdConnectOptions> oidc)
{
    var options = oidc.Get(Oidc);
    for (var attempt = 0; attempt < 2; attempt++)
    {
        var config = await Config(oidc);
        var r = await new JsonWebTokenHandler().ValidateTokenAsync(idToken, new TokenValidationParameters
        {
            ValidIssuer = issuer,
            ValidAudience = clientId,
            IssuerSigningKeys = config.SigningKeys,
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
        });
        if (r.IsValid) return sub is not null && r.Claims.TryGetValue("sub", out var s) && s as string == sub;
        if (r.Exception is not SecurityTokenSignatureKeyNotFoundException) return false;
        options.ConfigurationManager!.RequestRefresh(); // unknown kid: re-fetch the JWKS once
    }
    return false;
}

static void SetToken(AuthenticationProperties p, string name, string value)
{
    if (p.UpdateTokenValue(name, value)) return;
    var list = p.GetTokens().ToList();
    list.Add(new AuthenticationToken { Name = name, Value = value });
    p.StoreTokens(list);
}

partial class Program
{
    static readonly HtmlEncoder Html5 = HtmlEncoder.Create(UnicodeRanges.All);
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
}

sealed class SignInError(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

record TokenResult(int Status, JsonObject? Json, string? Error);

// Refresh tokens rotate, and presenting a spent one ends the whole session, so
// concurrent refreshes of the same token in this process share one request.
// With several server instances, serialise refreshes per user yourself.
static class Refresher
{
    static readonly ConcurrentDictionary<string, Lazy<Task<TokenResult>>> InFlight = new();

    public static async Task<TokenResult> Refresh(string refreshToken, Func<Task<TokenResult>> send)
    {
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken)));
        var lazy = InFlight.GetOrAdd(key, _ => new Lazy<Task<TokenResult>>(send));
        try { return await lazy.Value; }
        finally { InFlight.TryRemove(new KeyValuePair<string, Lazy<Task<TokenResult>>>(key, lazy)); }
    }
}

// Server-side store for cookie authentication tickets. Each entry expires with its ticket.
sealed class MemoryTicketStore : ITicketStore
{
    readonly MemoryCache _cache = new(new MemoryCacheOptions());

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        Put(key, ticket);
        return Task.FromResult(key);
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        Put(key, ticket);
        return Task.CompletedTask;
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key) =>
        Task.FromResult(_cache.TryGetValue(key, out AuthenticationTicket? ticket) ? ticket : null);

    public Task RemoveAsync(string key)
    {
        _cache.Remove(key);
        return Task.CompletedTask;
    }

    void Put(string key, AuthenticationTicket ticket)
    {
        var entry = new MemoryCacheEntryOptions();
        if (ticket.Properties.ExpiresUtc is { } expires) entry.AbsoluteExpiration = expires;
        else entry.SlidingExpiration = TimeSpan.FromHours(8);
        _cache.Set(key, ticket, entry);
    }
}

sealed class HtmlResult(int status, string body) : IResult
{
    public static string Page(string body) =>
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
        "<title>NobleID example</title></head><body style=\"font-family:system-ui;max-width:48rem;margin:2rem auto;padding:0 1rem\">" +
        body + "</body></html>";

    public static void SetHeaders(HttpResponse res)
    {
        res.ContentType = "text/html; charset=utf-8";
        res.Headers.CacheControl = "no-store";
        // frame-ancestors 'none' and X-Frame-Options: no other site may frame these pages (clickjacking).
        res.Headers.ContentSecurityPolicy = "default-src 'none'; img-src https:; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'";
        res.Headers.XFrameOptions = "DENY";
        res.Headers["Referrer-Policy"] = "no-referrer";
    }

    public Task ExecuteAsync(HttpContext ctx)
    {
        ctx.Response.StatusCode = status;
        SetHeaders(ctx.Response);
        return ctx.Response.WriteAsync(Page(body));
    }
}
