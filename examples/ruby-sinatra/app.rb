# frozen_string_literal: true

# Minimal "Sign in with NobleID" web app: Sinatra + OmniAuth +
# omniauth_openid_connect. Confidential client: the secret and the tokens stay
# on this server; the browser only gets an opaque session id cookie.
#
#   ISSUER=https://id.nobleid.org CLIENT_ID=... CLIENT_SECRET=... \
#   REDIRECT_URI=http://localhost:3000/auth/nobleid/callback \
#   bundle exec puma -b tcp://localhost:3000

require "digest"
require "json"
require "net/http"
require "securerandom"
require "uri"

require "sinatra/base"
require "rack/session"
require "rack/protection"
require "omniauth"
require_relative "nobleid_strategy"

ISSUER = ENV.fetch("ISSUER", "https://id.nobleid.org")
CLIENT_ID = ENV["CLIENT_ID"].to_s
CLIENT_SECRET = ENV["CLIENT_SECRET"].to_s
REDIRECT_URI = ENV.fetch("REDIRECT_URI", "http://localhost:3000/auth/nobleid/callback")
SCOPE = ENV.fetch("SCOPE", "openid profile email orcid affiliations works offline_access").split

abort "Set CLIENT_ID and CLIENT_SECRET (see .env.example)." if CLIENT_ID.empty? || CLIENT_SECRET.empty?

issuer_uri = URI(ISSUER)
LOCAL_HTTP_ISSUER = issuer_uri.scheme == "http" && %w[localhost 127.0.0.1 ::1 [::1]].include?(issuer_uri.host)
abort "ISSUER must be https (http is allowed only for a localhost mock)." unless issuer_uri.scheme == "https" || LOCAL_HTTP_ISSUER
# The discovery helper builds https URLs; allow http only for the local mock provider.
SWD.url_builder = URI::HTTP if LOCAL_HTTP_ISSUER

redirect = URI(REDIRECT_URI)
APP_ORIGIN = "#{redirect.scheme}://#{redirect.host}#{[80, 443].include?(redirect.port) ? '' : ":#{redirect.port}"}"
CALLBACK_PATH = redirect.path
SECURE_COOKIE = redirect.scheme == "https"

# ── OmniAuth ────────────────────────────────────────────────────────────────
# GET /login runs the strategy's request phase (see README: login CSRF).
OmniAuth.config.logger.level = Logger::INFO # failures are logged with their code, never with tokens
OmniAuth.config.allowed_request_methods = [:get]
OmniAuth.config.silence_get_warning = true
OmniAuth.config.request_validation_phase = lambda do |env|
  # Browsers label cross-site navigations; refuse to start a sign-in from another site.
  raise OmniAuth::AuthenticityError, "cross-site sign-in start" if env["HTTP_SEC_FETCH_SITE"] == "cross-site"
end

module Html
  module_function

  def esc(value) = Rack::Utils.escape_html(value.to_s)

  def page(body)
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" \
      "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>NobleID example</title></head>" \
      "<body style=\"font-family:system-ui;max-width:48rem;margin:2rem auto;padding:0 1rem\">#{body}</body></html>"
  end

  HEADERS = {
    "content-type" => "text/html; charset=utf-8",
    "cache-control" => "no-store",
    # frame-ancestors 'none' and X-Frame-Options: no other site may frame these pages (clickjacking).
    "content-security-policy" => "default-src 'none'; img-src https:; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    "x-frame-options" => "DENY",
    "referrer-policy" => "no-referrer"
  }.freeze

  # Only short OAuth-style codes are shown; anything else becomes server_error.
  def error_code(value)
    s = value.to_s
    s.match?(/\A[a-z0-9_.-]{1,64}\z/i) ? s : "server_error"
  end

  def error_body(code, description = nil)
    "<h1>Sign-in failed</h1><p id=\"error\">#{esc(error_code(code))}#{description ? ": #{esc(description)}" : ''}</p>" \
      "<p><a href=\"/\">Back</a></p>"
  end
end

# Any callback failure (state, iss, error=..., ID token, userinfo) ends here.
OmniAuth.config.on_failure = lambda do |env|
  session = env["rack.session"]
  session&.keys&.grep(/\Aomniauth\.|\Anobleid\./)&.each { |k| session.delete(k) } # the flow is single use
  code = env["omniauth.error.type"]
  [400, Html::HEADERS.dup, [Html.page(Html.error_body(code))]]
end

# ── Provider endpoints for refresh and revoke (from discovery) ──────────────
module Provider
  @lock = Mutex.new
  @config = nil

  module_function

  def config
    @lock.synchronize do
      @config ||= OpenIDConnect::Discovery::Provider::Config.discover!(ISSUER)
    end
  end

  def client
    c = config
    OpenIDConnect::Client.new(
      identifier: CLIENT_ID,
      secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      authorization_endpoint: c.authorization_endpoint,
      token_endpoint: c.token_endpoint,
      userinfo_endpoint: c.userinfo_endpoint,
      revocation_endpoint: c.raw["revocation_endpoint"] || c.raw[:revocation_endpoint]
    )
  end
end

# Refresh tokens rotate, and presenting a used one ends the whole session.
# Concurrent refreshes of the same token in this process share one request.
# (Across processes, serialise refreshes yourself, e.g. with a per-session lock.)
module Refresher
  @lock = Mutex.new
  @inflight = {} # sha256(refresh token) -> { mutex:, result:, at: }

  module_function

  def call(refresh_token)
    key = Digest::SHA256.hexdigest(refresh_token)
    entry = @lock.synchronize do
      @inflight.delete_if { |_, e| Time.now - e[:at] > 60 }
      @inflight[key] ||= { mutex: Mutex.new, result: nil, at: Time.now }
    end
    entry[:mutex].synchronize do
      entry[:result] ||= begin
        client = Provider.client
        client.refresh_token = refresh_token
        t = client.access_token!(client_auth_method: :basic)
        {
          "access_token" => t.access_token,
          "refresh_token" => t.refresh_token,
          "expires_at" => Time.now.to_i + t.expires_in.to_i, # from the response, never hardcoded
          "scope" => t.scope && Array(t.scope).join(" ").split
        }
      end
    end
  end
end

# In-memory server-side sessions (use a shared store in production). The
# cookie holds only a random session id. Nothing is stored for a visitor until
# there is something to keep (from GET /login on), sessions idle for 8 hours
# are dropped, and a sweep runs at most every 10 minutes.
class MemorySessionStore < Rack::Session::Abstract::PersistedSecure
  IDLE = 8 * 3600
  SWEEP_EVERY = 600

  def initialize(app, options = {})
    super
    @sessions = {} # private session id -> [data, last seen]
    @mutex = Mutex.new
    @last_sweep = now
  end

  def find_session(_req, sid)
    @mutex.synchronize do
      sweep
      entry = sid && @sessions[sid.private_id]
      if entry && now - entry[1] <= IDLE
        entry[1] = now
        [sid, entry[0]]
      else
        @sessions.delete(sid.private_id) if entry
        [generate_sid, {}] # stored only once it holds something
      end
    end
  end

  def write_session(_req, sid, data, _options)
    @mutex.synchronize { @sessions[sid.private_id] = [data, now] }
    sid
  end

  def delete_session(_req, sid, options)
    @mutex.synchronize { @sessions.delete(sid.private_id) }
    generate_sid unless options[:drop]
  end

  private

  # A session holding nothing but a CSRF token is not kept, and gets no cookie.
  def commit_session?(req, session, options)
    return false unless super
    return true if session.to_hash.any? { |k, v| k != "csrf" && !v.nil? }

    @mutex.synchronize { @sessions.delete(session.id.private_id) } if session.id.respond_to?(:private_id)
    false
  end

  def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  def sweep
    return if now - @last_sweep < SWEEP_EVERY

    @last_sweep = now
    @sessions.delete_if { |_, (_, seen)| now - seen > IDLE }
  end
end

class App < Sinatra::Base
  set :protection, false # configured explicitly below, after the session
  set :show_exceptions, false
  set :raise_errors, false
  set :dump_errors, false # never print errors that may carry request data

  # Server-side session store: the cookie holds only a random session id.
  use MemorySessionStore,
      key: SECURE_COOKIE ? "__Host-nobleid_example" : "nobleid_example", # __Host-: pinned to this origin
      path: "/",
      httponly: true,
      same_site: :lax,
      secure: SECURE_COOKIE,
      expire_after: 8 * 3600

  # CSRF: hidden authenticity_token on every POST form, plus an Origin check.
  use Rack::Protection, use: [:authenticity_token], permitted_origins: [APP_ORIGIN], reaction: :deny

  use OmniAuth::Builder do
    provider :nobleid,
             issuer: ISSUER,
             discovery: true, # endpoints and JWKS from {issuer}/.well-known/openid-configuration
             client_signing_alg: :ES256, # NobleID signs ID tokens with ES256 only; anything else is rejected
             response_type: :code,
             scope: SCOPE,
             pkce: true, # S256
             send_nonce: true,
             send_state: true,
             require_state: true,
             client_auth_method: :basic, # client_secret_basic: id and secret form-urlencoded, then base64
             send_scope_to_token_endpoint: false,
             uid_field: "sub",
             request_path: "/login",
             callback_path: CALLBACK_PATH, # set explicitly: OmniAuth would otherwise reuse request_path
             client_options: {
               identifier: CLIENT_ID,
               secret: CLIENT_SECRET,
               redirect_uri: REDIRECT_URI
             }
  end

  helpers do
    def esc(value) = Html.esc(value)

    def html(status_code, body)
      status status_code
      headers Html::HEADERS
      Html.page(body)
    end

    def error_page(code, description = nil, status_code = 400)
      html(status_code, Html.error_body(code, description))
    end

    def csrf_token = Rack::Protection::AuthenticityToken.token(session)

    def post_form(action, label)
      "<form method=\"post\" action=\"#{esc(action)}\" style=\"display:inline\">" \
        "<input type=\"hidden\" name=\"authenticity_token\" value=\"#{esc(csrf_token)}\">" \
        "<button>#{esc(label)}</button></form>"
    end

    def sign_out_locally!
      session.clear
      request.env["rack.session.options"][:drop] = true
    end

    # A current access token, refreshed first if it has expired (and a refresh token exists).
    def access_token!
      t = session["tokens"]
      if t["refresh_token"] && Time.now.to_i >= t["expires_at"].to_i - 30
        apply_refresh!(Refresher.call(t["refresh_token"]))
      end
      session["tokens"]["access_token"]
    end

    def apply_refresh!(fresh)
      session["tokens"] = session["tokens"].merge(fresh.reject { |k, v| k == "scope" || v.nil? })
      session["scope"] = fresh["scope"] if fresh["scope"]
    end
  end

  get "/" do
    user = session["user"]
    unless user
      next html(200, "<h1>NobleID example (Sinatra)</h1><p id=\"signed-out\">You are signed out.</p>" \
                     "<p><a href=\"/login\">Sign in with NobleID</a></p>")
    end

    claims = user.merge("granted_scope" => session["scope"].join(" "))
    html(200, "<h1>Signed in</h1><p>Hello, #{esc(user['name'] || user['nobleid'])}.</p>" \
              "<pre id=\"claims\">#{esc(JSON.pretty_generate(claims))}</pre>" \
              "<p><a href=\"/works\">My works</a> " \
              "#{session['tokens']['refresh_token'] ? post_form('/refresh', 'Refresh tokens') : ''} " \
              "#{post_form('/logout', 'Sign out')}</p>")
  end

  # GET /login is handled by OmniAuth (request_path above): state, nonce, PKCE S256, redirect.

  # Reached only after NobleID's checks in nobleid_strategy.rb and the gem's ID-token verification.
  get CALLBACK_PATH do
    auth = request.env["omniauth.auth"]
    next error_page("invalid_request", "no sign-in result") unless auth

    creds = auth["credentials"] || {}
    claims = auth.dig("extra", "raw_info").to_hash # ID-token claims merged with userinfo
    # The user may untick scopes: read what was actually granted from the token response.
    granted = Array(creds["scope"]).join(" ").split
    granted = SCOPE if granted.empty?

    # New session id after sign-in; the old session (and its flow data) is discarded.
    session.clear
    request.env["rack.session.options"][:renew] = true
    # Key your accounts on `sub`. Only trust `email` for linking when email_verified is true.
    session["user"] = claims
    session["scope"] = granted
    session["tokens"] = {
      "access_token" => creds["token"],
      "refresh_token" => creds["refresh_token"], # present only if offline_access was granted
      "expires_at" => Time.now.to_i + creds["expires_in"].to_i
    }
    redirect "/", 303
  end

  get "/works" do
    redirect "/", 303 unless session["user"]
    unless session["scope"].include?("works")
      next html(200, "<p>The works scope was not granted.</p><p><a href=\"/\">Back</a></p>")
    end

    uri = URI("#{ISSUER}/oauth/works")
    uri.query = URI.encode_www_form(limit: 50, offset: 0)
    req = Net::HTTP::Get.new(uri)
    req["Authorization"] = "Bearer #{access_token!}"
    req["Accept"] = "application/json"
    res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", open_timeout: 10, read_timeout: 15) do |http|
      http.request(req)
    end
    body = JSON.parse(res.body.to_s) rescue {}
    unless res.is_a?(Net::HTTPSuccess)
      retry_after = res["retry-after"] ? "retry after #{res['retry-after']}s" : nil # 429 slow_down: back off
      next error_page(body["error"] || "http_#{res.code}", retry_after, 502)
    end
    html(200, "<h1>Works</h1><pre id=\"works\">#{esc(JSON.pretty_generate(body))}</pre><p><a href=\"/\">Back</a></p>")
  rescue Rack::OAuth2::Client::Error => e # from the refresh in access_token!
    # The refresh token may already be spent (see POST /refresh): sign out locally.
    sign_out_locally!
    redirect "/", 303 if e.response[:error] == "invalid_grant"
    error_page(e.response[:error], nil, 502)
  end

  post "/refresh" do
    tokens = session["tokens"]
    redirect "/", 303 unless tokens && tokens["refresh_token"]

    begin
      apply_refresh!(Refresher.call(tokens["refresh_token"]))
    rescue StandardError => e
      # invalid_grant: the user removed the app, or the session ended at NobleID.
      # Any other failure may come after NobleID already rotated the refresh
      # token, so the one we hold could be spent. Either way, sign out here too.
      sign_out_locally!
      code = e.is_a?(Rack::OAuth2::Client::Error) ? e.response[:error] : "server_error"
      redirect "/", 303 if code == "invalid_grant"
      next error_page(code, nil, 502)
    end
    redirect "/", 303
  end

  # NobleID has no end-session endpoint: revoke the tokens, then clear our session.
  post "/logout" do
    tokens = session["tokens"]
    if tokens
      begin
        client = Provider.client
        # Revoking the refresh token also ends the access tokens issued from it.
        client.revoke!(refresh_token: tokens["refresh_token"]) if tokens["refresh_token"]
        client.revoke!(access_token: tokens["access_token"]) if tokens["access_token"]
      rescue StandardError => e
        warn "revoke failed: #{e.class}" # never log the token
      end
    end
    sign_out_locally!
    redirect "/", 303
  end

  not_found { html(404, "<p>Not found</p>") }

  error do
    warn "request failed: #{env['sinatra.error'].class}" # class only: messages may hold request data
    error_page("server_error", nil, 500)
  end
end
