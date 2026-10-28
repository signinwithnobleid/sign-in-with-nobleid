<?php

/**
 * Minimal "Sign in with NobleID" web app in plain PHP, using the nobleid/signin
 * package (league/oauth2-client + firebase/php-jwt). Confidential client: the
 * secret and the tokens stay on this server; the browser only gets an opaque
 * PHP session cookie.
 *
 *   composer install --no-dev
 *   ISSUER=https://id.nobleid.org CLIENT_ID=... CLIENT_SECRET=... \
 *   REDIRECT_URI=http://localhost:3000/callback php -S localhost:3000 -t public public/index.php
 */

declare(strict_types=1);

use NobleId\SignIn\NobleIdClient;
use NobleId\SignIn\NobleIdException;

require __DIR__ . '/../vendor/autoload.php';

$ISSUER = getenv('ISSUER') ?: NobleIdClient::ISSUER;
$CLIENT_ID = getenv('CLIENT_ID') ?: '';
$CLIENT_SECRET = getenv('CLIENT_SECRET') ?: '';
$REDIRECT_URI = getenv('REDIRECT_URI') ?: 'http://localhost:3000/callback';
$SCOPE = getenv('SCOPE') ?: 'openid profile email orcid affiliations works offline_access';

$redirect = parse_url($REDIRECT_URI);
$APP_ORIGIN = $redirect['scheme'] . '://' . $redirect['host'] . (isset($redirect['port']) ? ':' . $redirect['port'] : '');
$CALLBACK_PATH = $redirect['path'] ?? '/callback';
$SECURE = $redirect['scheme'] === 'https';

/* ── html ── */

function e(mixed $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
}

function send(int $status, string $body): never
{
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header("Content-Security-Policy: default-src 'none'; img-src https:; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");
    header('Referrer-Policy: no-referrer');
    header('X-Content-Type-Options: nosniff');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<title>NobleID example</title></head><body style="font-family:system-ui;max-width:48rem;margin:2rem auto;padding:0 1rem">'
        . $body . '</body></html>';
    exit;
}

function go(string $location): never
{
    http_response_code(303);
    header('Location: ' . $location);
    header('Cache-Control: no-store');
    exit;
}

function form(string $action, string $label): string
{
    return '<form method="post" action="' . e($action) . '" style="display:inline">'
        . '<input type="hidden" name="csrf" value="' . e($_SESSION['csrf']) . '"><button>' . e($label) . '</button></form>';
}

function errorPage(NobleIdException $err): never
{
    send(400, '<h1>Sign-in failed</h1><p id="error">' . e($err->error)
        . ($err->description !== '' ? ': ' . e($err->description) : '') . '</p><p><a href="/">Back</a></p>');
}

if ($CLIENT_ID === '' || $CLIENT_SECRET === '') {
    send(500, '<p id="error">Set CLIENT_ID and CLIENT_SECRET (see .env.example).</p>');
}

/** Discovery happens only on routes that talk to NobleID. Pass a PSR-16 `cache` in production. */
function nobleid(): NobleIdClient
{
    static $client = null;
    global $ISSUER, $CLIENT_ID, $CLIENT_SECRET, $REDIRECT_URI;

    return $client ??= NobleIdClient::discover([
        'issuer' => $ISSUER,
        'clientId' => $CLIENT_ID,
        'clientSecret' => $CLIENT_SECRET,
        'redirectUri' => $REDIRECT_URI,
        'clientAuth' => 'client_secret_basic',
    ]);
}

/* ── session: HttpOnly, SameSite=Lax, Secure on https, strict ids ── */

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_trans_sid', '0');
// Over https the __Host- prefix pins the cookie to this exact origin.
session_name($SECURE ? '__Host-nobleid_example' : 'nobleid_example');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $SECURE, 'httponly' => true, 'samesite' => 'Lax']);
session_start();
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));

function destroySession(): void
{
    $_SESSION = [];
    $p = session_get_cookie_params();
    setcookie(session_name(), '', ['expires' => 1, 'path' => $p['path'], 'secure' => $p['secure'], 'httponly' => true, 'samesite' => 'Lax']);
    session_destroy();
}

/* ── routes ── */

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

try {
    if ($method === 'GET' && $path === '/') {
        if (!isset($_SESSION['user'])) {
            send(200, '<h1>NobleID example (PHP)</h1><p id="signed-out">You are signed out.</p><p><a href="/login">Sign in with NobleID</a></p>');
        }
        $u = $_SESSION['user'];
        $shown = $u + ['granted_scope' => implode(' ', $_SESSION['scope'])];
        send(200, '<h1>Signed in</h1><p>Hello, ' . e($u['name'] ?? $u['nobleid'] ?? '') . '.</p>'
            . '<pre id="claims">' . e(json_encode($shown, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) . '</pre>'
            . '<p><a href="/works">My works</a> '
            . (!empty($_SESSION['tokens']['refresh_token']) ? form('/refresh', 'Refresh tokens') : '') . ' '
            . form('/logout', 'Sign out') . '</p>');
    }

    if ($method === 'GET' && $path === '/login') {
        [$url, $transaction] = nobleid()->startSignIn($SCOPE);
        $_SESSION['nobleid_tx'] = $transaction;
        go($url);
    }

    if ($method === 'GET' && $path === $CALLBACK_PATH) {
        $transaction = $_SESSION['nobleid_tx'] ?? null;
        unset($_SESSION['nobleid_tx']); // single use, whatever happens next
        $result = nobleid()->finishSignIn($_GET, $transaction);
        $claims = $result['claims'];
        $info = nobleid()->userinfo($result['tokens']['access_token'], $claims['sub']);
        // Key your accounts on `sub`. Only trust `email` for linking when email_verified is true.
        session_regenerate_id(true); // new session id after sign-in (no session fixation)
        $_SESSION = [
            'csrf' => bin2hex(random_bytes(32)),
            'user' => array_merge($claims, $info),
            'tokens' => $result['tokens'],
            'scope' => $result['scope'],
        ];
        go('/');
    }

    if ($method === 'GET' && $path === '/works') {
        if (!isset($_SESSION['user'])) {
            go('/');
        }
        if (!in_array('works', $_SESSION['scope'], true)) {
            send(200, '<p>The works scope was not granted.</p><p><a href="/">Back</a></p>');
        }
        $works = nobleid()->works($_SESSION['tokens']['access_token'], 50, 0);
        send(200, '<h1>Works</h1><pre id="works">' . e(json_encode($works, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) . '</pre><p><a href="/">Back</a></p>');
    }

    if ($method === 'POST' && ($path === '/refresh' || $path === '/logout')) {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
        $token = $_POST['csrf'] ?? null;
        if (($origin !== null && $origin !== $APP_ORIGIN) || !is_string($token) || !hash_equals($_SESSION['csrf'], $token)) {
            send(403, '<p id="error">forbidden</p>');
        }

        if ($path === '/refresh') {
            if (empty($_SESSION['tokens']['refresh_token'])) {
                go('/');
            }
            // PHP's file session handler locks the session for this request, so two
            // refreshes of the same (rotating) token cannot run at once for one user.
            try {
                $fresh = nobleid()->refresh($_SESSION['tokens']['refresh_token'], $_SESSION['user']['sub']);
            } catch (\Throwable $err) {
                // invalid_grant: the user removed the app, or the session ended. Any
                // other failure (a rejected ID token, a different sub) may come after
                // the provider already rotated the refresh token, so the one we hold
                // could be spent. Either way, sign out locally.
                destroySession();
                if ($err instanceof NobleIdException && $err->error === 'invalid_grant') {
                    go('/');
                }
                throw $err;
            }
            unset($fresh['claims']);
            $_SESSION['tokens'] = array_merge($_SESSION['tokens'], array_filter($fresh, static fn ($v) => $v !== null));
            go('/');
        }

        // Logout: NobleID has no end-session endpoint. Revoke, then clear our session.
        $tokens = $_SESSION['tokens'] ?? null;
        if (is_array($tokens)) {
            foreach (['refresh_token', 'access_token'] as $hint) {
                if (!empty($tokens[$hint])) {
                    try {
                        nobleid()->revoke($tokens[$hint], $hint);
                    } catch (NobleIdException) {
                        // Still sign out locally.
                    }
                }
            }
        }
        destroySession();
        go('/');
    }

    send(404, '<p>Not found</p>');
} catch (NobleIdException $err) {
    errorPage($err);
} catch (\Throwable $t) {
    error_log('request failed: ' . get_class($t)); // never log tokens or full errors that may hold them
    send(500, '<p id="error">server_error</p>');
}
