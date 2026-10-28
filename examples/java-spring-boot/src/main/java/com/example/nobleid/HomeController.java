package com.example.nobleid;

import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientResponseException;

@RestController
class HomeController {

    private static final Logger log = LoggerFactory.getLogger(HomeController.class);

    private final NobleIdApi api;
    private final ObjectMapper json;

    HomeController(NobleIdApi api, ObjectMapper json) {
        this.api = api;
        this.json = json;
    }

    @GetMapping("/")
    ResponseEntity<String> home(Authentication auth, HttpServletRequest req, CsrfToken csrf) {
        if (!(auth instanceof OAuth2AuthenticationToken token) || !(token.getPrincipal() instanceof OidcUser user)) {
            return Html.ok("<h1>NobleID example (Spring Boot)</h1><p id=\"signed-out\">You are signed out.</p>"
                    + "<p><a href=\"/login\">Sign in with NobleID</a></p>");
        }
        OAuth2AuthorizedClient client = api.load(auth, req);
        // ID-token claims merged with the userinfo response (Spring's OidcUser does the merge).
        // Key accounts on `sub`; only trust `email` for linking when email_verified is true.
        Map<String, Object> claims = new LinkedHashMap<>(user.getClaims());
        if (client != null) claims.put("granted_scope", String.join(" ", client.getAccessToken().getScopes()));
        String name = user.getFullName() != null ? user.getFullName() : user.getClaimAsString("nobleid");
        boolean canRefresh = client != null && client.getRefreshToken() != null;
        return Html.ok("<h1>Signed in</h1><p>Hello, " + Html.esc(name) + ".</p>"
                + "<pre id=\"claims\">" + Html.esc(json.writerWithDefaultPrettyPrinter().writeValueAsString(claims)) + "</pre>"
                + "<p><a href=\"/works\">My works</a> "
                + (canRefresh ? Html.postForm("/refresh", "Refresh tokens", csrf.getParameterName(), csrf.getToken()) + " " : "")
                + Html.postForm("/logout", "Sign out", csrf.getParameterName(), csrf.getToken()) + "</p>");
    }

    /** Spring starts the flow (state, nonce, PKCE S256) at /oauth2/authorization/{registrationId}. */
    @GetMapping("/login")
    ResponseEntity<String> login() {
        return Html.seeOther("/oauth2/authorization/" + NobleIdApi.REGISTRATION_ID);
    }

    @GetMapping("/works")
    ResponseEntity<String> works(Authentication auth, HttpServletRequest req, HttpServletResponse res) {
        OAuth2AuthorizedClient client;
        try {
            client = api.fresh(auth, req, res);
        } catch (NobleIdApi.SignedOutException e) {
            return signOutLocally(auth, req, res);
        }
        if (client == null) return Html.seeOther("/");
        if (!client.getAccessToken().getScopes().contains("works")) {
            return Html.ok("<p>The works scope was not granted.</p><p><a href=\"/\">Back</a></p>");
        }
        JsonNode works = api.works(client, 50, 0);
        return Html.ok("<h1>Works</h1><pre id=\"works\">" + Html.esc(json.writerWithDefaultPrettyPrinter().writeValueAsString(works))
                + "</pre><p><a href=\"/\">Back</a></p>");
    }

    /** Refresh now (normally you would only refresh when the access token is about to expire). */
    @PostMapping("/refresh")
    ResponseEntity<String> refresh(Authentication auth, HttpServletRequest req, HttpServletResponse res) {
        try {
            api.refresh(auth, req, res);
        } catch (NobleIdApi.SignedOutException e) {
            // invalid_grant: the user removed the app or the session ended. Sign out locally.
            return signOutLocally(auth, req, res);
        }
        return Html.seeOther("/");
    }

    private ResponseEntity<String> signOutLocally(Authentication auth, HttpServletRequest req, HttpServletResponse res) {
        new SecurityContextLogoutHandler().logout(req, res, auth);
        return Html.seeOther("/");
    }

    @ExceptionHandler(OAuth2AuthorizationException.class)
    ResponseEntity<String> oauthError(OAuth2AuthorizationException e) {
        return Html.status(HttpStatus.BAD_GATEWAY, Html.errorBody(e.getError().getErrorCode(), e.getError().getDescription()));
    }

    @ExceptionHandler(RestClientResponseException.class)
    ResponseEntity<String> apiError(RestClientResponseException e) {
        int s = e.getStatusCode().value();
        String code = s == 429 ? "slow_down" : s == 401 ? "invalid_token" : s == 403 ? "insufficient_scope" : "server_error";
        return Html.status(HttpStatus.BAD_GATEWAY, Html.errorBody(code, null));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<String> unexpected(Exception e) {
        log.error("request failed: {}", e.getClass().getSimpleName()); // never log tokens or full errors that may hold them
        return Html.status(HttpStatus.INTERNAL_SERVER_ERROR, Html.errorBody("server_error", null));
    }
}
