package com.example.nobleid;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import tools.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.WebUtils;

/** Refresh, revoke and the works API. Tokens live in the per-session authorized-client repository. */
@Component
class NobleIdApi {

    static final String REGISTRATION_ID = "nobleid";
    private static final Logger log = LoggerFactory.getLogger(NobleIdApi.class);

    /** Thrown when the refresh token is no longer valid: the caller signs the user out locally. */
    static final class SignedOutException extends RuntimeException {
        SignedOutException() {
            super("refresh token rejected", null, false, false);
        }
    }

    private final OAuth2AuthorizedClientRepository clients;
    private final RestClientRefreshTokenTokenResponseClient refreshClient = new RestClientRefreshTokenTokenResponseClient();
    private final RestClient http = RestClient.create();

    NobleIdApi(OAuth2AuthorizedClientRepository clients) {
        this.clients = clients;
    }

    OAuth2AuthorizedClient load(Authentication auth, HttpServletRequest req) {
        return clients.loadAuthorizedClient(REGISTRATION_ID, auth, req);
    }

    /**
     * Refresh-token grant. NobleID rotates the refresh token on every use and revokes the
     * whole family if an old one is replayed, so refreshes for one session are serialised
     * and the new refresh token is stored before anything else can read the old one.
     */
    OAuth2AuthorizedClient refresh(Authentication auth, HttpServletRequest req, HttpServletResponse res) {
        synchronized (WebUtils.getSessionMutex(req.getSession())) {
            OAuth2AuthorizedClient current = load(auth, req);
            if (current == null || current.getRefreshToken() == null) return current;
            OAuth2AccessTokenResponse tokens;
            try {
                tokens = refreshClient.getTokenResponse(new OAuth2RefreshTokenGrantRequest(
                        current.getClientRegistration(), current.getAccessToken(), current.getRefreshToken()));
            } catch (OAuth2AuthorizationException e) {
                if ("invalid_grant".equals(e.getError().getErrorCode())) {
                    clients.removeAuthorizedClient(REGISTRATION_ID, auth, req, res);
                    throw new SignedOutException();
                }
                throw e;
            }
            OAuth2RefreshToken rotated = tokens.getRefreshToken() != null ? tokens.getRefreshToken() : current.getRefreshToken();
            // The access token's scopes come from the `scope` the token response granted.
            OAuth2AuthorizedClient updated = new OAuth2AuthorizedClient(
                    current.getClientRegistration(), current.getPrincipalName(), tokens.getAccessToken(), rotated);
            clients.saveAuthorizedClient(updated, auth, req, res);
            return updated;
        }
    }

    /** A usable access token: refreshed first if it expires within a minute (expiry comes from `expires_in`). */
    OAuth2AuthorizedClient fresh(Authentication auth, HttpServletRequest req, HttpServletResponse res) {
        OAuth2AuthorizedClient c = load(auth, req);
        if (c == null) return null;
        Instant exp = c.getAccessToken().getExpiresAt();
        if (exp != null && exp.isBefore(Instant.now().plus(Duration.ofMinutes(1))) && c.getRefreshToken() != null) {
            return refresh(auth, req, res);
        }
        return c;
    }

    JsonNode works(OAuth2AuthorizedClient c, int limit, int offset) {
        String issuer = c.getClientRegistration().getProviderDetails().getIssuerUri();
        var uri = UriComponentsBuilder.fromUriString(issuer).path("/oauth/works")
                .queryParam("limit", limit).queryParam("offset", offset).build().toUri();
        return http.get().uri(uri)
                .headers(h -> h.setBearerAuth(c.getAccessToken().getTokenValue()))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve().body(JsonNode.class);
    }

    /** RFC 7009 revocation at the revocation_endpoint from discovery. Errors are not fatal. */
    void revoke(ClientRegistration reg, String token, String hint) {
        Object endpoint = reg.getProviderDetails().getConfigurationMetadata().get("revocation_endpoint");
        if (endpoint == null || token == null) return;
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);
        form.add("token_type_hint", hint);
        try {
            http.post().uri(endpoint.toString())
                    .headers(h -> h.setBasicAuth(basic(reg)))
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve().toBodilessEntity();
        } catch (RuntimeException e) {
            log.warn("revocation failed: {}", e.getClass().getSimpleName()); // never log the token
        }
    }

    /** client_secret_basic: form-urlencode id and secret, then base64 (RFC 6749 section 2.3.1). */
    private static String basic(ClientRegistration reg) {
        String id = URLEncoder.encode(reg.getClientId(), StandardCharsets.UTF_8);
        String secret = URLEncoder.encode(reg.getClientSecret(), StandardCharsets.UTF_8);
        return HttpHeaders.encodeBasicAuth(id, secret, StandardCharsets.UTF_8);
    }
}
