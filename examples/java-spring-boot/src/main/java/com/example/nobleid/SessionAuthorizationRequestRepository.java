package com.example.nobleid;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

/**
 * Keeps the one pending authorization request (state, nonce, PKCE verifier) in the HTTP
 * session, like Spring's HttpSessionOAuth2AuthorizationRequestRepository, but compares
 * `state` in constant time and lets {@link CallbackIssuerFilter} look at it first.
 */
final class SessionAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final String KEY = SessionAuthorizationRequestRepository.class.getName() + ".PENDING";

    /** The pending request, whatever the callback says (null when no sign-in is in progress). */
    OAuth2AuthorizationRequest pending(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? null : (OAuth2AuthorizationRequest) session.getAttribute(KEY);
    }

    static boolean stateMatches(OAuth2AuthorizationRequest pending, String state) {
        if (pending == null || pending.getState() == null || state == null) return false;
        return MessageDigest.isEqual(pending.getState().getBytes(StandardCharsets.UTF_8), state.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        OAuth2AuthorizationRequest pending = pending(request);
        return stateMatches(pending, request.getParameter(OAuth2ParameterNames.STATE)) ? pending : null;
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if (authorizationRequest == null) {
            clear(request);
            return;
        }
        request.getSession().setAttribute(KEY, authorizationRequest);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        OAuth2AuthorizationRequest loaded = loadAuthorizationRequest(request);
        clear(request); // single use, whatever happens next
        return loaded;
    }

    void clear(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) session.removeAttribute(KEY);
    }
}
