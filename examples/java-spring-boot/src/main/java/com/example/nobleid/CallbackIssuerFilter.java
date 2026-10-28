package com.example.nobleid;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Runs in front of Spring's OAuth2LoginAuthenticationFilter on the callback and checks, in
 * this order: a sign-in is in progress, `state` matches it, and `iss` equals the issuer
 * (RFC 9207; a missing `iss` is rejected). Only then does the callback reach Spring, which
 * surfaces `error` or exchanges the code. Spring Security does not check `iss` itself.
 */
final class CallbackIssuerFilter extends OncePerRequestFilter {

    static final String CALLBACK_PREFIX = "/login/oauth2/code/";

    private final ClientRegistrationRepository registrations;
    private final SessionAuthorizationRequestRepository pendingRequests;

    CallbackIssuerFilter(ClientRegistrationRepository registrations, SessionAuthorizationRequestRepository pendingRequests) {
        this.registrations = registrations;
        this.pendingRequests = pendingRequests;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Spring's callback filter matches the decoded path, so the raw request URI alone
        // could be sidestepped with percent-encoding (/%6Cogin/...). Check the decoded
        // servlet path, the raw URI, and any request that carries an authorization response.
        String raw = request.getRequestURI().substring(request.getContextPath().length());
        boolean callbackPath = request.getServletPath().startsWith(CALLBACK_PREFIX) || raw.startsWith(CALLBACK_PREFIX);
        boolean authorizationResponse = request.getParameter(OAuth2ParameterNames.STATE) != null
                && (request.getParameter(OAuth2ParameterNames.CODE) != null || request.getParameter(OAuth2ParameterNames.ERROR) != null);
        return !(callbackPath || authorizationResponse);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
        OAuth2AuthorizationRequest pending = pendingRequests.pending(req);
        if (pending == null) {
            reject(req, res, "invalid_request", "No sign-in is in progress.");
            return;
        }
        if (!SessionAuthorizationRequestRepository.stateMatches(pending, req.getParameter(OAuth2ParameterNames.STATE))) {
            reject(req, res, "invalid_request", "The state does not match this sign-in.");
            return;
        }
        String registrationId = pending.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
        ClientRegistration registration = registrationId == null ? null : registrations.findByRegistrationId(registrationId);
        String issuer = registration == null ? null : registration.getProviderDetails().getIssuerUri();
        String iss = req.getParameter("iss");
        if (issuer == null || iss == null
                || !MessageDigest.isEqual(issuer.getBytes(StandardCharsets.UTF_8), iss.getBytes(StandardCharsets.UTF_8))) {
            reject(req, res, "invalid_request", iss == null ? "The response has no iss parameter." : "The response came from another issuer.");
            return;
        }
        chain.doFilter(req, res); // Spring now handles `error`, or exchanges the code
    }

    private void reject(HttpServletRequest req, HttpServletResponse res, String code, String description) throws IOException {
        pendingRequests.clear(req); // never reuse a pending request after a bad callback
        Html.writeError(res, HttpServletResponse.SC_BAD_REQUEST, code, description);
    }
}
