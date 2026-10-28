package com.example.nobleid;

import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

@Configuration
class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    /** NobleID signs ID tokens with ES256 only; Spring's default is RS256. */
    @Bean
    JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
        OidcIdTokenDecoderFactory factory = new OidcIdTokenDecoderFactory();
        factory.setJwsAlgorithmResolver(registration -> SignatureAlgorithm.ES256);
        return factory;
    }

    /** Tokens are kept per HTTP session, so they end with the session. */
    @Bean
    OAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    SessionAuthorizationRequestRepository authorizationRequestRepository() {
        return new SessionAuthorizationRequestRepository();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository registrations,
            SessionAuthorizationRequestRepository pendingRequests, NobleIdApi api) throws Exception {

        // state + nonce are Spring's defaults for an openid scope; PKCE S256 must be asked for
        // explicitly for a confidential client.
        DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(
                registrations, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        // Always call userinfo: several NobleID claims (research_interests, affiliations,
        // verified_authorship_count) are only there, not in the ID token.
        OidcUserService userService = new OidcUserService();
        userService.setRetrieveUserInfo(request -> true);

        // Logout: NobleID has no end-session endpoint. Revoke the refresh token (which ends its
        // access tokens) and the access token, then Spring clears the session.
        LogoutHandler revoke = (req, res, auth) -> {
            if (!(auth instanceof OAuth2AuthenticationToken)) return;
            OAuth2AuthorizedClient c = api.load(auth, req);
            if (c == null) return;
            if (c.getRefreshToken() != null) api.revoke(c.getClientRegistration(), c.getRefreshToken().getTokenValue(), "refresh_token");
            api.revoke(c.getClientRegistration(), c.getAccessToken().getTokenValue(), "access_token");
        };

        http
            .authorizeHttpRequests(a -> a
                .requestMatchers("/", "/login", "/error").permitAll()
                .anyRequest().authenticated())
            .oauth2Login(o -> o
                .loginPage("/login")
                .authorizationEndpoint(e -> e
                    .authorizationRequestResolver(resolver)
                    .authorizationRequestRepository(pendingRequests))
                .userInfoEndpoint(u -> u.oidcUserService(userService))
                .defaultSuccessUrl("/", true)
                .failureHandler((req, res, ex) -> {
                    // Denied consent, bad nonce/aud, failed code exchange: show the OAuth error code.
                    String code = "server_error";
                    String description = null;
                    if (ex instanceof OAuth2AuthenticationException oae) {
                        code = oae.getError().getErrorCode();
                        description = oae.getError().getDescription();
                    } else {
                        log.warn("sign-in failed: {}", ex.getClass().getSimpleName());
                    }
                    Html.writeError(res, HttpServletResponse.SC_BAD_REQUEST, code, description);
                }))
            .addFilterBefore(new CallbackIssuerFilter(registrations, pendingRequests), OAuth2LoginAuthenticationFilter.class)
            .logout(l -> l.addLogoutHandler(revoke).logoutSuccessUrl("/"))
            // CSRF stays on (Spring's default): every POST form carries a hidden _csrf input.
            .csrf(Customizer.withDefaults())
            .headers(h -> h
                .contentSecurityPolicy(c -> c.policyDirectives("default-src 'none'; img-src https:; style-src 'unsafe-inline'; form-action 'self'"))
                .referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER)));
        return http.build();
    }
}
