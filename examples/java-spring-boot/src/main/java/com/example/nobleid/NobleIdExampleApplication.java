package com.example.nobleid;

import java.net.URI;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Minimal "Sign in with NobleID" web app on Spring Boot + Spring Security's OAuth2 client.
 * Confidential client: the secret and the tokens stay on this server; the browser only
 * gets an opaque session cookie.
 *
 * <pre>
 *   ISSUER=https://id.nobleid.org CLIENT_ID=... CLIENT_SECRET=... \
 *   REDIRECT_URI=http://localhost:8080/login/oauth2/code/nobleid java -jar app.jar
 * </pre>
 */
@SpringBootApplication
public class NobleIdExampleApplication {

    public static void main(String[] args) {
        if (isBlank(System.getenv("CLIENT_ID")) || isBlank(System.getenv("CLIENT_SECRET"))) {
            System.err.println("Set CLIENT_ID and CLIENT_SECRET (see .env.example).");
            System.exit(1);
        }
        String issuer = System.getenv().getOrDefault("ISSUER", "https://id.nobleid.org");
        if (!issuerAllowed(issuer)) {
            System.err.println("ISSUER must be https (http is allowed only for a localhost mock).");
            System.exit(1);
        }
        String redirectUri = System.getenv().getOrDefault("REDIRECT_URI", "http://localhost:8080/login/oauth2/code/nobleid");
        SpringApplication app = new SpringApplication(NobleIdExampleApplication.class);
        // Secure session cookie whenever the app is served over https.
        app.setDefaultProperties(Map.of("server.servlet.session.cookie.secure", String.valueOf(redirectUri.startsWith("https:"))));
        app.run(args);
    }

    /** https, or http only for a provider on this machine (the local mock). */
    static boolean issuerAllowed(String issuer) {
        URI u;
        try {
            u = new URI(issuer);
        } catch (Exception e) {
            return false;
        }
        String host = u.getHost();
        if (host == null || u.getRawUserInfo() != null) return false;
        if ("https".equals(u.getScheme())) return true;
        return "http".equals(u.getScheme())
                && (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]"));
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
