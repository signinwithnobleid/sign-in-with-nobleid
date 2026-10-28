package com.example.nobleid;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.util.HtmlUtils;

/** Tiny HTML helpers. Everything dynamic goes through {@link #esc}. */
final class Html {

    private Html() {}

    static String esc(Object s) {
        return s == null ? "" : HtmlUtils.htmlEscape(String.valueOf(s), "UTF-8");
    }

    static String page(String body) {
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>NobleID example</title></head>"
                + "<body style=\"font-family:system-ui;max-width:48rem;margin:2rem auto;padding:0 1rem\">" + body + "</body></html>";
    }

    static ResponseEntity<String> ok(String body) {
        return status(HttpStatus.OK, body);
    }

    static ResponseEntity<String> status(HttpStatus status, String body) {
        return ResponseEntity.status(status)
                .contentType(new MediaType(MediaType.TEXT_HTML, StandardCharsets.UTF_8))
                .cacheControl(CacheControl.noStore())
                .body(page(body));
    }

    static ResponseEntity<String> seeOther(String location) {
        return ResponseEntity.status(HttpStatus.SEE_OTHER).header("Location", location).cacheControl(CacheControl.noStore()).build();
    }

    static String errorBody(String code, String description) {
        return "<h1>Sign-in failed</h1><p id=\"error\">" + esc(code == null ? "error" : code)
                + (description == null || description.isEmpty() ? "" : ": " + esc(description))
                + "</p><p><a href=\"/\">Back</a></p>";
    }

    /** For filters and handlers that write the servlet response directly. */
    static void writeError(HttpServletResponse res, int status, String code, String description) throws IOException {
        res.setStatus(status);
        res.setContentType("text/html;charset=UTF-8");
        res.setHeader("Cache-Control", "no-store");
        res.getWriter().write(page(errorBody(code, description)));
    }

    static String postForm(String action, String label, String csrfParam, String csrfToken) {
        return "<form method=\"post\" action=\"" + esc(action) + "\" style=\"display:inline\">"
                + "<input type=\"hidden\" name=\"" + esc(csrfParam) + "\" value=\"" + esc(csrfToken) + "\">"
                + "<button>" + esc(label) + "</button></form>";
    }
}
