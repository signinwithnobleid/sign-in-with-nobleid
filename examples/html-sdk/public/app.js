/* Browser-only "Sign in with NobleID" (public client). DOM text APIs only. */
(function () {
  "use strict";
  var cfg = window.NOBLEID_CONFIG || {};
  if (cfg.issuer) NobleID.configure({ issuer: cfg.issuer, authorizationEndpoint: cfg.authorizationEndpoint }); // local mock only
  var status = document.getElementById("status");
  var say = function (t) {
    status.textContent = t;
  };

  if (document.getElementById("signin")) {
    var theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    NobleID.renderButton("signin", {
      clientId: cfg.clientId,
      redirectUri: cfg.redirectUri,
      scope: cfg.scope,
      theme: theme,
      onError: function (e) {
        say("Could not start sign-in: " + e.code);
      },
    });
    return;
  }

  // callback.html
  var tokens = null; // memory only: never localStorage, never a URL
  NobleID.handleCallback({ clientId: cfg.clientId, redirectUri: cfg.redirectUri })
    .then(function (r) {
      tokens = r.tokens;
      say("Signed in as " + (r.claims.name || r.claims.nobleid) + ".");
      NobleID.renderResearcherBadge("badge", r.claims);
      var pre = document.getElementById("claims");
      pre.textContent = JSON.stringify(r.claims, null, 2);
      pre.hidden = false;
      document.getElementById("signout").hidden = false;
    })
    .catch(function (e) {
      // e.code: access_denied, invalid_state, invalid_issuer, expired, ...
      say("Sign-in failed: " + e.code + (e.description ? " (" + e.description + ")" : ""));
    });

  document.getElementById("signout").addEventListener("click", function () {
    var done = function () {
      tokens = null;
      window.location.assign("/");
    };
    if (!tokens) return done();
    var t = tokens.refresh_token || tokens.access_token;
    NobleID.revoke({ clientId: cfg.clientId, token: t, tokenTypeHint: tokens.refresh_token ? "refresh_token" : "access_token" }).then(done, done);
  });
})();
