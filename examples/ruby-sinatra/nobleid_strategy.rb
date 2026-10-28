# frozen_string_literal: true

require "digest"
require "omniauth_openid_connect"

module OmniAuth
  module Strategies
    # omniauth_openid_connect with the checks NobleID needs and the gem lacks.
    #
    # The gem does PKCE, nonce, discovery and ID-token signature verification
    # (via json-jwt and the provider's JWKS). It does not check the RFC 9207
    # `iss` callback parameter, surfaces `error` before checking `state`, and
    # reads `nonce`, `code_verifier` and `redirect_uri` from the callback query
    # string if they are present. This subclass, in order:
    #
    #   1. requires a sign-in in progress and a matching `state` (constant time),
    #   2. requires `iss` to equal the configured issuer (missing = reject),
    #   3. rejects callbacks carrying parameters the gem would otherwise trust,
    #   4. only then lets the gem surface `error` or exchange the code,
    #   5. checks that the userinfo `sub` equals the ID token `sub`.
    #
    # It overrides a few of the gem's private methods, so keep the gem pinned
    # (see Gemfile) and re-read this file when upgrading it.
    class NobleID < OpenIDConnect
      option :name, "nobleid"

      FLOW_KEYS = %w[omniauth.state omniauth.nonce omniauth.pkce.verifier nobleid.flow_started_at].freeze
      # The gem would read these from the callback URL; the provider never sends them there.
      UNTRUSTED_CALLBACK_PARAMS = %w[nonce code_verifier redirect_uri id_token error_reason].freeze
      MAX_FLOW_AGE = 10 * 60 # seconds

      def request_phase
        FLOW_KEYS.each { |k| session.delete(k) }
        session["nobleid.flow_started_at"] = Time.now.to_i
        super
      end

      def callback_phase
        q = request.GET
        expected = session["omniauth.state"]
        started = session["nobleid.flow_started_at"]

        return reject!(:invalid_state, "no sign-in in progress") unless expected.is_a?(String) && !expected.empty?
        return reject!(:invalid_state, "state does not match") unless same_string?(q["state"], expected)
        return reject!(:invalid_issuer, "the response did not come from the expected issuer") unless q["iss"] == options.issuer
        return reject!(:invalid_request, "unexpected callback parameter") if UNTRUSTED_CALLBACK_PARAMS.any? { |k| request.params.key?(k) }
        return reject!(:expired, "sign-in took too long; start again") if !started.is_a?(Integer) || Time.now.to_i - started > MAX_FLOW_AGE

        session.delete("nobleid.flow_started_at")
        super # surfaces `error`, then exchanges the code (PKCE) and verifies the ID token
      rescue ::OpenIDConnect::ResponseObject::IdToken::InvalidToken, ::JSON::JWT::Exception => e
        fail!(:invalid_id_token, e)
      rescue ::OpenIDConnect::Exception, ::Faraday::Error, ::Rack::OAuth2::Client::Error => e
        fail!(:server_error, e)
      end

      private

      def reject!(code, reason)
        FLOW_KEYS.each { |k| session.delete(k) }
        fail!(code, CallbackError.new(error: code, reason: reason))
      end

      def same_string?(a, b)
        return false unless a.is_a?(String) && b.is_a?(String)

        Rack::Utils.secure_compare(Digest::SHA256.digest(a), Digest::SHA256.digest(b)) && a.bytesize == b.bytesize
      end

      # Always the registered redirect URI, never one built from request parameters.
      def redirect_uri
        client_options.redirect_uri
      end

      # The nonce comes from the session only (the gem would also accept ?nonce= on the callback).
      def verify_id_token!(id_token)
        raise ::OpenIDConnect::ResponseObject::IdToken::InvalidToken, "no ID token" unless id_token

        nonce = stored_nonce
        raise ::OpenIDConnect::ResponseObject::IdToken::InvalidNonce, "no nonce in the session" if nonce.to_s.empty?

        decode_id_token(id_token).verify!(issuer: options.issuer, client_id: client_options.identifier, nonce: nonce)
      end

      # ID-token claims merged with userinfo, after checking both describe the same subject.
      def user_info
        return @user_info if @user_info

        id_claims = decode_id_token(access_token.id_token).raw_attributes
        info = access_token.userinfo!.raw_attributes
        unless info["sub"].is_a?(String) && info["sub"] == id_claims["sub"]
          raise CallbackError.new(error: :invalid_userinfo, reason: "userinfo sub does not match the ID token")
        end

        @user_info = ::OpenIDConnect::ResponseObject::UserInfo.new(info.merge(id_claims))
      end
    end
  end
end

OmniAuth.config.add_camelization "nobleid", "NobleID"
