<?php

declare(strict_types=1);

namespace NobleId\SignIn;

use League\OAuth2\Client\OptionProvider\PostAuthOptionProvider;

/**
 * client_secret_basic as RFC 6749 section 2.3.1 defines it: the client id and
 * secret are form-urlencoded, then joined with ":" and base64-encoded.
 *
 * league/oauth2-client's own HttpBasicAuthOptionProvider skips the
 * form-urlencoding step, which breaks for secrets with reserved characters.
 * The secret is sent in the header only, never also in the body.
 */
final class ClientSecretBasicOptionProvider extends PostAuthOptionProvider
{
    public function getAccessTokenOptions($method, array $params)
    {
        $id = (string) ($params['client_id'] ?? '');
        $secret = (string) ($params['client_secret'] ?? '');
        unset($params['client_id'], $params['client_secret']);

        $options = parent::getAccessTokenOptions($method, $params);
        $options['headers']['Authorization'] = self::header($id, $secret);

        return $options;
    }

    public static function header(string $id, #[\SensitiveParameter] string $secret): string
    {
        return 'Basic ' . base64_encode(urlencode($id) . ':' . urlencode($secret));
    }
}
