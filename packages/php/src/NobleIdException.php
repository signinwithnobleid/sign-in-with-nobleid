<?php

declare(strict_types=1);

namespace NobleId\SignIn;

/**
 * A sign-in or API failure with an OAuth error code.
 *
 * `$error` is the OAuth error code (for example `access_denied`,
 * `invalid_grant`, `invalid_state`, `slow_down`). The message and the
 * description never contain tokens, codes or secrets, so they are safe to log
 * and to show (escaped) to a developer.
 */
final class NobleIdException extends \RuntimeException
{
    public function __construct(
        public readonly string $error,
        public readonly string $description = '',
        public readonly ?int $status = null,
        public readonly ?int $retryAfter = null,
    ) {
        parent::__construct($description !== '' ? $error . ': ' . $description : $error);
    }
}
