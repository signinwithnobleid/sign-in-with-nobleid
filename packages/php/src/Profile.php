<?php

declare(strict_types=1);

namespace NobleId\SignIn;

/**
 * A plain profile from NobleID's claims, for filling your own app's profile.
 *
 * Profile::fromClaims() takes the verified ID token claims (finishSignIn()'s
 * `claims`) and, optionally, the userinfo response for the same `sub`, and
 * returns an array whose keys are always present: null, [] or false when the
 * person did not share a value or NobleID does not know it.
 *
 * Fill only empty fields with it, and never overwrite what the person edited
 * in your app (docs/profile-data.md). No dependencies.
 */
final class Profile
{
    private const ORCID_URI = '~^https://orcid\.org/\d{4}-\d{4}-\d{4}-\d{3}[\dX]$~';
    private const ROR_URI = '~^https://ror\.org/0[a-hj-km-np-tv-z0-9]{6}\d{2}$~';

    /**
     * Userinfo wins where both carry a claim: it is fresher and has more.
     * `orcid` is set only when NobleID marked it proven through ORCID;
     * `picture` only when https; `website` only when http(s).
     *
     * @param array<string, mixed>      $idToken
     * @param array<string, mixed>|null $userinfo
     * @return array<string, mixed>
     * @throws NobleIdException `invalid_token` when the ID token has no sub or userinfo is for another subject
     */
    public static function fromClaims(array $idToken, ?array $userinfo = null): array
    {
        $sub = self::text($idToken['sub'] ?? null);
        if ($sub === null) {
            throw new NobleIdException('invalid_token', 'the ID token has no sub');
        }
        $userinfo ??= [];
        if (array_key_exists('sub', $userinfo) && $userinfo['sub'] !== $sub) {
            throw new NobleIdException('invalid_token', 'userinfo is for another subject');
        }
        $c = array_merge($idToken, $userinfo);
        $c['sub'] = $sub;

        $interests = [];
        $seen = [];
        foreach (is_array($c['research_interests'] ?? null) && array_is_list($c['research_interests']) ? $c['research_interests'] : [] as $item) {
            $t = self::text($item);
            if ($t !== null && !isset($seen[mb_strtolower($t)])) {
                $seen[mb_strtolower($t)] = true;
                $interests[] = $t;
            }
        }

        $affiliation = null;
        $main = $c['affiliation'] ?? null;
        if (is_array($main) && !array_is_list($main) && self::text($main['name'] ?? null) !== null) {
            $affiliation = ['name' => self::text($main['name']), 'ror' => self::ror($main['ror'] ?? null)];
        }

        $affiliations = [];
        $list = $c['affiliations'] ?? null;
        foreach (is_array($list) && array_is_list($list) ? $list : [] as $a) {
            if (!is_array($a) || self::text($a['organization'] ?? null) === null) {
                continue;
            }
            $affiliations[] = [
                'organization' => self::text($a['organization']),
                'role' => self::text($a['role'] ?? null),
                'start_year' => self::year($a['start_year'] ?? null),
                'ror' => self::ror($a['ror'] ?? null),
            ];
        }

        $email = self::text($c['email'] ?? null);
        $orcid = self::text($c['orcid'] ?? null);
        $updatedAt = $c['updated_at'] ?? null;

        return [
            'sub' => $sub,
            'nobleid' => self::text($c['nobleid'] ?? null),
            'nobleid_uri' => self::url($c['nobleid_uri'] ?? null, ['https']),
            'name' => self::text($c['name'] ?? null),
            'given_name' => self::text($c['given_name'] ?? null),
            'family_name' => self::text($c['family_name'] ?? null),
            'username' => self::text($c['preferred_username'] ?? null),
            'picture' => self::url($c['picture'] ?? null, ['https']),
            'website' => self::url($c['website'] ?? null, ['https', 'http']),
            'profile_url' => self::url($c['profile'] ?? null, ['https']),
            'research_interests' => $interests,
            'email' => $email,
            'email_verified' => $email !== null && ($c['email_verified'] ?? null) === true,
            'orcid' => ($c['orcid_verified'] ?? null) === true && $orcid !== null && preg_match(self::ORCID_URI, $orcid) === 1 ? $orcid : null,
            'affiliation' => $affiliation,
            'affiliations' => $affiliations,
            'identity_verified' => ($c['identity_verified'] ?? null) === true,
            'verified_researcher' => ($c['nobleid_verified_researcher'] ?? null) === true,
            'updated_at' => is_int($updatedAt) ? $updatedAt : null,
        ];
    }

    private static function text(mixed $v): ?string
    {
        return is_string($v) && trim($v) !== '' ? trim($v) : null;
    }

    /** @param list<string> $schemes */
    private static function url(mixed $v, array $schemes): ?string
    {
        $t = self::text($v);
        if ($t === null || preg_match('~\s~', $t) === 1) {
            return null;
        }
        $parts = parse_url($t);
        if (!is_array($parts) || !in_array($parts['scheme'] ?? '', $schemes, true) || ($parts['host'] ?? '') === '') {
            return null;
        }
        return $t;
    }

    private static function ror(mixed $v): ?string
    {
        $t = self::text($v);
        return $t !== null && preg_match(self::ROR_URI, $t) === 1 ? $t : null;
    }

    /** A four-digit year; servers before 27 Oct 2026 sent it as a string. */
    private static function year(mixed $v): ?int
    {
        if (is_int($v) && $v >= 1000 && $v <= 9999) {
            return $v;
        }
        if (is_string($v) && preg_match('~^\d{4}$~', trim($v)) === 1) {
            return (int) trim($v);
        }
        return null;
    }
}
