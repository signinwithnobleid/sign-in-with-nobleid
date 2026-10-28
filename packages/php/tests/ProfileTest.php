<?php

declare(strict_types=1);

/*
 * Profile::fromClaims against the shared cases in test/profile-vectors.json
 * (the kit's root), which every helper's tests also read. No dependencies:
 *
 *     php tests/ProfileTest.php
 */

require __DIR__ . '/../src/NobleIdException.php';
require __DIR__ . '/../src/Profile.php';

use NobleId\SignIn\NobleIdException;
use NobleId\SignIn\Profile;

$cases = json_decode(file_get_contents(__DIR__ . '/../../../test/profile-vectors.json'), true, 512, JSON_THROW_ON_ERROR)['cases'];
$failed = 0;
foreach ($cases as $case) {
    try {
        $got = Profile::fromClaims($case['id_token'], $case['userinfo'] ?? null);
        $ok = !isset($case['error']) && $got === $case['profile'];
        if (!$ok && !isset($case['error'])) {
            fwrite(STDERR, "got:  " . json_encode($got) . "\nwant: " . json_encode($case['profile']) . "\n");
        }
    } catch (NobleIdException $e) {
        $ok = isset($case['error']) && $e->error === $case['error'];
    }
    echo ($ok ? 'ok   ' : 'FAIL ') . $case['name'] . "\n";
    $failed += $ok ? 0 : 1;
}
echo $failed === 0 ? "all " . count($cases) . " passed\n" : "$failed failed\n";
exit($failed === 0 ? 0 : 1);
