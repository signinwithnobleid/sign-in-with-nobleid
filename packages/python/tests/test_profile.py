"""profile_from_claims against the shared cases in test/profile-vectors.json
(the kit's root), which every helper's tests also read.

    python -B -m unittest discover -s tests
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nobleid_signin import NobleIdError, profile_from_claims  # noqa: E402

VECTORS = os.path.join(os.path.dirname(__file__), "..", "..", "..", "test", "profile-vectors.json")
with open(VECTORS, encoding="utf-8") as f:
    CASES = json.load(f)["cases"]


class ProfileFromClaims(unittest.TestCase):
    def test_shared_cases(self):
        for case in CASES:
            with self.subTest(case["name"]):
                if "error" in case:
                    with self.assertRaises(NobleIdError) as e:
                        profile_from_claims(case["id_token"], case.get("userinfo"))
                    self.assertEqual(e.exception.code, case["error"])
                else:
                    self.assertEqual(profile_from_claims(case["id_token"], case.get("userinfo")), case["profile"])

    def test_inputs_are_not_changed(self):
        case = CASES[0]
        before = copy.deepcopy((case["id_token"], case["userinfo"]))
        profile_from_claims(case["id_token"], case["userinfo"])
        self.assertEqual((case["id_token"], case["userinfo"]), before)

    def test_booleans_are_not_years_or_timestamps(self):
        p = profile_from_claims({"sub": "u", "updated_at": True}, {"sub": "u", "affiliations": [{"organization": "X", "start_year": True}]})
        self.assertIsNone(p["updated_at"])
        self.assertIsNone(p["affiliations"][0]["start_year"])


if __name__ == "__main__":
    unittest.main()
