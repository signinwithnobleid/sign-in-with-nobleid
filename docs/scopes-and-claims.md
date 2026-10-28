# Scopes and claims

Ask for the scopes you need. The person sees each one on the consent screen
and can untick any of them except `openid`, so the `scope` in the token
response can be narrower than what you asked for. Always read it.

| Scope | Covers | Claims | Where |
|---|---|---|---|
| `openid` | Who the person is on NobleID. Required; cannot be unticked | `sub`, `nobleid`, `nobleid_uri` | ID token, userinfo |
| `profile` | Profile details, and how complete the NobleID profile is | `name`, `given_name`, `family_name`, `preferred_username`, `profile`, `picture`, `website`, `identity_verified`, `nobleid_verified_researcher`, `updated_at`, `profile_complete`, `verification_level` | ID token, userinfo |
| | | `research_interests` | userinfo only |
| `email` | Email address | `email`, `email_verified` | ID token, userinfo |
| `orcid` | The person's ORCID iD, only when they connected it through ORCID's own sign-in | `orcid`, `orcid_verified` | ID token, userinfo |
| `affiliations` | Self-described affiliations | `affiliation` (the primary one) | ID token, userinfo |
| | | `affiliations` (all of them) | userinfo only |
| `works` | The works the person registered on NobleID (titles, ARK identifiers, DOIs, dates) and how many NobleID confirmed them as an author of | `works_count`, `works_endpoint`, `verified_authorship_count` | userinfo only |
| `offline_access` | Keep access while the person is away | a refresh token | token response |

`offline_access` is not pre-ticked. You get a refresh token only if you asked
for it **and** the person left it ticked.

## Claim reference

| Claim | Type | Meaning |
|---|---|---|
| `sub` | string | Stable, opaque identifier for this person. **Key your accounts on it.** |
| `nobleid` | string | The person's NobleID, e.g. `NI0P88W05R71S46`. Public. |
| `nobleid_uri` | string | `https://www.nobleid.org/<nobleid>`, their public profile. |
| `name`, `given_name`, `family_name` | string | As entered by the person. |
| `preferred_username` | string | Display handle. Can change; not an identifier. |
| `profile` | string (URL) | The public NobleID profile page. Absent when the person's profile is not public. |
| `picture` | string (URL) | Avatar. Always `https`. |
| `website` | string (URL) | Personal site. `http` or `https`; NobleID adds `https://` to a bare host and leaves anything else out. |
| `research_interests` | string[] | Self-described interests. Trimmed, no empty or duplicate entries. |
| `identity_verified` | boolean | NobleID checked a government-issued ID for this person. |
| `nobleid_verified_researcher` | boolean | A badge granted by NobleID staff. |
| `updated_at` | number | Unix seconds of the last profile change. |
| `profile_complete` | boolean | The person's NobleID profile is complete. See [complete profiles](#complete-profiles). |
| `verification_level` | string | One of `"profile"`, `"orcid"`, `"authorship"`, in increasing order: a complete profile; plus an ORCID iD proven through ORCID's own sign-in; plus at least one authorship NobleID confirmed. `"incomplete"` can appear only in an ID token issued on refresh. **Not an identity check**: use `identity_verified` for that. Compare by the order above, and do not assume no other value will ever appear. |
| `email` | string | The person's email address. |
| `email_verified` | boolean | `true` only if the address was confirmed: through a confirmation link, or because a sign-in provider vouched for that same address. |
| `orcid` | string | Full URI, `https://orcid.org/0000-0000-0000-0000`. Present only when connected through ORCID's own sign-in. |
| `orcid_verified` | `true` | Sent with `orcid`. Absent when `orcid` is absent. |
| `affiliation` | object | `{ "name": …, "ror": … }`: the primary affiliation as the person entered it. `ror` (a `https://ror.org/…` URL) only when they chose one. **Self-declared, not verified.** |
| `affiliations` | object[] | `{ organization, role?, start_year?, ror? }`, the primary affiliation first (the same one as `affiliation`). `start_year` is a four-digit number (a string on servers before 27 Oct 2026); `ror` is an `https://ror.org/…` URL. Fields with no value are absent. **Self-asserted. Nothing about affiliations is verified.** |
| `works_count` | number | Works the person registered on NobleID. |
| `works_endpoint` | string | URL of the works list (below). |
| `verified_authorship_count` | number | Works where NobleID confirmed this person is an author. Only confirmed authorships count. |
| `amr` | string[] | ID token from sign-in only. How the person authenticated, e.g. `["pwd"]`, `["pwd","otp","mfa"]`. Contains `"otp"` when a second factor was used. Omitted when unknown. |
| `auth_time` | number | ID token from sign-in only. When the person last authenticated. |

There is no `acr` claim. To require a second factor, check that `amr`
contains `"otp"`.

Absent means "not granted or not known". It never means `false`. A claim
with no value is left out: NobleID never sends `null` or an empty string.

To fill your own app's profile from these claims without overwriting what
people edit, see [Fill your app's profile from NobleID](profile-data.md).
Every helper has a `profileFromClaims` function for it.

## What NobleID can and cannot tell you

| Question | Answer from NobleID | Claim |
|---|---|---|
| Is this the same person as last time? | Yes, reliably | `sub` |
| Did they confirm this email address? | Yes | `email_verified` |
| Did NobleID check a government-issued ID? | Yes | `identity_verified` |
| Do they own this ORCID iD? | Yes, when they connected it through ORCID's sign-in; otherwise you get nothing | `orcid`, `orcid_verified` |
| Did NobleID staff badge them as a researcher? | Yes | `nobleid_verified_researcher` |
| How many works did they register on NobleID? | Yes (a count, plus the list) | `works_count`, `/oauth/works` |
| On how many works did NobleID confirm their authorship? | Yes | `verified_authorship_count` |
| Did they use a second factor this time? | Yes, when known | `amr` contains `"otp"` |
| Do they work where they say they work? | **No.** Affiliations are self-asserted | `affiliations` |
| Are they an author of a work outside NobleID? | **No** | — |
| Is their NobleID profile complete? | Yes | `profile_complete` |
| A single summary level? | Yes (not an identity check) | `verification_level` |
| Their phone number or postal address? | **No**, not available through sign-in | — |

## Works list

`GET {issuer}/oauth/works?limit=1..100&offset=0..` with
`Authorization: Bearer <access token>`; needs the `works` scope (otherwise
`403 insufficient_scope`). `limit` defaults to 50.

```json
{
  "sub": "…", "total": 2, "limit": 50, "offset": 0,
  "works": [
    {
      "nobleid": "NI…", "ark": "ark:/48914/…", "url": "https://nobleid.org/ark:/48914/…",
      "title": "…", "type": "article", "doi": "10.…", "publication_date": "2025-03-14",
      "publication_year": 2025, "version": 1, "registered_at": "2025-03-20T10:00:00Z"
    }
  ]
}
```

ARK identifiers use NAAN `48914`. `doi` and dates may be `null`.

## Account linking

- Key accounts on `sub`. Never on `email`, `preferred_username` or `name`.
- Link to an existing account by email only when `email_verified` is `true`,
  and prefer asking the person to confirm the link while signed in to both.
- Use `orcid` only when it is present (it is then verified). Never infer an
  ORCID iD from anything else.
- Treat `affiliation` and `affiliations` as the person's own statement.

## Complete profiles

NobleID signs a person in to an app only when their NobleID profile is
complete and nothing holds the account back. If it is not, NobleID asks them
to complete it before it returns them to your app; your app sees nothing
until then. With `prompt=none` you get `error=interaction_required` instead.

A sign-in therefore always carries `profile_complete: true` (with the
`profile` scope). An ID token issued later, on refresh, reports the profile
as it is then.

See also the [roadmap](roadmap.md).
