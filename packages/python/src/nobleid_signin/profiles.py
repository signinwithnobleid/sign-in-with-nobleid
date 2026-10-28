"""A plain profile from NobleID's claims, for filling your own app's profile.

Standard library only. ``profile_from_claims`` takes the verified ID token
claims and, optionally, the userinfo response for the same ``sub``, and
returns a dict whose keys are always present: ``None``, ``[]`` or ``False``
when the person did not share a value or NobleID does not know it.

See docs/profile-data.md: fill only empty fields with it, and never
overwrite what the person edited in your app.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlsplit

__all__ = ["profile_from_claims"]

_ORCID_URI = re.compile(r"https://orcid\.org/\d{4}-\d{4}-\d{4}-\d{3}[\dX]")
_ROR_URI = re.compile(r"https://ror\.org/0[a-hj-km-np-tv-z0-9]{6}\d{2}")


def _text(v: Any) -> Optional[str]:
    return v.strip() if isinstance(v, str) and v.strip() else None


def _url(v: Any, schemes: tuple) -> Optional[str]:
    t = _text(v)
    if t is None or any(c.isspace() for c in t):
        return None
    try:
        parts = urlsplit(t)
    except ValueError:
        return None
    return t if parts.scheme in schemes and parts.hostname else None


def _ror(v: Any) -> Optional[str]:
    t = _text(v)
    return t if t is not None and _ROR_URI.fullmatch(t) else None


def _year(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int) and 1000 <= v <= 9999:
        return v
    # Servers before 27 Oct 2026 sent start_year as a string.
    if isinstance(v, str) and re.fullmatch(r"\d{4}", v.strip()):
        return int(v.strip())
    return None


def _true(v: Any) -> bool:
    return v is True


def profile_from_claims(id_token: Mapping[str, Any], userinfo: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Build the normalised profile. Userinfo wins where both carry a claim
    (it is fresher and has more). Raises ``NobleIdError("invalid_token")``
    when the ID token has no ``sub`` or userinfo is for another subject.

    ``orcid`` is set only when NobleID marked it proven through ORCID;
    ``picture`` only when https; ``website`` only when http(s). Affiliations
    are what the person entered, not checked by NobleID.
    """
    from . import NobleIdError  # the package's error type

    id_token = id_token if isinstance(id_token, Mapping) else {}
    sub = _text(id_token.get("sub"))
    if sub is None:
        raise NobleIdError("invalid_token", "the ID token has no sub")
    ui = userinfo if isinstance(userinfo, Mapping) else {}
    if "sub" in ui and ui["sub"] != sub:
        raise NobleIdError("invalid_token", "userinfo is for another subject")
    c: Dict[str, Any] = {**id_token, **ui, "sub": sub}

    interests: List[str] = []
    seen = set()
    raw_interests = c.get("research_interests")
    for item in raw_interests if isinstance(raw_interests, list) else []:
        t = _text(item)
        if t is not None and t.lower() not in seen:
            seen.add(t.lower())
            interests.append(t)

    main = c.get("affiliation")
    affiliation = None
    if isinstance(main, Mapping) and _text(main.get("name")) is not None:
        affiliation = {"name": _text(main.get("name")), "ror": _ror(main.get("ror"))}

    affiliations = []
    raw_affiliations = c.get("affiliations")
    for a in raw_affiliations if isinstance(raw_affiliations, list) else []:
        if isinstance(a, Mapping) and _text(a.get("organization")) is not None:
            affiliations.append({
                "organization": _text(a.get("organization")),
                "role": _text(a.get("role")),
                "start_year": _year(a.get("start_year")),
                "ror": _ror(a.get("ror")),
            })

    email = _text(c.get("email"))
    orcid = _text(c.get("orcid"))
    updated_at = c.get("updated_at")
    return {
        "sub": sub,
        "nobleid": _text(c.get("nobleid")),
        "nobleid_uri": _url(c.get("nobleid_uri"), ("https",)),
        "name": _text(c.get("name")),
        "given_name": _text(c.get("given_name")),
        "family_name": _text(c.get("family_name")),
        "username": _text(c.get("preferred_username")),
        "picture": _url(c.get("picture"), ("https",)),
        "website": _url(c.get("website"), ("https", "http")),
        "profile_url": _url(c.get("profile"), ("https",)),
        "research_interests": interests,
        "email": email,
        "email_verified": email is not None and _true(c.get("email_verified")),
        "orcid": orcid if _true(c.get("orcid_verified")) and orcid is not None and _ORCID_URI.fullmatch(orcid) else None,
        "affiliation": affiliation,
        "affiliations": affiliations,
        "identity_verified": _true(c.get("identity_verified")),
        "verified_researcher": _true(c.get("nobleid_verified_researcher")),
        "updated_at": updated_at if isinstance(updated_at, int) and not isinstance(updated_at, bool) else None,
    }
