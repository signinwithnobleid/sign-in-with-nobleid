package nobleid

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Profile is a plain profile built from NobleID's claims, for filling your
// own app's profile. An empty string, nil, an empty slice or false means
// the person did not share the value or NobleID does not know it.
//
// Fill only empty fields with it, and never overwrite what the person
// edited in your app (docs/profile-data.md).
type Profile struct {
	// Subject is the stable account key. Key your accounts on it.
	Subject    string `json:"sub"`
	NobleID    string `json:"nobleid"`
	NobleIDURI string `json:"nobleid_uri"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	// Username is preferred_username: a suggestion only; it can change.
	Username string `json:"username"`
	// Picture is an https URL, or empty.
	Picture string `json:"picture"`
	// Website is an http or https URL, or empty.
	Website string `json:"website"`
	// ProfileURL is the public NobleID profile page; empty when the profile is not public.
	ProfileURL        string   `json:"profile_url"`
	ResearchInterests []string `json:"research_interests"`
	Email             string   `json:"email"`
	// EmailVerified: link to an existing account by email only when true.
	EmailVerified bool `json:"email_verified"`
	// ORCID is https://orcid.org/..., set only when NobleID marked it proven through ORCID.
	ORCID string `json:"orcid"`
	// Affiliation is the main affiliation as the person entered it. Not checked by NobleID.
	Affiliation *ProfileAffiliation `json:"affiliation"`
	// Affiliations: the main one first. Self-asserted.
	Affiliations       []ProfileAffiliationEntry `json:"affiliations"`
	IdentityVerified   bool                      `json:"identity_verified"`
	VerifiedResearcher bool                      `json:"verified_researcher"`
	// UpdatedAt is Unix seconds of the last NobleID profile change; 0 when unknown.
	UpdatedAt int64 `json:"updated_at"`
}

// ProfileAffiliation is the main affiliation. ROR is an https://ror.org/ URL or empty.
type ProfileAffiliation struct {
	Name string `json:"name"`
	ROR  string `json:"ror"`
}

// ProfileAffiliationEntry is one entry of the affiliations list. StartYear is 0 when unknown.
type ProfileAffiliationEntry struct {
	Organization string `json:"organization"`
	Role         string `json:"role"`
	StartYear    int    `json:"start_year"`
	ROR          string `json:"ror"`
}

var (
	orcidURI = regexp.MustCompile(`^https://orcid\.org/\d{4}-\d{4}-\d{4}-\d{3}[\dX]$`)
	rorURI   = regexp.MustCompile(`^https://ror\.org/0[a-hj-km-np-tv-z0-9]{6}\d{2}$`)
	fourDigs = regexp.MustCompile(`^\d{4}$`)
)

func claimText(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func claimURL(v any, schemes ...string) string {
	t := claimText(v)
	if t == "" || strings.ContainsAny(t, " \t\r\n") {
		return ""
	}
	u, err := url.Parse(t)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	for _, s := range schemes {
		if u.Scheme == s {
			return t
		}
	}
	return ""
}

func claimROR(v any) string {
	if t := claimText(v); rorURI.MatchString(t) {
		return t
	}
	return ""
}

// claimYear accepts a four-digit number, or (servers before 27 Oct 2026)
// a four-digit string.
func claimYear(v any) int {
	switch y := v.(type) {
	case float64:
		if y == float64(int(y)) && y >= 1000 && y <= 9999 {
			return int(y)
		}
	case json.Number:
		if n, err := y.Int64(); err == nil && n >= 1000 && n <= 9999 {
			return int(n)
		}
	case string:
		if t := strings.TrimSpace(y); fourDigs.MatchString(t) {
			n, _ := strconv.Atoi(t)
			return n
		}
	}
	return 0
}

func claimTrue(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

// ProfileFromClaims builds a Profile from the verified ID token claims
// (Claims.Raw) and, optionally, the userinfo response for the same sub
// (nil to skip). Userinfo wins where both carry a claim: it is fresher and
// has more. It returns an *Error with Code "invalid_token" when the ID
// token has no sub or userinfo is for another subject.
func ProfileFromClaims(idToken, userinfo map[string]any) (*Profile, error) {
	sub := claimText(idToken["sub"])
	if sub == "" {
		return nil, newErr("invalid_token", "the ID token has no sub")
	}
	if v, ok := userinfo["sub"]; ok {
		if s, _ := v.(string); s != sub {
			return nil, newErr("invalid_token", "userinfo is for another subject")
		}
	}
	c := make(map[string]any, len(idToken)+len(userinfo))
	for k, v := range idToken {
		c[k] = v
	}
	for k, v := range userinfo {
		c[k] = v
	}

	p := &Profile{
		Subject:            sub,
		NobleID:            claimText(c["nobleid"]),
		NobleIDURI:         claimURL(c["nobleid_uri"], "https"),
		Name:               claimText(c["name"]),
		GivenName:          claimText(c["given_name"]),
		FamilyName:         claimText(c["family_name"]),
		Username:           claimText(c["preferred_username"]),
		Picture:            claimURL(c["picture"], "https"),
		Website:            claimURL(c["website"], "https", "http"),
		ProfileURL:         claimURL(c["profile"], "https"),
		ResearchInterests:  []string{},
		Email:              claimText(c["email"]),
		Affiliations:       []ProfileAffiliationEntry{},
		IdentityVerified:   claimTrue(c["identity_verified"]),
		VerifiedResearcher: claimTrue(c["nobleid_verified_researcher"]),
	}
	p.EmailVerified = p.Email != "" && claimTrue(c["email_verified"])
	if o := claimText(c["orcid"]); claimTrue(c["orcid_verified"]) && orcidURI.MatchString(o) {
		p.ORCID = o
	}
	seen := map[string]bool{}
	if list, ok := c["research_interests"].([]any); ok {
		for _, item := range list {
			t := claimText(item)
			if t != "" && !seen[strings.ToLower(t)] {
				seen[strings.ToLower(t)] = true
				p.ResearchInterests = append(p.ResearchInterests, t)
			}
		}
	}
	if m, ok := c["affiliation"].(map[string]any); ok && claimText(m["name"]) != "" {
		p.Affiliation = &ProfileAffiliation{Name: claimText(m["name"]), ROR: claimROR(m["ror"])}
	}
	if list, ok := c["affiliations"].([]any); ok {
		for _, item := range list {
			m, ok := item.(map[string]any)
			if !ok || claimText(m["organization"]) == "" {
				continue
			}
			p.Affiliations = append(p.Affiliations, ProfileAffiliationEntry{
				Organization: claimText(m["organization"]),
				Role:         claimText(m["role"]),
				StartYear:    claimYear(m["start_year"]),
				ROR:          claimROR(m["ror"]),
			})
		}
	}
	if f, ok := c["updated_at"].(float64); ok && f == float64(int64(f)) {
		p.UpdatedAt = int64(f)
	}
	return p, nil
}
