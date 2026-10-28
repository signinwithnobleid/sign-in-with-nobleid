# Security policy

## Reporting a vulnerability

Email **info@nobleid.org**. NobleID's current contact details are in
https://www.nobleid.org/.well-known/security.txt; check it for the latest.

Please include what you found, how to reproduce it, and what an attacker
could do with it. Do not open a public issue for a vulnerability.

## In scope

- Everything in this repository: the browser SDK, the helper packages, the
  examples, the mock provider and the documentation (for example, advice
  that would lead integrators into an insecure setup).
- The Sign in with NobleID protocol endpoints listed in
  `https://id.nobleid.org/.well-known/openid-configuration`, and the
  consent page at `https://www.nobleid.org/oauth/authorize`.

## Out of scope / not allowed

- Denial-of-service or load testing, and anything that degrades the service
  for others.
- Testing against accounts or data that are not yours. Use your own NobleID
  account and your own registered apps.
- Social engineering, phishing, or physical attacks against NobleID staff or
  users.
- Automated scanning that generates large volumes of traffic.
- Reports that only say a rate limit exists or that a client id is public.

## Safe harbour

If you act in good faith, stay within the rules above, avoid privacy
violations and service disruption, and give us reasonable time to fix an
issue before disclosing it, we will not pursue or support legal action
against you for your research.

## Credentials

Never commit real credentials to this repository or to issues: no client
secrets (`nbcs_…`), access tokens (`nbat_…`), refresh tokens (`nbrt_…`) or
authorization codes (`nbac_…`). The values in this repository are fake and
work only with the local mock. If you leak a real secret, rotate it in the
NobleID dashboard and tick "Stop accepting the current secret now", so the
old one stops working at once.
