# Contributing to Honeypot XRPL

Thank you for your interest — contributions are genuinely welcome.

## How contribution works here

Honeypot XRPL has a single maintainer (@Krypto-Whitehat). **Nothing lands in `main` without maintainer review.** `main` is branch-protected: direct pushes by contributors are impossible, and every change arrives as a fork + pull request that the maintainer reviews and merges.

1. **Fork** the repository.
2. Create a **branch** for your change.
3. Keep changes focused (one feature or fix per PR).
4. Run `npm test` locally — the suite must stay green.
5. Open a **pull request**. Explain what it does and why.

Issues are open to everyone: bug reports, false-positive reports, feature ideas.

## Good starting points

- **Globe view** — the current globe is rough; rendering and interaction improvements are a known open area.
- **Node geolocation** — geolocating actors shown on the globe (e.g. via optional, privacy-preserving hints) is a welcome contribution.
- Detection heuristics with testable false-positive guards.

## Ground rules

- **Never commit credentials or bait material.** `bait.json`, wallet seeds, tokens and any honeypot-internal data must stay out of the repository — they are what makes the honeypot safe to run.
- **No detection-evasion details in public issues.** If you found a way to bypass or abuse the detection, open an issue without the details (or DM @Krypto-Whitehat on X) and ask for a private channel.
- Findings here are **heuristics, not proof of guilt** — keep claims honest, including limits.
- Address masking gates (`isFullShownAddr` / `displayFindingAddr`) must never be removed or bypassed.

## Live verification

A PR is accepted when the full test suite passes and the change is verified against the live site. Expect review feedback — that is the point of open contribution, not a barrier.
