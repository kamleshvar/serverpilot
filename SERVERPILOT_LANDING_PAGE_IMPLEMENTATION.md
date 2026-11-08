# ServerPilot Landing Page Implementation

## Summary

The ServerPilot public landing page was rebuilt as a cinematic TechOrigin / ServerPilot experience. The page now uses the real TechOrigin logo assets, a short branded intro, a responsive premium dark interface, truthful product copy, and real application routes.

No deployment, authentication, quota, or admin behavior was changed. The only Python change is the addition of template context values already available in application configuration.

## Brand Assets

Source assets were copied from the sibling TechOrigin project:

- `techorigin-logo-transparent.png`
- `techorigin-mark.png`

Generated from the mark for browser use:

- `favicon.png` (64 × 64)
- `apple-touch-icon.png` (180 × 180)

Destination: `serverpilot/static/images/brand/`

## Files Changed

| File | Change |
| --- | --- |
| `serverpilot/templates/public/landing.html` | Full landing page rewrite |
| `serverpilot/static/css/public.css` | Full public design system rewrite |
| `serverpilot/static/js/landing-head.js` | New synchronous intro/state bootstrap |
| `serverpilot/static/js/landing.js` | New intro, reveal, navigation, and scroll-spy behavior |
| `serverpilot/__init__.py` | Added `plan_limits`, OAuth, GitHub App, and Cloudflare flags to template context |
| `serverpilot/templates/auth/login.html` | TechOrigin branding, favicon, real home link |
| `serverpilot/templates/errors/error.html` | TechOrigin mark, favicon, real home link |
| `serverpilot/static/css/auth.css` | Palette aligned with the new public design system |
| `serverpilot/static/images/brand/*` | New brand assets |

## Landing Page Structure

1. Branded intro overlay
2. Sticky navigation with responsive mobile menu
3. Hero with deployment pipeline visualization
4. Product showcase using an illustrative browser-framed dashboard preview
5. Six capability cards mapped to implemented platform areas
6. Four-step “repository to live website” flow
7. Infrastructure architecture board with live integration configuration chips
8. Security and reliability list
9. Implemented free plan with backend quota values
10. Final call to action
11. Footer with only real routes and anchors

## Intro Behavior

- Runs for approximately 4.4 seconds.
- Scenes: TechOrigin logo → ServerPilot product reveal → dissolve.
- Has a visible **Skip intro** button and supports the `Escape` key.
- Skips automatically for:
  - `prefers-reduced-motion: reduce`
  - authenticated users
  - a browser session that has already seen the intro
- Stores completion in `sessionStorage` under `serverpilot-intro-seen`.
- Marks the page `inert` while the intro is active.
- Includes a 7-second JavaScript fallback in case the main script fails.
- Without JavaScript, the intro is hidden by CSS and the page remains visible.

## Responsive and Accessibility Notes

- Breakpoints cover 1080, 980, 900, 760, 680, 620, 520, and 440 pixels.
- Verified without horizontal document overflow at 1440, 1024, 820, 768, 414, 390, 360, and 320 pixels.
- Mobile navigation closes on link selection, outside click, `Escape`, and resize.
- Scroll spy highlights the active navigation item.
- Reveal animations are disabled for reduced-motion users.
- Focus-visible states are defined for buttons, navigation, providers, and skip controls.
- The landing page uses external scripts only, matching the CSP `script-src 'self'` policy.

## Backend Truthfulness

- Website slots, RAM, and storage limits are read from application configuration.
- Integration chips reflect the current deployment configuration:
  - Deployments: accepting/paused
  - GitHub App: configured/not configured
  - Cloudflare: configured/not configured
  - Google OAuth: configured/not configured
  - GitHub OAuth: configured/not configured
- The dashboard preview is explicitly labelled “Illustrative preview” and “Demo data”.
- Pricing describes only the implemented free plan. No paid plan is offered.
- Footer links point only to real anchors, `/healthz`, `/api/v1`, sign-in, and the operator console.

## Verification Performed

- `python -m pytest -q` → **52 passed**
- `python -m ruff check .` → **All checks passed**
- `node --check` on both new JavaScript files → passed
- HTTP 200 verification for:
  - `/`
  - `/auth/login`
  - `/healthz`
  - `/techorigin/login`
  - `/static/css/public.css`
  - `/static/js/landing-head.js`
  - `/static/js/landing.js`
  - brand logo and favicon assets
- Playwright visual checks at desktop, tablet, and mobile widths
- Intro brand/product scene screenshots
- Skip button, session-skip reload, and reduced-motion checks
- Simulated blocked `landing.js`; the 7-second fallback hid the intro and revealed all content
- Sign-in and 404 page screenshots
- No page JavaScript errors; the only 404 was the intentional unknown-route test

## Cleanup Performed

Removed generated and unwanted files from the project:

- all `__pycache__` directories
- `.pytest_cache`
- `.ruff_cache`
- generated `logs/*.log` files
- `instance/logs/serverpilot.log`
- `instance/migration-check.db`

Preserved:

- `.env`, `.env.example`, `.env.production`
- `secrets/github-app.pem`
- `instance/serverpilot-dev.db`
- runtime directories under `instance/`

## Running Locally

```powershell
python app.py
```

or:

```powershell
python -m flask --app app run --no-reload
```

Then open `http://127.0.0.1:5000/`.

## Notes

- GitHub App and Cloudflare are not configured in the current environment; the page reports that accurately.
- Google and GitHub OAuth are configured in the current environment.
- The intro can be replayed by clearing the `serverpilot-intro-seen` session storage key.
- The product preview is illustrative and does not represent live account data.
