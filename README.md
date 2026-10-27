# ORBIT — OSINT Workbench

A static, browser-native OSINT console for authorized reconnaissance. Enter a domain, IP, username, email, or URL and ORBIT fans out across public, CORS-enabled sources, then assembles a structured evidence report.

**No backend. No build step. No target database.** Queries run directly from the browser to the providers listed below. Reports stay in memory until you download them; the run log is stored in `localStorage` on your device.

## Features

- **Domain / URL** — DNS over HTTPS (A, AAAA, CNAME, MX, TXT, NS, CAA, SOA), RDAP registration, certificate-transparency subdomain discovery, mail authentication posture, IP enrichment, and Wayback history.
- **IP** — geolocation/ASN, RDAP network registration, Shodan InternetDB exposure, and reverse DNS.
- **Username** — public profile sweep across GitHub, GitLab, Keybase, Hacker News, dev.to, and Codeberg.
- **Email** — Gravatar profile lookup, domain mail posture, and public GitHub commit association.
- **URL anatomy** — scheme, host, path, query parameters, punycode/shortener/credential/tracking checks.
- **Evidence handling** — each provider card shows its source and, where available, the raw JSON; export a Markdown report or full JSON.
- **Local run log** — re-run recent targets without sending history to a server.
- **Manual type override** — click the `AUTO` pill in the search bar to force a target type (`@handle` also forces username detection).

## Quick start

```bash
cd orbit-osint
npm run dev
```

Open `http://localhost:4173`. There are no dependencies to install; the dev server uses Node's built-in HTTP module.

Other commands:

```bash
npm run check   # syntax-check all browser modules
npm test        # run dependency-free unit tests
npm start       # same as npm run dev
```

## Deploy to GitHub Pages

1. Create a new GitHub repository and push this directory.
2. In the repository, open **Settings → Pages**.
3. Set **Source** to **GitHub Actions**.
4. Push to `main`. The included workflow in `.github/workflows/pages.yml` runs syntax checks and unit tests, then publishes `index.html` and `assets/` to Pages.

The site uses relative asset paths, so it works from `https://<user>.github.io/<repo>/` without configuration.

If you prefer branch-based Pages deployment instead, set **Source** to **Deploy from a branch**, choose `main` and `/ (root)`, and skip the workflow.

## Optional settings

Open the gear icon in the header.

- **GitHub token** — raises the unauthenticated GitHub API limit (60 requests/hour per IP). A fine-grained token with public read access is enough. It is stored only in this browser's `localStorage` and sent only to `api.github.com`.
- **Expand raw data** — opens each card's provider JSON by default.

## Data sources

| Source | Used for |
| --- | --- |
| Cloudflare DNS over HTTPS | DNS records and reverse PTR |
| RDAP (rdap.org, IANA bootstrap fallback) | Domain and IP network registration |
| crt.sh (CertSpotter fallback) | Certificate transparency and subdomain discovery |
| Shodan InternetDB | Observed ports, hostnames, tags, CVEs |
| ipwho.is | IP geolocation, ASN, organization |
| GitHub API | Profiles, public commit author search |
| GitLab, Keybase, Hacker News, dev.to, Codeberg | Public profile discovery |
| Gravatar | Public profile linked to an email hash |
| Wayback Machine | Closest archived snapshot |

ORBIT does not query breach databases, paid identity-resolution services, or any source that requires a server-side secret. The Have I Been Pwned link in email results is a manual pivot.

## Limitations and safety

- Public records can be incomplete, stale, or self-declared. A missing record is **not** proof that something does not exist.
- Certificate transparency tries crt.sh first and falls back to CertSpotter when crt.sh is unavailable or blocks the browser request.
- Some providers rate-limit or block browser-origin requests. ORBIT labels failed sources instead of hiding them.
- CORS restricts arbitrary page fetching. ORBIT does not fetch arbitrary target pages; use the pivot links for page-level review.
- No active scanning, exploitation, brute force, or authentication bypass is performed.
- Use only against assets you own or have explicit written permission to investigate. You are responsible for lawful use.

## Project structure

```text
index.html                  Single-page UI
assets/app.js               UI state, rendering, exports, local storage
assets/modules.js           Lookup orchestration and provider adapters
assets/api.js               Fetch wrapper, timeouts, error normalization
assets/report.js            Markdown report generation
assets/md5.js               Gravatar email hashing
assets/styles.css           Dark console theme and responsive layout
tests/unit.test.mjs         Detection, normalization, hash, and export tests
scripts/serve.mjs           Dependency-free local static server
.github/workflows/pages.yml GitHub Pages deployment
.gitignore                  Local and build artifacts
```

## Roadmap ideas

- Optional encrypted provider-proxy for sources that do not expose CORS (e.g. URLhaus).
- Shodan/Censys API-key mode with explicit local storage warnings.
- Diff two runs for a target and highlight newly observed hosts/ports.
- Saved case files with evidence timestamps and notes.
- Public-suffix-aware domain parsing via a bundled PSL snapshot.
