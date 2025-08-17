# Pentesting Notes: Email Parsing Discrepancies Attack

Write-up: *Bypassing access controls using email address parsing discrepancies* — Y Mabsoute (May 26, 2025) ([medium.com](https://medium.com/%40y.mabsoute/bypassing-access-controls-using-email-address-parsing-discrepancies-9a8b265a746e?utm_source=chatgpt.com))

This is a PortSwigger Web Security Academy lab write-up, based on Gareth Heyes' *“Splitting the Email Atom”* research. ([medium.com](https://medium.com/%40y.mabsoute/bypassing-access-controls-using-email-address-parsing-discrepancies-9a8b265a746e?utm_source=chatgpt.com))

---

##  Key Techniques & Observations

### 1. **Quoted local-part escaping (RFC 2822 quirks)**
- `“@”@test.com` → parsed as `@test.com`
- `(test)user@(test2 )email.com` → parsed as `user@email.com`  
  ([medium.com](https://medium.com/%40y.mabsoute/bypassing-access-controls-using-email-address-parsing-discrepancies-9a8b265a746e?utm_source=chatgpt.com))

### 2. **UUCP / source-route syntax**
- `fakeDomain!user@\RealDomain.com` → backend may interpret as `user@\RealDomain.com@fakeDomain`
- Source-route chain example: `@a.edu,@m.edu:final@gmail.com`  
  ([medium.com](https://medium.com/%40y.mabsoute/bypassing-access-controls-using-email-address-parsing-discrepancies-9a8b265a746e?utm_source=chatgpt.com))

### 3. **Percent hack / source-route fallback**
- `Yassine%gmail.com@school.edu` → routed to `yassine@gmail.com`
- `%` becomes `@`, allowing bypass of domain restrictions  
  ([medium.com](https://medium.com/%40y.mabsoute/bypassing-access-controls-using-email-address-parsing-discrepancies-9a8b265a746e?utm_source=chatgpt.com))

### 4. **Encoded-word (RFC 2047)**
```text
=?utf-8?q?=41=42=43?=user@domain.net → ABCuser@domain.net
```
- Mix of Q-encoding and UTF-7 or Base64 in `encoded-word` constructs can bypass email validation  
  ([medium.com](https://medium.com/%40y.mabsoute/bypassing-access-controls-using-email-address-parsing-discrepancies-9a8b265a746e?utm_source=chatgpt.com))

#### ● **Q-Encoding + UTF-7 layers**
- Construct payload like:
  ```
  =?@example.com">utf-7?q?=65HQAZQBzAHQAbQBl-?=@example.com
  ```
  → decoded to `testme@example.com`

- Replace encoding type with `b` (base64) as needed  
  ([medium.com](https://medium.com/%40y.mabsoute/bypassing-access-controls-using-email-address-parsing-discrepancies-9a8b265a746e?utm_source=chatgpt.com))

### 5. **Exploitation Workflow in Lab**
**Methodology**: Probe → Observe → Encode → Exploit  
Attempt various encoded payloads on the registration form.

- Basic Q- and UTF-8 encoded attempts blocked.
- **UTF-7** encoding bypasses server validation when domain constraint is last (e.g., `...=@ginandjuice.shop`)  
- Full payload example:
  ```
  =?utf-7?q?attacker&AEA-[EXPLOIT_ID]&ACA-?=@ginandjuice.shop
  ```
  Allows confirmation email to `attacker@[EXPLOIT_ID]` while appearing valid.  
  ([portswigger.net](https://portswigger.net/research/splitting-the-email-atom?utm_source=chatgpt.com), [portswigger.net](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies?utm_source=chatgpt.com))

After registering:
- Log in as the new account
- Access the Admin panel
- Delete the user `carlos` to solve the lab  
  ([x.com](https://x.com/WebSecAcademy/status/1844683158551187706?utm_source=chatgpt.com), [portswigger.net](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies?utm_source=chatgpt.com))

---

##  Weaponizing Techniques from Related Research

Based on Gareth Heyes' *Splitting the Email Atom* concepts: ([portswigger.net](https://portswigger.net/research/splitting-the-email-atom?utm_source=chatgpt.com))

- **Advanced email parsing quirks**:
  - Special characters, quoted pairs, comments, UUCP, source routes, percent-hack—all useful for domain confusion attacks.
  - Unicode overflows (e.g., `String.fromCodePoint(0x100 + 0x40)` → `@`) can generate bypass chars.
  - Encoded-word, base64 + UTF-7 combination.
  - Punycode abuse (e.g., malformed punycode values to misroute email or achieve RCE).
- **Methodology & tooling**:
  - Use Turbo Intruder scripts to automate payload testing.
  - Build punycode fuzzers for malformed domain injection.

---

##  Key Takeaways

| Principle | Details |
|-----------|---------|
| **Don't trust email parsing** | Even valid `@example.com` domains can be spoofed. |
| **Email domain is not enough for auth** | Validation bypass allows unauthorized access. |
| **Defense is multi-layered** | Disable `encoded-word`, validate domain ownership, and don't use email as sole auth factor. ([i.blackhat.com](https://i.blackhat.com/BH-US-24/Presentations/US24-Heyes-Splitting-the-Email-Atom-Exploiting-Parsers-to-Bypass-Access-Controls-Wednesday.pdf?utm_source=chatgpt.com), [portswigger.net](https://portswigger.net/research/splitting-the-email-atom?utm_source=chatgpt.com), [x.com](https://x.com/PortSwigger/status/1848289191655792653?utm_source=chatgpt.com)) |

---

## References

- **Y. Mabsoute**, *Bypassing access controls using email address parsing discrepancies*, Medium, May 26, 2025. ([medium.com](https://medium.com/%40y.mabsoute/bypassing-access-controls-using-email-address-parsing-discrepancies-9a8b265a746e?utm_source=chatgpt.com))  
- PortSwigger Web Security Academy — Logic Flaws / Lab write-up. ([portswigger.net](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies?utm_source=chatgpt.com))  
- **Gareth Heyes**, *Splitting the Email Atom: Exploiting Parsers to Bypass Access Controls* (Black Hat / DEF CON). ([portswigger.net](https://portswigger.net/research/splitting-the-email-atom?utm_source=chatgpt.com))

---

**Usage Reminder**: This is educational—including sophisticated encodings and RFC manipulation. Only use against environments you have permission to test.
