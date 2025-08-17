# Pentesting Notes: WayBackLister – Innovative Directory Bruteforcing Technique

**Source**: *WayBackLister: Innovative Directory Bruteforcing Technique*  
Author: Abhirup Konwar (System Weakness, May 21, 2025)  
Tool Author: [Anmol K Sachan](https://github.com/anmolksachan/wayBackLister)

---

## ⚠️ Disclaimer
For **educational and authorized pentesting only**. Use responsibly. You are solely responsible for your actions.

---

## ♻️ Tool Overview
- Uses the **Wayback Machine** to retrieve historical URLs for a domain.  
- Extracts **unique paths & endpoints**.  
- Checks for **exposed directory listings** on discovered endpoints.  
- Auto-discovers subdomains.  

---

## 📥 Installation

```bash
# Clone repository
git clone https://github.com/anmolksachan/wayBackLister.git
cd wayBackLister

# Install dependencies
pip install -r requirements.txt
```

Verify install:
```bash
python3 waybacklister.py -h
```

---

## ⚔️ Executing the Tool

Scan a single domain:
```bash
python3 waybacklister.py -d example.com
```

---

## ✅ Verify Directory Listing
Check results manually for open directory listings on discovered paths.

---

## 🎛️ Other Commands

Scan multiple domains from a file:
```bash
python3 waybacklister.py -f domains.txt
```

Auto-discover and scan subdomains (⚠️ feature not fully ready yet):
```bash
python3 waybacklister.py -auto redacted.com
```

Run with multiple threads:
```bash
python3 waybacklister.py -d redacted.com -t 10
```

---

## 💡 Tips
- Fuzz discovered paths against **IP addresses** collected via **Shodan, Censys, FOFA**.  
- Don’t report everything at once—prioritize findings.  
- Continuously monitor for **new IPs/subdomains** using a cronjob on a VPS.

---

## ⚡ How It Can Be Improved
- Add more URL sources beyond Wayback Machine (like [waymore](https://github.com/xnl-h4ck3r/waymore)):  
  - **commoncrawl**  
  - **alienvault**  
  - **urlscan** (note: rate-limited, may need proxies or header tricks).  

---

## 🔑 Key Takeaways
- WayBackLister provides a **smarter approach to directory bruteforcing** using historical data.  
- Can significantly **expand attack surface** with minimal effort.  
- Works best when integrated with other recon tools (Shodan, FOFA, Censys).  

---




# Pentesting Notes: Unlock the Full Potential of the Wayback Machine for Bug Bounties

**Source**: *Unlock the Full Potential of the Wayback Machine for Bug Bounties*  
Author: coffinxp — Bug Bounty Writeups / InfoSec Write-ups (2025)

---

## ⚠️ Disclaimer
Educational and authorized testing only. Do not use on targets without explicit permission.

---

## 🔎 Core Recon Commands

### 1. Extract URLs from Wayback Machine
```bash
# For a single domain
echo "example.com" | waybackurls > wayback.txt

# For multiple domains
cat domains.txt | waybackurls > all_wayback.txt
```

---

### 2. Filter Sensitive File Types
```bash
# Look for backup and database files
grep -Ei "\.zip|\.bak|\.sql|\.gz|\.tar|\.7z" wayback.txt

# Find exposed configuration files
grep -Ei "config|backup|db|admin" wayback.txt
```

---

### 3. Combine with gau (GetAllUrls)
```bash
# Gather historical + common crawl URLs
echo "example.com" | gau > gau.txt

# Merge with Wayback results
cat wayback.txt gau.txt | sort -u > merged_urls.txt
```

---

### 4. Probe Live Endpoints with httpx
```bash
# Basic probing
cat merged_urls.txt | httpx > live_urls.txt

# With extra details (IP, vhost, status code, tech stack)
cat merged_urls.txt | httpx -ip -sc -title -tech-detect -vhost > detailed_live_urls.txt
```

---

### 5. Parameter & Endpoint Hunting
```bash
# Extract only endpoints with parameters
grep "?" merged_urls.txt > params.txt

# Use gf patterns to filter interesting params (e.g., XSS, SSRF, LFI)
cat params.txt | gf xss > xss_params.txt
cat params.txt | gf ssrf > ssrf_params.txt
cat params.txt | gf lfi > lfi_params.txt
```

---

### 6. Content Discovery with hakrawler
```bash
# Crawl archived endpoints for hidden files
cat live_urls.txt | hakrawler -depth 2 -plain > crawled.txt
```

---

## 💡 Tips from the Article
- Always check **old parameters**; sometimes new WAFs ignore legacy query strings.  
- Archived **admin panels** or **forgotten endpoints** can still be active.  
- Prioritize high-value findings (API keys, backups, configs) instead of mass reporting.  

---

## 📚 Toolchain Recap
- **waybackurls** → Collect archived URLs  
- **gau** → Supplement with CommonCrawl & other sources  
- **httpx** → Check if endpoints are still live  
- **gf** → Filter for vulnerability patterns  
- **hakrawler** → Crawl archived endpoints for more files  

---

## ✅ Workflow Example
```bash
# One-liner combining everything
echo "example.com" | waybackurls | gau | sort -u \
  | httpx -silent -sc -title -tech-detect \
  | tee live_endpoints.txt
```

---

## 🔑 Key Takeaways
- The Wayback Machine is a **goldmine** for bug bounty recon.  
- Combining it with gau, httpx, gf, and hakrawler helps uncover:  
  - Forgotten endpoints  
  - Old parameters still vulnerable  
  - Exposed configs, backups, and sensitive files  
- The past often reveals what developers thought they’d hidden.

---
