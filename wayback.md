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
