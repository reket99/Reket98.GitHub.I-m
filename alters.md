# Pentesting Notes: AlterX Subdomain Wordlist Generator

**Source**: *AlterX Subdomain Wordlist Generator — How to expand Attack Surface for more vulnerabilities*  
Author: Abhirup Konwar (System Weakness, May 22, 2025)  
Tool: [ProjectDiscovery / alterx](https://github.com/projectdiscovery/alterx)

---

## ⚠️ Disclaimer
Educational and **authorized pentesting only**. Author and tool creators are not responsible for misuse.

---

## 📥 Installation (Direct Binary Download)

```bash
# Download AlterX release (Linux amd64 example)
wget -4 https://github.com/projectdiscovery/alterx/releases/download/v0.0.6/alterx_0.0.6_linux_amd64.zip

# Unzip
unzip alterx_0.0.6_linux_amd64.zip

# Copy/move binary to /usr/bin/
sudo cp alterx /usr/bin/

# Verify installation
ls /usr/bin/ | grep -i "alterx"
```

---

## 📕 Help Manual

```bash
alterx -h
```

---

## ⚔️ Core Commands

1️⃣ **Generate subdomain permutations for any domain**
```bash
echo "www.redacted.com" | alterx
```

2️⃣ **Save output into a file**
```bash
echo "www.redacted.com" | alterx > alterx_nasa.txt
```

3️⃣ **Generate permutations from previously discovered subs (e.g. with subfinder)**
```bash
# Discover subs first
subfinder -d redacted.com -all -recursive > subfinder_domain.txt

# Feed into AlterX
cat subfinder_domain.txt | alterx > alterx2_nasa.txt
```

4️⃣ **Change the default AlterX pattern**

Hyphen pattern:
```bash
cat subfinder_nasa.txt | alterx -enrich -p '{{word}}-{{suffix}}' > alterx_pattern1_nasa.txt
```

Underscore pattern:
```bash
cat subfinder_nasa.txt | alterx -enrich -p '{{word}}_{{suffix}}' > alterx_pattern2_nasa.txt
```

5️⃣ **Use httpx to probe live subdomains**

Basic:
```bash
cat sub-file-name.txt | httpx > live_subs_domain.txt
```

With additional detection (IP, vhost, status code, tech stack):
```bash
cat sub-file-name.txt | httpx -ip -vhost -sc -td > live_subs_domain_detailed.txt
```

---

## 💡 Tips

- Understand the **target’s subdomain naming convention** before choosing patterns.  
- Use enrichment (`-enrich`) to extract contextual words (e.g., staging, qa, dev).  
- Running at scale may take hours/days — recommended to use a **VPS** for heavy wordlist generation and probing.

---

## 🧩 Community Notes (from comments)

- Combine with `dnsx` and `shuffledns` for resolution workflows:
```bash
subfinder -d domain -all | dnsx -r

# If you see Akamai or Cloudflare → update resolvers and retry
subfinder -d domain -all | alterx > list.txt
shuffledns -l list.txt -r resolvers.txt -mode resolve
```

---

## ✅ Key Takeaways

- AlterX extends **attack surface discovery** by generating intelligent permutations.  
- Integrates seamlessly with **subfinder**, **httpx**, **dnsx**, and **shuffledns**.  
- Customizable patterns (`-p`) make it adaptable to naming conventions.  
- Faster, more flexible than static wordlists.

---
