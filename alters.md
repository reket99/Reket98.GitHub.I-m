# Pentesting Notes: AlterX Subdomain Wordlist Generator

**Article**: *Alterx Subdomain Wordlist Generator* by Abhirup Konwar (System Weakness, May 22, 2025) :contentReference[oaicite:1]{index=1}

---

##  Overview

- AlterX is a fast, customizable subdomain wordlist generator that uses a DSL (domain-specific language) rather than hardcoded patterns. It was developed by ProjectDiscovery — the same team behind **subfinder**. :contentReference[oaicite:2]{index=2}
- It fits into active enumeration pipelines by deriving permutations from known passive subdomain results, significantly improving efficiency and success rate. :contentReference[oaicite:3]{index=3}

---

##  Key Features & Options

###  Input & Output
- Accepts subdomain lists via:
  - `-l`, `--list` (stdin, comma-separated, or file)
- Outputs include:
  - `-o`, `--output` (write to file)
  - `-es`, `--estimate` (predict count without generating)
  - `-ms`, `--max-size` (limit export size)
  - `-v`, `--verbose` and `--silent`
  - `-version`, `-update`, `--disable-update-check` flags :contentReference[oaicite:4]{index=4}

###  DSL-Based Patterns & Variables
AlterX uses customizable variables similar to Nuclei templates:
- **Basic Variables**:
  - `{{sub}}`, `{{suffix}}`, `{{tld}}`, `{{etld}}`
- **Advanced Variables**:
  - `{{sld}}`, `{{root}}`, `{{sub1}}`, `{{sub2}}` :contentReference[oaicite:5]{index=5}

###  Pattern Examples
Given `api.scanme.sh` and `word = prod`:
```
"{{sub}}-{{word}}.{{suffix}}"   → api-prod.scanme.sh
"{{word}}-{{sub}}.{{suffix}}"   → prod-api.scanme.sh
"{{word}}.{{sub}}.{{suffix}}"   → prod.api.scanme.sh
"{{sub}}.{{word}}.{{suffix}}"   → api.prod.scanme.sh
```
Custom `permutations.yaml` allows even more flexibility. :contentReference[oaicite:6]{index=6}

###  Additional Features
- `-en`, `--enrich`: extracts words (e.g., `staging`, `qa`) from input subdomains to expand payloads.
- Automatic deduplication (avoids redundant patterns like `api-api.domain.com`).
- Other useful flags:
  - `-limit` (cap output count)
  - `-ac` (custom config yaml)
  - `-pp` (override variable payloads)
  - Built-in update functionality :contentReference[oaicite:7]{index=7}

---

##  Example Usage

```bash
# Generate permutations from passive results and resolve with dnsx:
$ chaos -d tesla.com | alterx | dnsx

# Result sample:
[INF] Generated 8312 permutations in 0.0740s
auth-global-stage.tesla.com
auth-stage.tesla.com
digitalassets-stage.tesla.com
... etc.
```
Using `-enrich` increases context-aware results: `chaos | alterx -enrich` :contentReference[oaicite:8]{index=8}

---

##  Summary Table

| Feature                    | Description                                                                 |
|---------------------------|-----------------------------------------------------------------------------|
| DSL-based patterns        | Customizable templates for efficient permutation generation                 |
| Enrichment                | Extracts contextual words from input for smarter permutations               |
| Deduplication             | Avoids generating redundant subdomain permutations                          |
| Flexible configuration    | Supports flags like `-limit`, `-ac`, `-pp`, and output control               |
| Pipeline integration      | Works seamlessly with tools like `dnsx` for validation                      |

---

##  References

- AlterX GitHub: ProjectDiscovery’s `alterx` repo :contentReference[oaicite:9]{index=9}  
- Official ProjectDiscovery description of AlterX functionality :contentReference[oaicite:10]{index=10}  

---

**Usage Reminder:** Use AlterX responsibly and only during authorized security assessments.

