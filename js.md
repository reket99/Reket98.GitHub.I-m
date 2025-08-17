# JS Recon Stack Cheatsheet

### 1. Pull all JS from a target
```bash
usedjs -u https://target.com
```

---

### 2. Extract endpoints from JS
```bash
python3 linkfinder.py -i https://target.com/main.js -o cli
```

---

### 3. Parse JavaScript logic
```bash
python3 JSParser.py -u https://target.com/app.js
```

---

### 4. Find juicy snippets with gf
```bash
cat app.js | gf interesting
cat app.js | gf api-keys
```

---

### 5. Replay endpoints with Burp Repeater
- Send URLs discovered from LinkFinder/JSParser into Repeater.  
- Modify headers, tokens, and cookies.  
- Example:  
  - `/admin/stats`  
  - Send request with no auth → check if backend responds.

---

### 6. AI-assisted deobfuscation
Copy confusing snippets, e.g.:
```js
if (user.role === "1" || user.email.includes("staff"))
```
Ask AI:
> “What is this logic doing? How can it be abused?”

---

### Example Hardcoded Secrets
```js
const firebaseConfig = {
  apiKey: "AIzaSyD-EXAMPLE-HARDCODED-KEY",
  authDomain: "test-app.firebaseapp.com",
  ...
};
```

---

### Common Things to Search For
- `config.js`, `env.js`, `firebase.js`
- `X-API-KEY` or `Authorization` in JS
- Debug/test flags
- Source maps (`.map` files)

---

### AI Recon Prompt
Feed into GPT/Claude:
> “Here is a JavaScript file. Can you find any API endpoints, hardcoded credentials, and logic flaws that might indicate auth bypass?”
