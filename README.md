# ATILLA 🔍  
### Advanced Reflected XSS Detection Tool (Educational)

ATILLA is an educational security testing tool designed to analyze **reflected Cross-Site Scripting (XSS)** vulnerabilities in **authorized web applications**.

> ⚠️ **For educational and authorized testing only**  
> Unauthorized scanning of systems you do not own or have permission for is illegal.

---

## 🚀 Features

- Multiple payload sets:
  - Basic
  - OWASP-inspired
  - Advanced WAF-bypass payloads
- Reflection analysis with confidence scoring
- Detection of:
  - Reflected XSS
  - Encoded / filtered payloads
  - CSP-protected responses
- DOM XSS sink detection
- Async scanning with retry & rate-limiting
- JSON export for reports
- Clean CLI interface with colored output

---
## 3️⃣ requirements.txt


## 📦 Installation

```bash
git clone https://github.com/Maquli234/atilla.git
cd atilla
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
## Usage 
```bash
python atilla.py -u "http://localhost/search?q=test"
python atilla.py -u "http://localhost/page?id=1" --set owasp
python atilla.py -u "http://localhost/search?q=test" --set advanced -v
python atilla.py -u "http://localhost/page?id=1" -o results.json





