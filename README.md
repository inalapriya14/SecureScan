# SecureScan — Website Security Scanner

SecureScan is a beginner-friendly Python/Flask portfolio project that performs lightweight, non-intrusive checks on a single public website response.

## Features
- HTTPS URL check and standard TLS certificate validation by Requests
- Checks for Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy
- Reviews `Secure`, `HttpOnly`, and `SameSite` cookie attributes when cookies are returned
- Simple heuristic header score and actionable recommendations
- Responsive web interface
- Basic safeguards: blocks non-public/reserved IP destinations, disables automatic redirects, validates redirect destinations, uses timeouts, and limits redirects

## Tech stack
- Python 3.10+
- Flask
- Requests
- HTML and CSS

## Run on Windows
1. Install Python 3.10 or newer.
2. Extract this repository and open PowerShell in the project folder.
3. Create and activate a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
4. Install packages:
   ```powershell
   pip install -r requirements.txt
   ```
5. Start the app:
   ```powershell
   python app.py
   ```
6. Open `http://127.0.0.1:5000` in your browser.

## Safety and limitations
- Use only on websites you own or are explicitly authorized to assess.
- This is a header/configuration checker, not a penetration test, full vulnerability scanner, or proof that a site is secure.
- It makes a small number of GET requests and follows at most three redirects after validating each destination.
- Network restrictions reduce risk but are not a substitute for running the tool in a sandbox; DNS rebinding and unusual network setups can require stronger egress controls.
- The score is a simple heuristic. Header presence alone does not validate whether a policy is correct.
- The tool does not attempt exploitation, password guessing, port scanning, or crawling.
- Do not expose Flask's development server directly to the public internet.

## Project structure
```text
SecureScan/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── templates/
│   └── index.html
└── static/
    └── style.css
```

## GitHub upload
Create an empty public repository named `securescan-python`. From this folder:
```powershell
git init
git add .
git commit -m "Build SecureScan website security checker"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/securescan-python.git
git push -u origin main
```
Replace `YOUR-USERNAME` with your GitHub username. If this folder is already a Git repository, inspect `git status` and `git remote -v` first.

## Resume description (after testing)
**SecureScan — Python Website Security Scanner**
- Built a Flask-based tool to review HTTPS usage, common security headers, and cookie attributes on authorized public websites.
- Added URL validation, redirect limits, request timeouts, and defensive checks against private network destinations.
- Created a responsive dashboard with findings and remediation guidance.

Only claim features you have personally tested.
## 📸 Application Screenshot

![SecureScan Demo](securescan-demo.png)
