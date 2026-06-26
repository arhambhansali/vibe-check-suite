# vibe-check-suite

A modular, lightweight dynamic application security testing (DAST) framework designed for fast configuration audits, parameter probing, and cryptographic exposure checks against web environments.

---

## 🛠️ System Modules

The suite isolates its auditing logic into five focused, pluggable sub-engines:

| # | Module | Core Functionality | Target Risk |
|---|---|---|---|
| **1** | `core_spider` | Autonomous site mapper & HTML input parser. | Hidden entry points, unlinked parameters. |
| **2** | `jwt_crack` | Weak key verification, algorithmic fallback testing (`none`), and signature manipulation. | Broken JWT authentication mechanics. |
| **3** | `abuse_test` | Concurrent execution engine measuring rate-limit threshold exhaustion and stack-trace drops. | Denial of Service & Informational leakage. |
| **4** | `headers_audit`| Validation engine checking explicit security headers and cross-origin disclosure policies. | Misconfigurations (CORS, CSP, HSTS, XFO). |
| **5** | `secret_scan` | High-entropy regex crawler inspecting server responses and JS files for inline credentials. | Static token & hardcoded API key leaks. |

---

## 🚀 Getting Started

### Prerequisites
* Python 3.11+
* Active Virtual Environment (`venv`)

### Installation & Execution (Local Development)

1. Clone the repository and navigate to the directory:
   ```bash
   git clone [https://github.com/arhambhansali/vibe-check-suite.git](https://github.com/arhambhansali/vibe-check-suite.git)
   cd vibe-check-suite

    Initialize and activate your isolation environment:
    Bash

    python -m venv venv
    # Windows PowerShell:
    .\venv\Scripts\Activate.ps1
    # Linux / macOS:
    source venv/bin/activate

    Install requirements directly:
    Bash

    pip install -r requirements.txt

    Initialize a targeted framework audit invocation:
    Bash

    python -m scanner.cli scan --url http://localhost:3000
