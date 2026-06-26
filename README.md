# VibeCheck

A modular, lightweight dynamic application security testing (DAST) framework designed for fast configuration audits, parameter probing, and cryptographic exposure checks against web environments.

---

## 🚀 Getting Started

### Prerequisites
* Python 3.11+
* Active Virtual Environment

### Installation & Execution

#### Step 1: Clone and Navigate
```bash
git clone https://github.com/arhambhansali/vibe-check-suite.git
cd vibe-check-suite

```

#### Step 2: Initialize Environment

```bash
python -m venv venv

```

#### Step 3: Activate (Windows PowerShell)

```powershell
.\venv\Scripts\Activate.ps1

```

#### Step 4: Activate (Linux or macOS Fallback)

```bash
source venv/bin/activate

```

#### Step 5: Install Requirements

```bash
pip install -r requirements.txt

```

#### Step 6: Run the Suite

```bash
python -m scanner.cli scan --url http://localhost:3000

```

---

## ⚠️ Disclaimer

This suite is intended strictly for authorized white-hat auditing, local defensive validation, and security research. Running offensive probing actions against infrastructure without explicit, prior written consent is illegal.
