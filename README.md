# Zyntra

### Security Assessment & Intelligence Framework

**Version:** 0.1.0

Zyntra is a modular Python framework designed to support authorized security assessments through reconnaissance, enumeration, web security testing, evidence correlation, and structured reporting.

It brings multiple assessment capabilities into one command-line interface, helping security practitioners collect technical observations, identify potential security weaknesses, preserve evidence, and generate assessment reports.

> Zyntra is intended for authorized security testing only. Always obtain permission and define the assessment scope before testing a target.

---

## Features

| Flag | Module | Description |
|---|---|---|
| `-r` | Reconnaissance | Domain intelligence, DNS analysis, subdomain discovery, infrastructure discovery, IP intelligence, network discovery, and web-surface analysis. |
| `-e` | Enumeration | Web crawling, API candidate discovery, virtual-host enumeration, JavaScript analysis, and evidence correlation. |
| `-w` | Web Assessment | Security configuration, access-control, input-reflection, and CORS assessment. |
| `--export` | Assessment Export | Exports a previously generated assessment using its assessment ID. |

### Core capabilities

- Modular assessment architecture.
- Command-line operation.
- Eight-digit sequential assessment identifiers.
- Centralized assessment lifecycle.
- Structured observation collection.
- Evidence correlation and potential finding generation.
- JSON evidence storage.
- HTML report generation.
- Sensitive-value redaction in HTML reports.
- SHA-256 verification during assessment export.
- Configurable persistent data directory.
- Automated test suite.

---

## Requirements

- Linux environment.
- Python 3.10 or newer.
- Python dependencies listed in `requirements.txt`.
- WHOIS system utility for WHOIS lookups.
- Git for cloning the repository.
- Network connectivity for live assessment operations and dependency installation.

---

## Local setup

This section explains how to install and run Zyntra directly on a Linux computer, including Kali Linux and Debian-based distributions.

### 1. Prepare your system

Update your package lists:

```bash
sudo apt update
```

Install the required system packages:

```bash
sudo apt install -y git python3 python3-venv python3-pip whois
```

These packages provide:

- `git` — retrieves the Zyntra source code.
- `python3` — runs the application.
- `python3-venv` — creates an isolated Python environment.
- `python3-pip` — Python package installation support.
- `whois` — system utility used for WHOIS lookups.

### 2. Verify your Python installation

Check the installed Python version:

```bash
python3 --version
```

Check pip:

```bash
python3 -m pip --version
```

Zyntra requires Python 3.10 or newer.

### 3. Clone the repository

Move to the directory where you want to keep your projects:

```bash
cd ~
```

Clone Zyntra:

```bash
git clone https://github.com/iamridwansec/zyntra.git
```

Enter the project directory:

```bash
cd zyntra
```

Confirm the project files:

```bash
ls -la
```

You should see the application entry point, configuration, core components, modules, documentation, tests, and dependency file.

### 4. Create a virtual environment

Create a dedicated environment for Zyntra:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Your terminal prompt should now show the virtual environment name, usually `(.venv)`.

Verify which Python interpreter is active:

```bash
which python
```

The returned path should point inside the project's `.venv` directory.

A virtual environment keeps Zyntra's Python dependencies separate from your system-wide Python installation.

### 5. Install project dependencies

Upgrade pip inside the virtual environment:

```bash
python -m pip install --upgrade pip
```

Install Zyntra's declared dependencies:

```bash
python -m pip install -r requirements.txt
```

Check for dependency conflicts:

```bash
python -m pip check
```

### 6. Verify the installation

Display the application version:

```bash
python zyntra.py --version
```

Display the command-line help:

```bash
python zyntra.py --help
```

Run the automated test suite:

```bash
python -m unittest discover -s tests -v
```

A successful test run should finish without failed tests.

### 7. Launch Zyntra locally

Once the installation and verification steps are complete, run reconnaissance:

```bash
python zyntra.py -r -t example.com
```

Run enumeration:

```bash
python zyntra.py -e -t example.com
```

Run web assessment:

```bash
python zyntra.py -w -t https://example.com
```

Only use targets within your authorized testing scope.

### 8. Working with Zyntra again

When you open a new terminal session, navigate to the project directory:

```bash
cd ~/zyntra
```

Activate the existing virtual environment:

```bash
source .venv/bin/activate
```

You do not need to recreate the virtual environment or reinstall dependencies every time.

When finished, leave the environment:

```bash
deactivate
```

### 9. Troubleshooting local setup

**Problem: `python3: command not found`**

Check whether Python is installed:

```bash
sudo apt install python3
```

**Problem: `No module named venv`**

Install virtual-environment support:

```bash
sudo apt install python3-venv
```

**Problem: `whois: command not found`**

Install the WHOIS utility:

```bash
sudo apt install whois
```

**Problem: `ModuleNotFoundError`**

Make sure the virtual environment is active and dependencies are installed:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

**Problem: `externally-managed-environment`**

Do not force installation into Kali's system Python. Activate the project virtual environment and install dependencies there.

---

## Command-line usage

Display help:

```bash
python3 zyntra.py --help
```

Display the version:

```bash
python3 zyntra.py --version
```

### 1. Reconnaissance

Run reconnaissance against a target:

```bash
python3 zyntra.py -r -t example.com
```

Specify TCP ports:

```bash
python3 zyntra.py -r -t example.com --ports 22,80,443
```

Run an intentional full TCP port scan:

```bash
python3 zyntra.py -r -t example.com --ports 1-65535 --confirm-full-scan
```

### 2. Enumeration

Run enumeration:

```bash
python3 zyntra.py -e -t example.com
```

### 3. Web security assessment

Run web assessment:

```bash
python3 zyntra.py -w -t https://example.com
```

Only test systems that you own or have explicit permission to assess.

---

## Assessment lifecycle

Every assessment receives a unique eight-digit sequential identifier.

Example:

```text
ZYN-00000001
```

The assessment lifecycle includes:

1. Target validation.
2. Assessment initialization.
3. Assessment ID generation.
4. Module dispatch.
5. Observation collection.
6. Evidence correlation.
7. Potential finding generation.
8. Assessment status tracking.
9. JSON serialization.
10. HTML report generation.

Assessment statuses include:

- `running`
- `completed`
- `partial`
- `failed`

For additional technical details, see `docs/assessment-lifecycle.md`.

---

## Assessment output

By default, Zyntra stores assessment data in the `data/` directory.

```text
data/
├── assessment_counter.txt
└── assessments/
    └── ZYN-00000001/
        ├── results.json
        └── report.html
```

### results.json

Contains the original collected observations and derived findings.

This file may contain sensitive evidence, including detected secret values. It should be treated as confidential.

### report.html

Provides a human-readable assessment report.

- Detected secret values are redacted.
- Untrusted content is escaped before rendering.
- Findings are presented for further validation.

A detected issue is not automatically a confirmed vulnerability. Manual validation is necessary to establish exploitability and impact.

---

## Export assessments

Create an export destination:

```bash
mkdir -p ./assessment-exports
```

Export an assessment:

```bash
python3 zyntra.py --export ZYN-00000001 --destination ./assessment-exports
```

The exporter:

- Validates the assessment identifier.
- Checks the assessment data.
- Copies `results.json` and `report.html`.
- Verifies copied files using SHA-256 hashes.
- Skips an existing export rather than overwriting it.

The destination directory must already exist.

---

## Configuring the data directory

Zyntra supports an alternative persistent data location through the `ZYNTRA_DATA_DIR` environment variable.

Example:

```bash
export ZYNTRA_DATA_DIR="$HOME/zyntra-data"
python3 zyntra.py -r -t example.com
```

This allows assessment records to be stored separately from the application directory.

Protect this directory because original assessment evidence may contain sensitive information.

---

## Project structure

```text
zyntra/
├── config/
│   └── wordlists/
│       └── subdomains.txt
├── core/
│   ├── assessment.py
│   ├── dispatcher.py
│   ├── exporter.py
│   ├── findings.py
│   ├── ids.py
│   ├── lifecycle.py
│   ├── registry.py
│   ├── reporting.py
│   └── serializer.py
├── data/
│   ├── wordlists/
│   │   └── vhosts.txt
│   ├── assessment_counter.txt
│   └── assessments/
├── docs/
│   ├── assessment-lifecycle.md
│   └── configuration.md
├── modules/
│   ├── enumeration/
│   ├── evidence/
│   ├── recon/
│   └── web/
├── templates/
├── tests/
├── requirements.txt
└── zyntra.py
```

---

## Testing

Zyntra includes automated tests for its core components and assessment modules.

Run the complete test suite:

```bash
python3 -m unittest discover -s tests -v
```

---

## Portable USB deployment

Zyntra can also be deployed on a USB drive for use on compatible Linux systems.

The portable deployment can include:

- Application source code.
- Configuration files.
- Wordlists.
- Documentation.
- Test files.
- Bundled Python dependencies in `vendor/`.
- A shell launcher named `zyntra`.

The portable launcher uses the directory containing itself as the application location and adds the bundled `vendor/` directory to `PYTHONPATH`.

Example:

```bash
/path/to/usb/zyntra --help
```

A Linux host can optionally configure a command shortcut and automatic USB mounting. Those are host-specific configurations and are not automatically installed by cloning the repository.

---

## Responsible use

Zyntra is developed for legitimate security assessment, learning, and authorized testing.

Users are responsible for:

- Obtaining explicit authorization.
- Respecting defined assessment scope.
- Avoiding unnecessary disruption.
- Protecting collected evidence.
- Validating findings before reporting them.
- Handling sensitive assessment data responsibly.

Unauthorized testing is not supported or encouraged.

---

## Project information

- **Project:** Zyntra
- **Version:** 0.1.0
- **Category:** Security Assessment & Intelligence Framework
- **Language:** Python
- **Interface:** Command Line Interface
- **Repository:** https://github.com/iamridwansec/zyntra

---

*Assess with purpose. Collect with context. Report with evidence.*
