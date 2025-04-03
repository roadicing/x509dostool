# X.509DoSTool

*X.509DoSTool* is a tool introduced in our USENIX Security '25 paper, *X.509DoS: Exploiting and Detecting Denial-of-Service Vulnerabilities in Cryptographic Libraries using Crafted X.509 Certificates*, developed to facilitate the rapid generation of crafted certificates and the automatic detection of Denial-of-Service (DoS) risks in cryptographic library implementations. This document provides instructions for the installation, usage, and evaluation of the tool.

# Directory Structure

Some primary components include:

- `x509dostool/` (source code):
  - `tool.py`: contains the main implementation of the tool.
  - `func/`: includes the implementation of three commands: `generate`, `edit`, and `detect`.
  - `misc/`: contains auxiliary functions frequently used by these commands.
  - `ext_pyasn1_modules/`: includes the implementation of the extended pyasn1-modules template.
  - `config.json`: serves as the configuration file for the tool.
- `test/` (evaluation):
  - `generate/`: contains the script for testing the `generate` command.
  - `edit/`: contains the script for testing the `edit` command (upon first execution, it will create a directory named `certs/`, which contains the certificates to be used).
  - `detect/`: contains the script for testing the `detect` command (upon first execution, it will create a directory named `certs/`, which contains the certificates to be used) and a directory named `scripts/`, which includes some scripts used to run the relevant APIs for the libraries under examination.
- `setup.py`: a file used to install the tool.

# Dependencies

## Hardware Dependencies

Our testing environment is built on a Linux server equipped with 4GB of RAM and a 4-core CPU, running Ubuntu v22.04. No special hardware dependencies are required.

## Software Dependencies

The software dependencies required to run this tool primarily include the following:

- Python v3.10.12
- pip v22.0.2
- setuptools v75.8.0 (Python package)
- psutil v6.0.0 (Python package)
- pyasn1 v0.6.0 (Python package)
- pyasn1_modules v0.4.0 (Python package)
- pycryptodome v3.20.0 (Python package)
- OpenSSL v3.0.2

The versions used during testing should match or closely align with those mentioned above, as significant version discrepancies may introduce potential untested issues.

Additionally, before evaluators attempt to use the tool to detect issues in a specific library, the corresponding version of the library (as listed in Table 3 and Table 4 of our paper) needs to be installed first. The libraries and their version information involved include:

- OpenSSL v3.0.0, v1.0.2
- Botan v1.11.21, v1.11.26, v3.2.0, v3.4.0
- Bouncy Castle v1.70, v1.77
- Crypto++ v5.6.4, v8.9
- GnuTLS v3.7.10, v3.7.11
- phpseclib v3.0.18, v3.0.33, v3.0.35

## Installation

To install, run `pip install .` in the root directory of the repository. This will package the necessary files and create a command named `x509dostool`. 

Upon installation, the command is readily available for the root user. However, for non-root users, it is necessary to first run `export PATH=$PATH:~/.local/bin` before the command can be used.

To execute, run `x509dostool`. If the installation is successful, it will display the tool's version number along with a help page containing the three basic subcommands: `generate`, `edit`, and `detect`:

```
      ____   ___   ___  ____       ____ _____           _ 
__  _| ___| / _ \ / _ \|  _ \  ___/ ___|_   _|__   ___ | |
\ \/ /___ \| | | | (_) | | | |/ _ \___ \ | |/ _ \ / _ \| |
 >  < ___) | |_| |\__, | |_| | (_) |__) || | (_) | (_) | |
/_/\_\____/ \___/   /_/|____/ \___/____/ |_|\___/ \___/|_|
Test Tool (v1.0.2)

positional arguments:
  {generate,edit,detect}
    generate            rapid generation of crafted certificates
    edit                customized edit of certificates
    detect              detection of implementations in libraries

options:
  -h, --help            show this help message and exit
```

## Usage

Run `x509dostool {generate, edit, detect} [-h]` to view the detailed meanings of each parameter. Some command examples for the tool are provided below:

Generate a certificate explicitly containing a crafted curve $E_p(a, b)$, where $p$ is very large:

```
x509dostool generate test4
```

Generate a certificate explicitly containing a crafted curve $E_p(a, b)$, where $p = 2^{13466917} - 1$, enabling point compression, and ensuring that the DER encoding length of the public key point's $x$ coordinate, the base point's $x$ coordinate, and the curve parameters $a$ and $b$ are all equal to $\lceil \frac{\log_2{p} + 7}{8} \rceil$:

```
x509dostool generate test4 -p 2**13466917-1 --compressed --balanced
```

Change the value of $p$ in the certificate to $1000$:

```
x509dostool edit -in crafted_certificate.crt tbs spki ecdsa_fp -p 1000
```

Modify the certificate's issuer to be `x509dos`:

```
x509dostool edit -in crafted_certificate.crt tbs issuer -values x509dos
```

Use the certificate to detect implementation issues in a library executed through a script named `test.sh`:

```
x509dostool detect -libs test.sh -certs crafted_certificate.crt 
```

In addition, the scripts under the `test/` directory also provide some common usage examples for the corresponding commands.

We also provided a video for demonstrating the usage of the tool, which can be found on [our website](https://sites.google.com/view/x509dos).

## Evaluation

To perform the evaluation for the `generate` or `edit` command, enter the respective directory (`test/generate/` or `test/edit/`) and run the corresponding script (`./test_generate.sh` or `./test_edit.sh`), optionally with the `--verbose` flag.

To perform the evaluation for the `detect` command, enter the `test/detect/` directory and run `./test_detect.sh`.