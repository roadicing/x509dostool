# X.509DoSTool

*X.509DoSTool* is a tool introduced in our USENIX Security '25 paper, *X.509DoS: Exploiting and Detecting Denial-of-Service Vulnerabilities in Cryptographic Libraries using Crafted X.509 Certificates*, developed to facilitate the rapid generation of crafted certificates and the automatic detection of Denial-of-Service (DoS) risks in cryptographic library implementations. This document provides instructions for the installation, usage, and evaluation of the tool.

## installation

To install, run `pip install .` in the root directory of the repository. This will package the necessary files and create a command named `x509dostool`.

To execute, run `x509dostool`. If the installation is successful, it will display the tool's version number along with a help page containing the three basic subcommands: `generate`, `edit`, and `detect`:

```
      ____   ___   ___  ____       ____ _____           _ 
__  _| ___| / _ \ / _ \|  _ \  ___/ ___|_   _|__   ___ | |
\ \/ /___ \| | | | (_) | | | |/ _ \___ \ | |/ _ \ / _ \| |
 >  < ___) | |_| |\__, | |_| | (_) |__) || | (_) | (_) | |
/_/\_\____/ \___/   /_/|____/ \___/____/ |_|\___/ \___/|_|
Test Tool (v1.0.1)

positional arguments:
  {generate,edit,detect}
    generate            rapid generation of crafted certificates
    edit                customized edit of certificates
    detect              detection of implementations in libraries

options:
  -h, --help            show this help message and exit
```

## usage

Run `x509dostool {generate, edit, detect} [-h]` to view the detailed meanings of each parameter. Additionally, some typical commands are provided in the shell scripts under the `test/functionality/` directory for reference.

We also provided a video for demonstrating the usage of the tool, which can be found on [our website](https://sites.google.com/view/x509dos).

## evaluation

To perform the evaluation for `generate` and `edit` command, enter the `test/functionality/` directory and run `./test_generate.sh [--verbose]` and `./test_edit.sh [--verbose]`.

To perform the evaluation for `detect` command, enter the `test/functionality/` directory and run `./test_detect.sh [--verbose]` and `./test_detect.sh`.
