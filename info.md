# Information
This document is used to provide information regarding the experiments discussed in Section 7 of our paper.

Our experimental environment is deployed on Ubuntu 22.04, with 16 GB of memory and an 8-core CPU.

The information regarding the 18 vulnerabilities we recently discovered is as follows (Table 3 in Section 7):

| **No.** | **Library**           | **_Risk_-ID** | **Test Ver.** | **Status**          |
|---------|-----------------------|---------------|---------------|---------------------|
| 1       | Botan                 | _Risk-4_      | v3.2.0        | CVE-2024-34703      |
| 2       | Botan                 | _Risk-5_      | v3.4.0        | CVE-2024-34702      |
| 3       | Botan                 | _Risk-8_      | v3.4.0        |                     |
| 4       | Bouncy Castle         | _Risk-1_      | v1.77         | CVE-2024-29857      |
| 5       | Bouncy Castle         | _Risk-7_      | v1.77         | CVE assigning       |
| 6       | Bouncy Castle         | _Risk-8_      | v1.77         | CVE assigning       |
| 7       | Crypto++              | _Risk-1_      | v8.9          | Fixing              |
| 8       | Crypto++              | _Risk-2_      | v8.9          | CVE-2023-50980      |
| 9       | Crypto++              | _Risk-3_      | v8.9          | CVE-2023-50981      |
| 10      | GnuTLS                | _Risk-5_      | v3.7.11       | CVE assigning       |
| 11      | GnuTLS                | _Risk-8_      | v3.7.11       | CVE assigning       |
| 12      | phpseclib             | _Risk-1_      | v3.0.33       | CVE-2023-49316      |
| 13      | phpseclib             | _Risk-3_      | v3.0.18       | CVE-2023-27560      |
| 14      | phpseclib             | _Risk-4_      | v3.0.35       | CVE-2024-27354      |
| 15      | phpseclib             | _Risk-7_      | v3.0.35       | CVE-2024-27355      |
| 16      | Security (Apple)      | _Risk-5_      | v14.6.1       | Fixing              |
| 17      | Security (Apple)      | _Risk-7_      | v14.6.1       | Fixing              |
| 18      | Security (Apple)      | _Risk-8_      | v14.6.1       | CVE-2024-54538      |

The information regarding the 12 previously known vulnerabilities identified is as follows (Table 4 in Appendix B):

| **No.** | **Library**           | **_Risk_-ID** | **Test Ver.** | **Comments**                |
|---------|-----------------------|---------------|---------------|-----------------------------|
| 1       | OpenSSL               | _Risk-3_      | v1.0.2        | CVE-2022-0778               |
| 2       | OpenSSL               | _Risk-4_      | v3.0.0        | CVE-2023-6237               |
| 3       | OpenSSL               | _Risk-6_      | v1.0.2        | CVE-2016-2109               |
| 4       | OpenSSL               | _Risk-7_      | v1.0.2        | CVE-2023-2650               |
| 5       | OpenSSL               | _Risk-8_      | v1.0.2        | https://github.com/openssl/openssl/commit/8545051c3652bce7bb962afcb6879c4a6288bc67 |
| 6       | OpenSSL               | _Risk-9_      | v1.0.2        | CVE-2023-0464               |
| 7       | Botan                 | _Risk-3_      | v1.11.26      | CVE-2016-2194               |
| 8       | Botan                 | _Risk-10_     | v1.11.21      | CVE-2015-7825               |
| 9       | Bouncy Castle         | _Risk-3_      | v1.70         | https://github.com/bcgit/bc-java/commit/9b5bc534ca9c40ce28c57b874f0d9f07b5c2fdd3 |
| 10      | GnuTLS                | _Risk-10_     | v3.7.10       | CVE-2024-0567               |
| 11      | Crypto++              | _Risk-6_      | v5.6.4        | CVE-2016-9939               |
| 12      | Security (Apple)      | _Risk-9_      | v13.2         | CVE-2023-23524              |
