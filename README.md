# VLX PKI Toolset

## Overview

**VLX PKI Toolset** is a robust and user-friendly Bash script designed to automate the creation and management of a Public Key Infrastructure (PKI) using OpenSSL. It simplifies the complex process of generating Root CAs, Intermediate CAs, Server Certificates, mTLS Certificates, and Certificate Signing Requests (CSRs).

Whether you are setting up a development environment, a home lab, or an internal corporate network, this toolset provides a streamlined workflow for handling your PKI needs.

## Features

*   **Root CA Creation**: Easily generate a self-signed Root Certificate Authority (CA) to act as the trust anchor.
*   **Intermediate CA Creation**: Create Intermediate CAs signed by your Root CA to establish a secure chain of trust.
*   **TLS/SSL Certificates**: Generate standard server certificates for HTTPS, signed by your Intermediate CA.
*   **mTLS Certificates**: specific support for mutual TLS (mTLS), generating certificates suitable for both server and client authentication.
*   **CSR Generation**: Create Certificate Signing Requests (CSR) for external CAs or third-party signing.
*   **Keystore & Chain Management**:
    *   Export certificates to PKCS12 format (`.p12`) for use with Tomcat/Java.
    *   Create full certificate chains (leaf + intermediate) for Apache/Nginx.
*   **Secure Defaults**:
    *   **Algorithm**: ECDSA (`secp384r1`) for modern security and performance.
    *   **Encryption**: AES256 encryption for CA private keys.
    *   **Digest**: SHA512 for signatures.

## Prerequisites

*   **Operating System**: Linux or Unix-like environment (macOS, WSL).
*   **Dependencies**: `openssl` must be installed and available in your system's `PATH`.
    *   Ubuntu/Debian: `sudo apt install openssl`
    *   RHEL/CentOS: `sudo yum install openssl`

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/vlx-pki-toolset.git
    cd vlx-pki-toolset
    ```

2.  Make the script executable:
    ```bash
    chmod +x VLX_PKI_toolset.sh
    ```

## Usage

Run the script directly from your terminal:

```bash
./VLX_PKI_toolset.sh
```

An interactive menu will appear guiding you through the available options:

```text
------------------------------------------------
      PKI AUTOMATION TOOL - OPENSSL
------------------------------------------------
1) Create Root CA
2) Create Intermediate CA (RootCA required)
3) Create HTTPS/TLS Cert (Standard)
4) Create mTLS Certs (Server + Client)
5) Create CSR for external CA
6) Create Keystore (Tomcat) e Chain (Apache)
q) Quit
------------------------------------------------
```

### Directory Structure

The script organizes generated files into the following directories:

*   `certs/`: Contains public certificates (`.crt`), full chains, and PKCS12 keystores.
*   `private/`: Contains private keys (`.key`). **Note:** CA keys are encrypted; server keys are generally unencrypted for automated startup.
*   `csr/`: Contains Certificate Signing Requests (`.csr`).
*   `config/`: Contains the generated OpenSSL configuration files (`.cnf`) used for each certificate.

## Workflow Example

1.  **Initialize the PKI**:
    *   Select option `1` to create your Root CA (e.g., `MyCompanyRoot`). You will be prompted for a password to secure the root key.

2.  **Establish an Intermediate CA**:
    *   Select option `2`. Provide a name (e.g., `MyCompanyInter`) and reference the Root CA created in step 1.

3.  **Issue Certificates**:
    *   Select option `3` (for web servers) or `4` (for mTLS).
    *   Enter the domain name (e.g., `app.internal`).
    *   Sign it using the Intermediate CA created in step 2.

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) file for details.
