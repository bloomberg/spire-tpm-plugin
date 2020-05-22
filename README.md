# SPIRE TPM Plugin

This repository contains agent and server plugins for [SPIRE](https://github.com/spiffe/spire) to allow TPM 2-based node attestation.

## Menu

- [Quick start](#quick-start)
- [How it Works](#how-it-works)
- [Building](#building)
- [Contributions](#contributions)
- [License](#license)
- [Code of Conduct](#code-of-conduct)
- [Security Vulnerability Reporting](#security-vulnerability-reporting)

## Demo

Here's a quick demo that shows how this plugin looks when run:

[![asciicast](https://asciinema.org/a/n0TUMXXlbPUpNtxGxzD0AWzdf.svg)](https://asciinema.org/a/n0TUMXXlbPUpNtxGxzD0AWzdf)

## Quick Start

Before starting, create a running SPIRE deployment and add the following configuration to the agent and server:

### Agent Configuration

```hcl
NodeAttestor "tpm" {
	plugin_cmd = "/path/to/plugin_cmd"
	plugin_checksum = "sha256 of the plugin binary"
	plugin_data {
	}
}
```

### Server Configuration

```hcl
NodeAttestor "tpm" {
	plugin_cmd = "/path/to/plugin_cmd"
	plugin_checksum = "sha256 of the plugin binary"
	plugin_data {
		ca_path = "/opt/spire/.data/certs"
		hash_path = "/opt/spire/.data/hashes"
	}
}
```

| key | type | required | description | default |
|:----|:-----|:---------|:------------|:--------|
| ca_path | string |   | the path to the CA directory | /opt/spire/.data/certs |
| hash_path | string |   | the path to the Hash directory | /opt/spire/.data/hashes |

### Directory Configuration

For this plugin to work, either `ca_path`, `hash_path`, or both must be configured.

#### Certificate Directory

Contains the manufacturer CA cert that signed the TPM's EK certificate in PEM or DER format. Drop all manufacturer CA certs in the directory `ca_path`.

*Note: not all TPM's have an EK certificate, if yours does not then use `hash_path`*

#### Hash Directory

Contains empty files named after the EK public key hash.  Use the `get_tpm_pubhash` command to print out the TPM's EK public key hash.  Example:

```bash
agent  $ ./get_tpm_pubhash
1b5bbe2e96054f7bc34ebe7ba9a4a9eac5611c6879285ceff6094fa556af485c 

server $ mkdir -p /opt/spire/.data/hashes
server $ touch /opt/spire/.data/hashes/1b5bbe2e96054f7bc34ebe7ba9a4a9eac5611c6879285ceff6094fa556af485c
```

## How it Works

The plugin uses TPM credential activation as the method of attestation. The plugin operates as follows:

1. Agent generates AK (attestation key) using TPM
1. Agent sends the AK attestation parameters and EK certificate or public key to the server
1. Server inspects EK certificate or public key
    1. If `hash_path` exists, and the public key hash matches filename in `hash_path`, validation passes
    1. If `ca_path` exists, and the EK certificate was signed by any chain in `ca_path`, validation passes
1. If validation passed, the server generates a credential activation challenge using
    1. The EK public key
    1. The AK attestation parameters
1. Server sends challenge to agent
1. Agent decrypts the challenge's secret 
1. Agent sends back decrypted secret
1. Server verifies that the decrypted secret is the same it used to build the challenge
1. Server creates a SPIFFE ID in the form of `spiffe://<trust_domain>/agent/tpm/<sha256sum_of_tpm_pubkey>`
1. All done!

For info on how TPM attestation usually works and how this implementation differs, visit [TPM.md](TPM.md).

## Building

To build this plugin on Linux, run `make build`. Because of the dependency on [go-attestation](https://github.com/google/go-attestation), you must have `libtspi-dev` installed.

## Contributions

We :heart: contributions.

Have you had a good experience with this project? Why not share some love and contribute code, or just let us know about any issues you had with it?

We welcome issue reports [here](../../issues); be sure to choose the proper issue template for your issue, so that we can be sure you're providing the necessary information.

Before sending a [Pull Request](../../pulls), please make sure you read our
[Contribution Guidelines](https://github.com/bloomberg/.github/blob/master/CONTRIBUTING.md).

## License

Please read the [LICENSE](LICENSE) file.

## Code of Conduct

This project has adopted a [Code of Conduct](https://github.com/bloomberg/.github/blob/master/CODE_OF_CONDUCT.md).
If you have any concerns about the Code, or behavior which you have experienced in the project, please
contact us at opensource@bloomberg.net.

## Security Vulnerability Reporting

If you believe you have identified a security vulnerability in this project, please send email to the project
team at opensource@bloomberg.net, detailing the suspected issue and any methods you've found to reproduce it.

Please do NOT open an issue in the GitHub repository, as we'd prefer to keep vulnerability reports private until
we've had an opportunity to review and address them.
