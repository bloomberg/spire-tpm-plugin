# TPM Intro

I had a lot of trouble understanding TPM attestation when I first came across it, so I thought I would write a little bit about what TPMs are/how they're used.

Note: While some of this info may be true for TPM 1.0, it is all written for TPM 2.0.

## What is a TPM?

TPM stands for Trusted Platform Module. A TPM is a special piece of hardware in a computer (can be external or burned into the motherboard) that stores RSA encryption keys for use in hardware authentication. The general problem that TPMs try to solve is "How can I say with 100% certainty that the machine I'm talking to is who it says it is?" Since TPMs have RSA keys burned into them, they can cryptographically prove that "they are who they say they are."

## TPM Terminology

- Endorsement Key (EK) - a key pair burned into the TPM by the manufacturer. This pair takes the form of one public certificate (EKCert) and one private key.
- Attestation Key (AK) - an RSA key pair that is created by the user. The public part of the key can be pulled out of the TPM, but the private part always stays inside the TPM.
- Credential Activation - the process of proving an AK is on the same machine as an EK
- Attestation - the process of proving that an AK is present on a machine
- Platform Configuration Register (PCR) - a part of memory in the TPM used to store sensitive information
- Quote - a way of signing PCRs and a nonce using an AK
- Credential Provider - the machine we're trying to attest to (prove to that we are who we say we are)

### Note on TPM memory

TPMs have two types of memory: public memory and private memory. Public memory can be read from by the host system, but private memory cannot. As such, public keys are stored in public memory, and private keys in private memory. This means you can, for example, tell the TPM to sign a piece of data with an AK's private key without the host system even being able to access the private key. This is useful because it allows the machine to prove it has the TPM without the TPM having a chance of having its private key stolen.

## TPM Credential Activation

By design, EK cannot sign any data, so before any attestation can be done, we need to create an AK and use credential activation to bind it to an EK.

On a very high level, this is done by the following steps:

1. TPM machine generates AK
1. Credential provider generates random data and encrypts with AK and EK
1. TPM machine decrypts random data and sends it back
1. Credential provider verifies that the data is accurate, proving that the AK is on the same machine as the EK

In TPM-speak, however, this sounds a little more complicated:

1. TPM machine mints new AK
1. TPM machine sends AK public key and EK certificate to credential provider
1. Credential provider runs the "MakeCredential" command with the AK public key and EK certificate to generate a "challenge" (encrypted secret)
1. Credential provider sends challenge back to TPM machine
1. TPM machine runs "ActivateCredential" to use AK and EK to decrypt challenge
1. TPM machine sends back decrypted secret
1. Credential provider verifies that the secret the TPM replied with is the same as the one it used to generate the challenge
1. Credential provider stores the AK public key in a list of trusted keys

Now, whenever the machine tries to attest to the Credential Provider to prove its identity, instead of having to generate a new AK and do credential activation, the TPM can use the AK to quote a piece of data.

## TPM Attestation

Once credential activation has happened, TPMs can use quotes to prove identity. The steps are as follows:

1. TPM machine sends AK public key to credential provider
1. Credential provider verifies the AK has been activated
1. Credential provider sends back a nonce
1. TPM creates a quote based on the nonce and sends it
1. Credential provider verifies the signature on the quote using the AK public key or the "VerifyQuote" utility

## Notes on SPIRE TPM Attestation

As you may have noticed, my SPIRE TPM plugin only does credential activation, completely forgoing quotes. This is because in SPIRE, node attestation will only ever be done once for a given machine (unless it's wiped). As such, implementing quotes would be useless because they're only useful for attestation after first attest.

Also, using quotes would require that SPIRE have some way to store all the AKs that have been activated, which it doesn't at the moment.

