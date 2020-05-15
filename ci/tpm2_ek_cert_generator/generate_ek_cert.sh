#!/bin/bash

# General parameters

readonly verbose_files=${VERBOSE_FILES:-yes}
readonly verbose_files_dir="${VERBOSE_FILES_DIR:-summaries}/"
readonly working_dir="${WORKING_DIR:-_${base}_working_dir}/"

# TPM parameters

readonly h_ek_pub_key='0x81010001'
readonly h_ek_pub_crt='0x1c00002'
readonly h_authorization='0x4000000C'
readonly ek_cert_nvram_attr='0x42072001'
readonly ek_alg='rsa'
readonly ek_alg_hex='0x0001'

# Keys parameters
readonly ca_cert_validity_days=3652
readonly tpm_cert_validity_days=$ca_cert_validity_days
readonly keylength=2048
readonly cwd="${PWD}"
readonly base='tpm2_'
readonly root_ca="${base}CA"
readonly ekc="${base}ekc"
readonly pubkey_to_certify=${1:-public.ek.portion.pem}
readonly manufacturer_ca='tpm.manufacturer.test'

# Utility functions

privout() {
   cd "${working_dir}"; o="$1"; rm -f "$o"; touch "$o"; chmod 0600 "$o"; shift
   (
      "$@"
   ) >> "$o"
   cd - &> /dev/null
}

privall() {
   cd "${working_dir}"; ="$1"; rm -f "$o"; touch "$o"; chmod 0600 "$o"; shift
   (
      "$@"
   ) >> "$o" 2>&1
   cd - &> /dev/null
}

# Create working dir if passed as parameter (if not, it's current dir)

[ ! -z "${working_dir}" ]       && mkdir -p "${working_dir}"
[ "${verbose_files}" == 'yes' ] && mkdir -p "${verbose_files_dir}"

echo "OpenSSL      $(openssl version 2> /dev/null | grep -Eo -m 1 ' [0-9]+.[0-9]+.[0-9a-z]+')"

# Generate EK and extract its TPM2_PUBLIC part to file

echo "Generate EK and extract TPM 2_PUBLIC part to file"

if command -v tpm2_getpubek > /dev/null 2>&1; then
  tpm2_getpubek -g "${ek_alg_hex}" -f "${working_dir}public.ek.portion" -H "${h_ek_pub_key}"
else
  tpm2_createek -G "${ek_alg}" -u "${working_dir}public.ek.portion" -c "${h_ek_pub_key}"
fi

# Map TPM2_PUBLIC to DER and PEM public key formats

echo "Map TPM2_PUBLIC to DER and PEM public key formats"

echo 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' | base64 -d > "${working_dir}header.bin"
echo '02 03' | xxd -r -p > "${working_dir}mid-header.bin"
echo '01 00 01' | xxd -r -p > "${working_dir}exponent.bin"
dd if="${working_dir}public.ek.portion" of="${working_dir}modulus.bin" bs=1 count=256 skip=60
cat "${working_dir}header.bin" "${working_dir}modulus.bin" "${working_dir}mid-header.bin" "${working_dir}exponent.bin" > "${working_dir}public.ek.portion.cer"
openssl rsa -in "${working_dir}public.ek.portion.cer" -inform DER -pubin > "${working_dir}public.ek.portion.pem"
rm "${working_dir}header.bin" "${working_dir}modulus.bin" "${working_dir}mid-header.bin" "${working_dir}exponent.bin"

cat "${working_dir}public.ek.portion.pem"

# Generate TPM self-signed CA

echo 'Creating self-signed TPM Root CA...'

readonly root_ca_csr_config="openssl/configs/${root_ca}.csr.config"
readonly root_ca_private_pem="${root_ca}_private.pem"
readonly root_ca_private_der="${root_ca}_private.der"
readonly root_ca_cert="${root_ca}.crt"
readonly root_ca_pass="$(pwgen -s 32 1)"
privout "${root_ca}.password" echo "${root_ca_pass}"

privout "${root_ca_private_pem}" \
  openssl genpkey -algorithm RSA -aes-256-cbc \
  -pkeyopt rsa_keygen_bits:${keylength} \
  -pass "pass:${root_ca_pass}"

privout "${root_ca}_private.pem.asn1.txt" \
  openssl asn1parse -i -in "${root_ca_private_pem}"

privout "${root_ca_private_der}" \
  openssl pkcs8 -topk8 -v2 aes-256-cbc \
    -in "${root_ca_private_pem}" -passin "pass:${root_ca_pass}" \
    -outform DER -passout "pass:${root_ca_pass}"

privout "${root_ca}_private.der.asn1.txt" \
  openssl asn1parse -i -inform DER -in "${root_ca_private_der}"

openssl req -batch -verbose -new -sha256 -x509 \
  -days "${ca_cert_validity_days}"  \
  -key "${working_dir}${root_ca_private_pem}" -passin "pass:${root_ca_pass}" \
  -out "${working_dir}${root_ca_cert}" -config "${root_ca_csr_config}"

openssl x509 -in "${working_dir}/${root_ca_cert}" \
  -text -noout -nameopt utf8 -sha256 -fingerprint \
    > "${working_dir}/${root_ca_cert}.x509.txt"

openssl asn1parse -i -in "${working_dir}/${root_ca_cert}" \
  > "${working_dir}/${root_ca_cert}.asn1.txt"

# Generate EK self-signed certificate (and private key, unused, but still
# required by OpenSSL)

echo ' Creating TPM Endorsement Key Certificate...'

readonly ekc_csr_config="openssl/configs/${ekc}.csr.config"
readonly pubkey_basename=${pubkey_to_certify%.*}

openssl rsa -pubin \
  -in "${working_dir}${pubkey_to_certify}" -text -noout \
    > "${working_dir}${pubkey_to_certify}.rsa.txt"

openssl asn1parse -i -in "${working_dir}${pubkey_to_certify}" \
  > "${working_dir}${pubkey_to_certify}.asn1.txt"

readonly csr_priv_key_pass="$(pwgen -s 32 1)"
privout "${ekc}_unused.password" echo "${csr_priv_key_pass}"
privout "${ekc}_unused.private.pem" \
  openssl genpkey -algorithm RSA -aes-256-cbc \
    -pkeyopt rsa_keygen_bits:${keylength} \
    -pass "pass:${csr_priv_key_pass}" 2> /dev/null

openssl req -batch -verbose -new -sha256 \
  -subj '/' \
  -passout "pass:${csr_priv_key_pass}" -keyout "${working_dir}${ekc}_unused.private.pem" \
  -out "${working_dir}${ekc}.csr" -config "${ekc_csr_config}"

if [ "${verbose_files}" == 'yes' ]; then
  openssl asn1parse -i -in "${working_dir}${ekc}.csr" > "${working_dir}${ekc}.csr.asn1.txt"
fi

output_pem_crt="${ekc}.pem.crt"
output_der_crt="${ekc}.der.crt"

openssl x509  -in "${working_dir}${ekc}.csr" -req \
  -extfile "${ekc_csr_config}" \
  -force_pubkey "${working_dir}${pubkey_to_certify}"  \
  -CA "${working_dir}${root_ca_cert}" -CAkey "${working_dir}${root_ca_private_pem}" \
  -CAcreateserial \
  -passin "pass:${root_ca_pass}" \
  -out "${output_pem_crt}" \
  -extensions v3_req \
  -days ${tpm_cert_validity_days} -sha256

openssl x509  -in "${working_dir}${ekc}.csr" -req \
  -extfile "${ekc_csr_config}" \
  -force_pubkey "${working_dir}${pubkey_to_certify}" \
  -CA "${working_dir}${root_ca_cert}" -CAkey "${working_dir}${root_ca_private_pem}" \
  -CAcreateserial \
  -passin "pass:${root_ca_pass}" \
  -outform der \
  -out "${output_der_crt}" \
  -extensions v3_req \
  -days ${tpm_cert_validity_days} -sha256

if [ "${verbose_files}" == 'yes' ]; then
  openssl asn1parse -i -in "${output_pem_crt}" \
    > "${working_dir}${ekc}.crt.asn1.txt"
  openssl x509 -in "${output_pem_crt}" -text -noout -nameopt utf8 -sha256 \
    -fingerprint > "${working_dir}${ekc}.crt.x509.txt"
fi

# Store EK cert (DER format) in NVRAM

echo "Store EK cert in NVRAM index ${h_ek_pub_crt}"

ek_der_cert_size=$(cat "${output_der_crt}" | wc -c)
# NOTE: if you want to remove existing NVRAM EK cert (at your risk), use the following command
# tpm2_nvrelease -x "${h_ek_pub_crt}" -a "${h_authorization}"
if command -v tpm2_getpubek > /dev/null 2>&1; then
  tpm2_nvdefine -x "${h_ek_pub_crt}" -a "${h_authorization}" -s "${ek_der_cert_size}" -t "${ek_cert_nvram_attr}"
  tpm2_nvwrite -x "${h_ek_pub_crt}" -a "${h_authorization}" -f "${output_der_crt}"
else
  tpm2_nvdefine "${h_ek_pub_crt}" -p "${h_authorization}" -s "${ek_der_cert_size}"
  tpm2_nvwrite "${h_ek_pub_crt}" -P "${h_authorization}" -i "${output_der_crt}"
fi

# Show EK certificate in console

openssl x509 -in "${output_der_crt}" -inform der -text -noout

exit 0