readonly working_dir="${WORKING_DIR:-_${base}_working_dir}/"

echo "Generating Endorsement Key (EK)"
sudo tpm2_createek -c 0x81010001 -G rsa -u "${working_dir}public.ek.portion"

echo "Map TPM2_PUBLIC to DER and PEM public key formats"
echo 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' | base64 -d > "${working_dir}header.bin"
echo '02 03' | xxd -r -p > "${working_dir}mid-header.bin"
echo '01 00 01' | xxd -r -p > "${working_dir}exponent.bin"
dd if="${working_dir}public.ek.portion" of="${working_dir}modulus.bin" bs=1 count=256 skip=60
cat "${working_dir}header.bin" "${working_dir}modulus.bin" "${working_dir}mid-header.bin" "${working_dir}exponent.bin" > "${working_dir}public.ek.portion.cer"
openssl rsa -in "${working_dir}public.ek.portion.cer" -inform DER -pubin > "${working_dir}public.ek.portion.pem"
rm "${working_dir}header.bin" "${working_dir}modulus.bin" "${working_dir}mid-header.bin" "${working_dir}exponent.bin"

cat "${working_dir}public.ek.portion.pem"

echo "Creating local TPM Root CA"
openssl genrsa -out tpm2_localCA/tpmCA.key 2048
openssl req -x509 -new -nodes -key tpm2_localCA/tpmCA.key -sha256 -days 3650 -out  tpm2_localCA/tpmCA.cert

echo "Generating EK certificate using local root CA"
openssl genrsa -out ek.unused.private.key 2048
openssl req -batch -verbose -new -sha256 \
  -subj '/' \
  -key ek.unused.private.key \
  -out ekcert.csr
openssl x509 -in ekcert.csr -req \
  -force_pubkey "${working_dir}public.ek.portion.pem" -keyform PEM \
  -CA tpm2_localCA/tpmCA.cert -CAkey tpm2_localCA/tpmCA.key \
  -CAcreateserial \
  -outform pem \
  -out "${working_dir}ekc.pem.cert" \
  -extensions v3_req \
  -days 3650 -sha256

echo "Storing EK certificate on TPM"
readonly h_ek_pub_key='0x81010001'
readonly h_ek_pub_crt='0x1c00002'
readonly h_authorization='0x4000000C'
readonly ek_cert_nvram_attr='0x42072001'

ek_pem_cert_size=$(cat /home/kali/simulated-tpm/ek-cert-pem | wc -c)
sudo tpm2_nvdefine "${h_ek_pub_crt}" -C "${h_authorization}" -s "${ek_pem_cert_size}" -a "${ek_cert_nvram_attr}"
echo "NV Area created. Size:  ${ek_pem_cert_size}\n"
sudo tpm2_nvwrite  "${h_ek_pub_crt}" -C "${h_authorization}" -i /home/kali/simulated-tpm/ek-cert-pem

sudo rm ek.unused.private.key ekcert.csr
