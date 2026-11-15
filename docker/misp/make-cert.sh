#!/bin/sh
# Creates a private lab CA and a server cert for https://127.0.0.1:8443.
# Run inside a throwaway container by scripts/misp-up.ps1 (output dir mounted at /out).
# Clients trust ca.pem (MISP_VERIFY_SSL=<path to ca.pem>), so TLS verification stays ON.
set -eu
apk add --no-cache openssl >/dev/null
cd /out
umask 077
openssl req -x509 -newkey rsa:3072 -nodes -days 825 -sha256 \
  -keyout ca-key.pem -out ca.pem -subj "/CN=HexBrief Lab CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -sha256 -keyout key.pem -out server.csr \
  -subj "/CN=127.0.0.1" 2>/dev/null
cat > ext.cnf <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:host.docker.internal
authorityKeyIdentifier=keyid,issuer
subjectKeyIdentifier=hash
EOF
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 825 -sha256 -extfile ext.cnf -out cert.pem 2>/dev/null
rm -f server.csr ext.cnf ca.srl ca-key.pem   # the CA key is not needed again
chmod 644 cert.pem ca.pem key.pem            # nginx runs as uid 101 and must read key.pem
echo "lab cert created (CA key discarded)"
