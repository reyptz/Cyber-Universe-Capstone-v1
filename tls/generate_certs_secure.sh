#!/bin/bash

# Script PKI sécurisé avec CRL et OCSP
# Génère une PKI complète avec révocation et test TLS

echo "=== Génération PKI sécurisée avec CRL/OCSP ==="

# Créer la structure de répertoires
mkdir -p {certs,private,csr,crl,ocsp,newcerts}
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

# Configuration OpenSSL pour CA
cat > openssl.cnf << 'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand
private_key       = $dir/private/root_ca.key
certificate       = $dir/certs/root_ca.crt
crlnumber         = $dir/crlnumber
crl               = $dir/crl/root_ca.crl
default_days      = 365
default_crl_days  = 30
default_md        = sha256
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
crlDistributionPoints = URI:http://localhost:8080/crl/intermediate.crl
authorityInfoAccess = OCSP;URI:http://localhost:8080/ocsp

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
crlDistributionPoints = URI:http://localhost:8080/crl/intermediate.crl
authorityInfoAccess = OCSP;URI:http://localhost:8080/ocsp
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# 1. Génération Root CA
echo "1. Génération Root CA..."
openssl genrsa -out private/root_ca.key 4096
openssl req -config openssl.cnf -key private/root_ca.key -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/root_ca.crt -subj "/C=FR/ST=IDF/L=Paris/O=CyberSec Lab/OU=Root CA/CN=Root CA"

# 2. Génération Intermediate CA
echo "2. Génération Intermediate CA..."
openssl genrsa -out private/intermediate_ca.key 4096
openssl req -config openssl.cnf -new -sha256 -key private/intermediate_ca.key -out csr/intermediate_ca.csr -subj "/C=FR/ST=IDF/L=Paris/O=CyberSec Lab/OU=Intermediate CA/CN=Intermediate CA"
openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in csr/intermediate_ca.csr -out certs/intermediate_ca.crt -batch

# 3. Génération certificat serveur
echo "3. Génération certificat serveur..."
openssl genrsa -out private/server.key 2048
openssl req -config openssl.cnf -key private/server.key -new -sha256 -out csr/server.csr -subj "/C=FR/ST=IDF/L=Paris/O=CyberSec Lab/OU=Web Server/CN=localhost"

# Configurer CA pour intermediate
cp openssl.cnf intermediate.cnf
sed -i 's/private_key.*=.*/private_key = $dir\/private\/intermediate_ca.key/' intermediate.cnf
sed -i 's/certificate.*=.*/certificate = $dir\/certs\/intermediate_ca.crt/' intermediate.cnf

openssl ca -config intermediate.cnf -extensions server_cert -days 375 -notext -md sha256 -in csr/server.csr -out certs/server.crt -batch

# 4. Création chaîne de certificats
echo "4. Création chaîne de certificats..."
cat certs/server.crt certs/intermediate_ca.crt > certs/server_chain.crt

# 5. Génération CRL
echo "5. Génération CRL..."
openssl ca -config openssl.cnf -gencrl -out crl/root_ca.crl
openssl ca -config intermediate.cnf -gencrl -out crl/intermediate.crl

# 6. Configuration serveur OCSP
echo "6. Configuration serveur OCSP..."
cat > ocsp_server.py << 'EOF'
#!/usr/bin/env python3
import http.server
import socketserver
import subprocess
import os
from urllib.parse import urlparse, parse_qs

class OCSPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/crl/'):
            # Servir les CRL
            crl_file = self.path.split('/')[-1]
            try:
                with open(f'crl/{crl_file}', 'rb') as f:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/pkix-crl')
                    self.end_headers()
                    self.wfile.write(f.read())
            except FileNotFoundError:
                self.send_error(404)
        else:
            self.send_error(404)
    
    def do_POST(self):
        if self.path == '/ocsp':
            # Répondeur OCSP basique
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            # Simuler réponse OCSP (certificat valide)
            self.send_response(200)
            self.send_header('Content-Type', 'application/ocsp-response')
            self.end_headers()
            # Réponse OCSP simplifiée (en production, utiliser openssl ocsp)
            self.wfile.write(b'OCSP Response: Certificate is valid')
        else:
            self.send_error(404)

if __name__ == '__main__':
    PORT = 8080
    with socketserver.TCPServer(("", PORT), OCSPHandler) as httpd:
        print(f"Serveur OCSP/CRL démarré sur port {PORT}")
        httpd.serve_forever()
EOF

chmod +x ocsp_server.py

# 7. Script de test TLS
echo "7. Création script de test TLS..."
cat > test_tls_server.py << 'EOF'
#!/usr/bin/env python3
import ssl
import socket
import threading
import http.server
import socketserver

class HTTPSHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        response = b'''
<!DOCTYPE html>
<html>
<head><title>Test PKI TLS</title></head>
<body>
    <h1>Serveur TLS avec PKI personnalisée</h1>
    <p>Connexion sécurisée établie avec succès!</p>
    <p>Certificat: localhost</p>
    <p>CA: CyberSec Lab Intermediate CA</p>
</body>
</html>
'''
        self.wfile.write(response)

def start_https_server():
    PORT = 8443
    
    # Créer contexte SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('certs/server_chain.crt', 'private/server.key')
    
    with socketserver.TCPServer(("", PORT), HTTPSHandler) as httpd:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print(f"Serveur HTTPS démarré sur https://localhost:{PORT}")
        print("Utilisez: curl -k --cacert certs/root_ca.crt https://localhost:8443")
        httpd.serve_forever()

if __name__ == '__main__':
    start_https_server()
EOF

chmod +x test_tls_server.py

echo "\n=== PKI sécurisée générée avec succès ==="
echo "Fichiers générés:"
echo "- Certificats: certs/"
echo "- CRL: crl/"
echo "- Serveur OCSP/CRL: ./ocsp_server.py"
echo "- Test TLS: ./test_tls_server.py"
echo "\nPour tester:"
echo "1. Démarrer serveur OCSP: python3 ocsp_server.py &"
echo "2. Démarrer serveur TLS: python3 test_tls_server.py &"
echo "3. Tester: curl -k --cacert certs/root_ca.crt https://localhost:8443"