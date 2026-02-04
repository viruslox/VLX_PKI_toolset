#!/bin/bash

KEY_PARAM="-algorithm EC -pkeyopt ec_paramgen_curve:secp384r1"
ENC="-aes256"
DAYS="825"
DIGEST="-sha512"
SUBJ_BASE="/C=IT/O=MiaAzienda/OU=IT"

mkdir -p certs private csr config

generate_cnf() {
    local type=$1 # root, inter, server, client
    local cn=$2
    local alt_names=$3

    cat <<EOF > config/$cn.cnf
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = IT
O = MiaAzienda
CN = $cn

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[v3_inter]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[v3_srv]
network_auth = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $alt_names

[v3_mtls]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = $alt_names
EOF
}

show_menu() {
    echo "------------------------------------------------"
    echo "      PKI AUTOMATION TOOL - OPENSSL             "
    echo "------------------------------------------------"
    echo "1) Create Root CA"
    echo "2) Create Intermediate CA (RootCA required)"
    echo "3) Create HTTPS/TLS Cert (Standard)"
    echo "4) Create mTLS Certs (Server + Client)"
    echo "5) Create CSR for external CA"
    echo "6) Crate Keystore (Tomcat) e Chain (Apache)"
    echo "q) Quit"
    echo "------------------------------------------------"
    read -p "Choose desired task: " opt
}

while true; do
    show_menu
    case $opt in
        1) # ROOT CA
            read -p "Common Name (es. RootCA): " cn
            generate_cnf root "$cn" ""
            openssl genpkey $KEY_PARAM -out private/$cn.key $ENC
            openssl req -x509 -new -key private/$cn.key -config config/$cn.cnf -extensions v3_ca -days 3650 -out certs/$cn.crt
            echo "Root CA creata: certs/$cn.crt"
            ;;

        2) # INTERMEDIATE CA
            read -p "Common Name Intermediate: " cn
            read -p "Nome file Root CA (es. RootCA.crt): " root_crt
            read -p "Nome file Root Key (es. RootCA.key): " root_key
            
            generate_cnf inter "$cn" ""
            openssl genpkey $KEY_PARAM -out private/$cn.key $ENC
            openssl req -new -key private/$cn.key -config config/$cn.cnf -out csr/$cn.csr
            openssl x509 -req -in csr/$cn.csr -CA certs/$root_crt -CAkey private/$root_key -CAcreateserial \
                -extfile config/$cn.cnf -extensions v3_inter -days 1825 -out certs/$cn.crt
            echo "Intermediate CA creata e firmata."
            ;;

        3|4) # TLS / mTLS
            read -p "Dominio (es. app.lan): " domain
            read -p "IP (es. 10.0.0.1 o lasciare vuoto): " ip
            read -p "CA per firma (es. InterCA.crt): " ca_crt
            read -p "Key della CA (es. InterCA.key): " ca_key
            
            alts="DNS:$domain,DNS:*.$domain"
            [[ ! -z "$ip" ]] && alts+=",IP:$ip"
            
            ext="v3_srv"
            [[ "$opt" == "4" ]] && ext="v3_mtls"

            generate_cnf "$ext" "$domain" "$alts"
            openssl genpkey $KEY_PARAM -out private/$domain.key
            openssl req -new -key private/$domain.key -config config/$domain.cnf -out csr/$domain.csr
            openssl x509 -req -in csr/$domain.csr -CA certs/$ca_crt -CAkey private/$ca_key -CAcreateserial \
                -extfile config/$domain.cnf -extensions $ext -days $DAYS -out certs/$domain.crt
            echo "Certificato $ext generato."
            ;;

        6) # KEYSTORE & CHAIN
            read -p "Nome base certificato (es. app.lan): " base
            read -p "Nome CA o Intermediate per la Chain: " ca_name
            
            # Chain per Apache
            cat certs/$base.crt certs/$ca_name.crt > certs/$base-fullchain.crt
            
            # Keystore per Tomcat (PKCS12)
            openssl pkcs12 -export -in certs/$base.crt -inkey private/$base.key \
                -out certs/$base.p12 -name tomcat -CAfile certs/$ca_name.crt -caname root
            echo "Chain creata: certs/$base-fullchain.crt"
            echo "Keystore PKCS12 creato: certs/$base.p12"
            ;;

        q) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
done
