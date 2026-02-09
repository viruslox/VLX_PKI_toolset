#!/bin/bash

# VLX PKI Toolset - Consolidated Script
# Integrates functionality from VLX_PKI_toolset.sh and VLX_PKI_utils.sh
#
# Usage:
#   ./VLX_PKI.sh [option]
#   ./VLX_PKI.sh (interactive mode)

# --- Configuration and Constants ---
KEY_PARAM="-algorithm EC -pkeyopt ec_paramgen_curve:secp384r1"
DAYS="825"
DIGEST="-sha512"
SUBJ_BASE="/C=IT/O=MiaAzienda/OU=IT"

# --- Utility Functions (from VLX_PKI_utils.sh) ---

function show_help {
    echo "Usage: $0 [option]"
    echo ""
    echo "Options:"
    echo "  update          Update the toolset from GitHub (git pull)"
    echo "  https <port>    Check SSL certificate validity for localhost on <port>"
    echo "  help            Show this help message"
    echo ""
    echo "Run without arguments for Interactive Mode."
}

function check_cert {
    local PORT=$1
    if [[ -z "$PORT" ]]; then
        echo "Error: Port number required."
        echo "Usage: $0 https <port>"
        return 1
    fi

    echo "Checking certificate on localhost:$PORT..."

    # Retrieve expiration date
    EXP_DATE=$(openssl s_client -connect localhost:$PORT -showcerts </dev/null 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2)

    if [[ -z "$EXP_DATE" ]]; then
        echo "[ERR]: Could not retrieve certificate from localhost:$PORT"
        return 1
    fi

    # Convert dates to seconds
    EXP_DATE_S=$(date -d "$EXP_DATE" +%s)
    NOW_S=$(date +%s)

    # Calculate days left using bash arithmetic
    DIFF_S=$(( EXP_DATE_S - NOW_S ))
    DAYS_LEFT=$(( DIFF_S / 86400 ))

    if [[ $DAYS_LEFT -gt 0 ]]; then
        echo "Certificate is valid."
        if [[ $DAYS_LEFT -lt 30 ]]; then
            echo "[WARN]: The certificate is about to expire ($DAYS_LEFT days)."
        else
            echo "Days until expiration: $DAYS_LEFT"
        fi
    else
        echo "[ERR]: The certificate is expired."
    fi
}

function update_repo {
    echo "Updating repository..."
    git pull
}

# --- PKI Helper Functions ---

function ensure_dirs {
    mkdir -p certs private csr config
}

function ask_subject_details {
    local def_c="IT"
    local def_o="MiaAzienda"

    echo "Default Subject: C=$def_c, O=$def_o"
    read -p "Customize Subject? [y/N]: " yn
    if [[ "$yn" =~ ^[Yy] ]]; then
        read -p "Country (C) [$def_c]: " user_c
        read -p "Organization (O) [$def_o]: " user_o
        CONF_C="${user_c:-$def_c}"
        CONF_O="${user_o:-$def_o}"
    else
        CONF_C="$def_c"
        CONF_O="$def_o"
    fi
}

function collect_sans {
    local domain=$1
    local dns_list=()
    local ip_list=()

    # Defaults
    dns_list+=("$domain")
    dns_list+=("*.$domain")

    while true; do
         echo "Current SANs:"
         echo "  DNS: ${dns_list[*]}"
         echo "  IP:  ${ip_list[*]}"
         read -p "Do you want to add another Subject Alternative Name (SAN)? [y/N]: " add_san
         if [[ ! "$add_san" =~ ^[Yy] ]]; then break; fi

         echo "Type: 1) DNS  2) IP"
         read -p "Select type: " stype
         if [ "$stype" == "1" ]; then
             read -p "Enter DNS name: " val
             if [ -n "$val" ]; then dns_list+=("$val"); fi
         elif [ "$stype" == "2" ]; then
             read -p "Enter IP address: " val
             if [ -n "$val" ]; then ip_list+=("$val"); fi
         fi
    done

    # Build block
    SAN_BLOCK=$'[ alt_names ]'
    local i=1
    for d in "${dns_list[@]}"; do
        SAN_BLOCK+=$'\n'"DNS.$i = $d"
        ((i++))
    done

    local j=1
    for ip in "${ip_list[@]}"; do
        SAN_BLOCK+=$'\n'"IP.$j = $ip"
        ((j++))
    done
}

function generate_cnf {
    local type=$1 # root, inter, server, client
    local cn=$2
    local san_block=$3
    local c_val=$4
    local o_val=$5

    # Ensure config dir exists
    mkdir -p config

    local san_line=""
    if [ -n "$san_block" ]; then
        san_line="subjectAltName = @alt_names"
    fi

    cat <<EOF > config/$cn.cnf
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = $c_val
O = $o_val
CN = $cn

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[v3_inter]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[v3_srv]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
$san_line

[v3_mtls]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
$san_line
EOF

    if [ -n "$san_block" ]; then
        echo "$san_block" >> config/$cn.cnf
    fi
}

# Check if user wants to password protect the key
function get_enc_opt {
    echo "" >&2
    echo "Do you want to password-protect the private key?" >&2
    echo "If 'y', you will be prompted to enter a password." >&2
    echo "If 'n', the key will be generated without a password." >&2
    read -p "Enable password protection? [y/N]: " yn
    case $yn in
        [Yy]* ) echo "-aes256";;
        * ) echo "";;
    esac
}

# List CAs in certs/ directory
# type: "root", "inter", or "all"
function list_cas {
    local type=$1

    if [ ! -d "certs" ]; then return; fi

    # Enable nullglob to handle empty certs directory safely
    shopt -s nullglob
    local crt_files=(certs/*.crt)
    shopt -u nullglob

    for f in "${crt_files[@]}"; do
        # Check if it is a CA
        if openssl x509 -in "$f" -noout -text 2>/dev/null | grep -q "CA:TRUE"; then
            local subject=$(openssl x509 -in "$f" -noout -subject_hash 2>/dev/null)
            local issuer=$(openssl x509 -in "$f" -noout -issuer_hash 2>/dev/null)

            # Identify if Root or Intermediate
            local is_root=false
            if [ "$subject" == "$issuer" ]; then
                is_root=true
            fi

            if [ "$type" == "root" ] && [ "$is_root" = true ]; then
                basename "$f"
            elif [ "$type" == "inter" ] && [ "$is_root" = false ]; then
                basename "$f"
            elif [ "$type" == "all" ]; then
                basename "$f"
            fi
        fi
    done
}

# List Leaf Certs (Not CAs)
function list_leafs {
    if [ ! -d "certs" ]; then return; fi

    shopt -s nullglob
    local crt_files=(certs/*.crt)
    shopt -u nullglob

    for f in "${crt_files[@]}"; do
        # Check if it is NOT a CA
        if ! openssl x509 -in "$f" -noout -text 2>/dev/null | grep -q "CA:TRUE"; then
             basename "$f"
        fi
    done
}

# Select a CA from the list
# Returns the filename of the selected CA
function select_ca {
    local type=$1
    local prompt=$2

    local options=()
    mapfile -t options < <(list_cas "$type")

    if [ ${#options[@]} -eq 0 ]; then
        echo "No CAs found of type '$type'." >&2
        return 1
    fi

    echo "$prompt" >&2
    PS3="Select CA: "
    select opt in "${options[@]}"; do
        if [ -n "$opt" ]; then
            echo "$opt"
            return 0
        else
            echo "Invalid selection." >&2
        fi
    done
}

# --- Core PKI Logic ---

function create_root_ca {
    ensure_dirs

    # Check for existing Root CAs
    local roots=()
    mapfile -t roots < <(list_cas root)
    local cn=""

    if [ ${#roots[@]} -gt 0 ]; then
        echo "------------------------------------------------"
        echo "Existing Root CAs found:"
        local i=1
        for r in "${roots[@]}"; do
            echo " $i) $r"
            ((i++))
        done
        echo "------------------------------------------------"

        read -p "Do you want to (c)reate a NEW Root CA or (u)pdate/overwrite an existing one? [c/u]: " action
        if [ "$action" == "u" ]; then
            PS3="Select Root CA to update: "
            select r in "${roots[@]}"; do
                if [ -n "$r" ]; then
                    cn="${r%.crt}" # Remove extension
                    break
                else
                    echo "Invalid selection."
                fi
            done
        else
            read -p "Common Name (e.g. RootCA): " input_cn
            cn="$input_cn"
        fi
    else
        read -p "Common Name (e.g. RootCA): " input_cn
        cn="$input_cn"
    fi

    if [ -z "$cn" ]; then echo "Operation cancelled."; return; fi

    ask_subject_details
    local enc=$(get_enc_opt)

    generate_cnf root "$cn" "" "$CONF_C" "$CONF_O"
    echo "Generating key..."
    openssl genpkey $KEY_PARAM -out private/$cn.key $enc
    echo "Generating certificate..."
    openssl req -x509 -new -key private/$cn.key -config config/$cn.cnf -extensions v3_ca -days 3650 -out certs/$cn.crt
    echo "Root CA created: certs/$cn.crt"
}

function create_intermediate_ca {
    ensure_dirs

    # Need at least one Root CA
    local all_cas=()
    mapfile -t all_cas < <(list_cas all)
    if [ ${#all_cas[@]} -eq 0 ]; then
        echo "No Root or Intermediate CAs found. Please create a Root CA first."
        return
    fi

    # Check for existing Intermediates to update
    local inters=()
    mapfile -t inters < <(list_cas inter)
    local cn=""

    if [ ${#inters[@]} -gt 0 ]; then
        echo "------------------------------------------------"
        echo "Existing Intermediate CAs found:"
        local i=1
        for r in "${inters[@]}"; do
            echo " $i) $r"
            ((i++))
        done
        echo "------------------------------------------------"

        read -p "Do you want to (c)reate a NEW Intermediate CA or (u)pdate/overwrite an existing one? [c/u]: " action
        if [ "$action" == "u" ]; then
            PS3="Select Intermediate CA to update: "
            select r in "${inters[@]}"; do
                if [ -n "$r" ]; then
                    cn="${r%.crt}"
                    break
                else
                    echo "Invalid selection."
                fi
            done
        else
            read -p "Common Name Intermediate (e.g. InterCA): " input_cn
            cn="$input_cn"
        fi
    else
        read -p "Common Name Intermediate (e.g. InterCA): " input_cn
        cn="$input_cn"
    fi

    if [ -z "$cn" ]; then echo "Operation cancelled."; return; fi

    # Select Signing CA (Parent)
    # Can be Root or another Intermediate
    echo "------------------------------------------------"
    local parent_crt=$(select_ca all "Select the Parent CA (Root or Intermediate) to sign this new Intermediate:")
    if [ $? -ne 0 ]; then return; fi

    local parent_name="${parent_crt%.crt}"
    local parent_key="private/${parent_name}.key"

    if [ ! -f "$parent_key" ]; then
        echo "Error: Private key for $parent_name not found at $parent_key."
        return
    fi

    ask_subject_details
    local enc=$(get_enc_opt)

    generate_cnf inter "$cn" "" "$CONF_C" "$CONF_O"
    echo "Generating key..."
    openssl genpkey $KEY_PARAM -out private/$cn.key $enc
    echo "Generating CSR..."
    openssl req -new -key private/$cn.key -config config/$cn.cnf -out csr/$cn.csr
    echo "Signing Intermediate CA..."
    openssl x509 -req -in csr/$cn.csr -CA certs/$parent_crt -CAkey "$parent_key" -CAcreateserial \
        -extfile config/$cn.cnf -extensions v3_inter -days 1825 -out certs/$cn.crt
    echo "Intermediate CA created and signed: certs/$cn.crt"
}

function create_leaf_cert {
    local is_mtls=$1 # true if mtls
    local ext="v3_srv"
    if [ "$is_mtls" == "true" ]; then ext="v3_mtls"; fi

    ensure_dirs

    # Need a signing CA
    local all_cas=()
    mapfile -t all_cas < <(list_cas all)
    if [ ${#all_cas[@]} -eq 0 ]; then
        echo "No CAs found. Please create a CA first."
        return
    fi

    # Check existing leafs
    local leafs=()
    mapfile -t leafs < <(list_leafs)
    local domain=""

    if [ ${#leafs[@]} -gt 0 ]; then
         echo "------------------------------------------------"
         echo "Existing Leaf Certificates found:"
         local i=1
         for l in "${leafs[@]}"; do
             echo " $i) $l"
             ((i++))
         done
         echo "------------------------------------------------"

         read -p "Do you want to (c)reate a NEW Certificate or (u)pdate/overwrite an existing one? [c/u]: " action
         if [ "$action" == "u" ]; then
             PS3="Select Certificate to update: "
             select l in "${leafs[@]}"; do
                 if [ -n "$l" ]; then
                     domain="${l%.crt}"
                     break
                 else
                     echo "Invalid selection."
                 fi
             done
         else
             read -p "Domain (e.g. app.lan): " input_domain
             domain="$input_domain"
         fi
    else
         read -p "Domain (e.g. app.lan): " input_domain
         domain="$input_domain"
    fi

    if [ -z "$domain" ]; then echo "Operation cancelled."; return; fi

    collect_sans "$domain"

    # Select Signing CA
    echo "------------------------------------------------"
    local parent_crt=$(select_ca all "Select the Signing CA (Root or Intermediate):")
    if [ $? -ne 0 ]; then return; fi

    local parent_name="${parent_crt%.crt}"
    local parent_key="private/${parent_name}.key"

    if [ ! -f "$parent_key" ]; then
        echo "Error: Private key for $parent_name not found at $parent_key."
        return
    fi

    ask_subject_details
    local enc=$(get_enc_opt)

    generate_cnf "$ext" "$domain" "$SAN_BLOCK" "$CONF_C" "$CONF_O"
    echo "Generating key..."
    openssl genpkey $KEY_PARAM -out private/$domain.key $enc
    echo "Generating CSR..."
    openssl req -new -key private/$domain.key -config config/$domain.cnf -out csr/$domain.csr
    echo "Signing Certificate..."
    openssl x509 -req -in csr/$domain.csr -CA certs/$parent_crt -CAkey "$parent_key" -CAcreateserial \
        -extfile config/$domain.cnf -extensions $ext -days $DAYS -out certs/$domain.crt
    echo "Certificate generated: certs/$domain.crt"
}

function create_csr_external {
    ensure_dirs
    read -p "Domain (e.g. app.lan): " domain

    collect_sans "$domain"

    local ext="v3_srv"
    ask_subject_details
    local enc=$(get_enc_opt)

    generate_cnf "$ext" "$domain" "$SAN_BLOCK" "$CONF_C" "$CONF_O"
    echo "Generating key..."
    openssl genpkey $KEY_PARAM -out private/$domain.key $enc
    echo "Generating CSR..."
    openssl req -new -key private/$domain.key -config config/$domain.cnf -out csr/$domain.csr
    echo "CSR created: csr/$domain.csr"
}

function create_keystore {
    ensure_dirs

    # List existing certs? Just ask for name for now to keep it simple, or list .crt files that are NOT CAs?
    # Keeping it simple as per original script but adding checks.

    read -p "Certificate Base Name (e.g. app.lan): " base

    if [ ! -f "certs/$base.crt" ]; then
        echo "Error: Certificate certs/$base.crt not found."
        return
    fi

    if [ ! -f "private/$base.key" ]; then
        echo "Error: Key private/$base.key not found."
        return
    fi

    # Select Chain CA
    echo "------------------------------------------------"
    local ca_crt=$(select_ca all "Select the CA to include in the chain:")
    if [ $? -ne 0 ]; then return; fi

    local ca_name="${ca_crt%.crt}"

    # Chain for Apache
    cat certs/$base.crt certs/$ca_crt > certs/$base-fullchain.crt
    echo "Chain created: certs/$base-fullchain.crt"

    # Keystore for Tomcat (PKCS12)
    # Note: If key is encrypted, it will ask for pass phrase
    # It will also ask for export password
    echo "Creating PKCS12 Keystore..."
    openssl pkcs12 -export -in certs/$base.crt -inkey private/$base.key \
        -out certs/$base.p12 -name tomcat -CAfile certs/$ca_crt -caname root
    echo "Keystore PKCS12 created: certs/$base.p12"
}

# --- Interactive Menu ---

function show_menu {
    echo "------------------------------------------------"
    echo "      PKI AUTOMATION TOOL - OPENSSL             "
    echo "------------------------------------------------"
    echo "1) Create Root CA"
    echo "2) Create Intermediate CA"
    echo "3) Create HTTPS/TLS Cert (Standard)"
    echo "4) Create mTLS Certs (Server + Client)"
    echo "5) Create CSR for external CA"
    echo "6) Create Keystore (Tomcat) & Chain (Apache)"
    echo "7) Check Local Certificate Expiry"
    echo "8) Update Toolset"
    echo "q) Quit"
    echo "------------------------------------------------"
    read -p "Choose desired task: " opt
}

# --- Main Logic ---

if [[ $# -gt 0 ]]; then
    # Argument mode
    case "$1" in
        update)
            update_repo
            ;;
        https)
            check_cert "$2"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo "Invalid option: $1"
            show_help
            exit 1
            ;;
    esac
else
    # Interactive mode
    while true; do
        show_menu
        case $opt in
            1) create_root_ca ;;
            2) create_intermediate_ca ;;
            3) create_leaf_cert false ;;
            4) create_leaf_cert true ;;
            5) create_csr_external ;;
            6) create_keystore ;;
            7)
                read -p "Port to check: " port
                check_cert "$port"
                ;;
            8) update_repo ;;
            q) exit 0 ;;
            *) echo "Invalid option" ;;
        esac
        echo ""
    done
fi
