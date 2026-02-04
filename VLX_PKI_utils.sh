#!/bin/bash

function show_help {
    echo "Usage: $0 [option]"
    echo ""
    echo "Options:"
    echo "  update          Update the toolset from GitHub (git pull)"
    echo "  https <port>    Check SSL certificate validity for localhost on <port>"
    echo "  help            Show this help message"
}

function check_cert {
    local PORT=$1
    if [[ -z "$PORT" ]]; then
        echo "Error: Port number required."
        echo "Usage: $0 https <port>"
        exit 1
    fi

    # Retrieve expiration date
    EXP_DATE=$(openssl s_client -connect localhost:$PORT -showcerts </dev/null 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2)

    if [[ -z "$EXP_DATE" ]]; then
        echo "[ERR]: Could not retrieve certificate from localhost:$PORT"
        exit 1
    fi

    # Convert dates to seconds
    EXP_DATE_S=$(date -d "$EXP_DATE" +%s)
    NOW_S=$(date +%s)

    # Calculate days left
    # Using bash arithmetic
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

# Main logic
if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

case "$1" in
    update)
        update_repo
        ;;
    https)
        check_cert "$2"
        ;;
    help)
        show_help
        ;;
    *)
        echo "Invalid option: $1"
        show_help
        exit 1
        ;;
esac
