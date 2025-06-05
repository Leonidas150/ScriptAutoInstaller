#!/bin/bash

# Load configuration
source /etc/vpn-manager/config.conf

# Function to update DNS record
update_dns_record() {
    local name="$1"
    local ip="$2"
    
    # Check if record exists
    local record_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?name=$name.$CF_DOMAIN" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" | jq -r '.result[0].id')
    
    if [[ "$record_id" != "null" ]]; then
        # Update existing record
        curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$record_id" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$name\",\"content\":\"$ip\",\"proxied\":false}"
    else
        # Create new record
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$name\",\"content\":\"$ip\",\"proxied\":false}"
    fi
}

# Function to remove DNS record
remove_dns_record() {
    local name="$1"
    
    # Get record ID
    local record_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?name=$name.$CF_DOMAIN" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" | jq -r '.result[0].id')
    
    if [[ "$record_id" != "null" ]]; then
        # Delete record
        curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$record_id" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json"
    fi
}

# Function to setup all VPN DNS records
setup_vpn_dns() {
    local server_ip=$(curl -s ifconfig.me)
    
    # Update DNS records for all services
    update_dns_record "vpn" "$server_ip"
    update_dns_record "v2ray" "$server_ip"
    update_dns_record "ss" "$server_ip"
    update_dns_record "wg" "$server_ip"
    update_dns_record "trojan" "$server_ip"
    update_dns_record "dns" "$server_ip"
    
    log_message "Updated all DNS records to point to $server_ip"
}

# Function to remove all VPN DNS records
remove_vpn_dns() {
    # Remove all service DNS records
    remove_dns_record "vpn"
    remove_dns_record "v2ray"
    remove_dns_record "ss"
    remove_dns_record "wg"
    remove_dns_record "trojan"
    remove_dns_record "dns"
    
    log_message "Removed all VPN DNS records"
}

# Function to setup SlowDNS
setup_slowdns() {
    local ns_domain="$1"
    
    # Install required packages
    if [[ "$OS" == "debian" ]]; then
        apt install -y bind9 dnsutils
    elif [[ "$OS" == "centos" ]]; then
        yum install -y bind bind-utils
    fi
    
    # Configure named
    cat > /etc/bind/named.conf.local << EOF
zone "$ns_domain" {
    type master;
    file "/etc/bind/db.$ns_domain";
};
EOF
    
    # Create zone file
    cat > "/etc/bind/db.$ns_domain" << EOF
\$TTL    3600
@       IN      SOA     ns1.$ns_domain. admin.$ns_domain. (
                        $(date +%s) ; Serial
                        3600       ; Refresh
                        1800       ; Retry
                        604800     ; Expire
                        86400 )    ; Minimum TTL
@       IN      NS      ns1.$ns_domain.
ns1     IN      A       $(curl -s ifconfig.me)
EOF
    
    # Restart bind
    systemctl restart named
    
    # Update DNS record for NS
    update_dns_record "ns1" "$(curl -s ifconfig.me)"
    
    log_message "SlowDNS setup completed with domain: $ns_domain"
}

# Check if being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being run directly
    case "$1" in
        setup)
            setup_vpn_dns
            ;;
        remove)
            remove_vpn_dns
            ;;
        slowdns)
            if [[ -z "$2" ]]; then
                echo "Usage: $0 slowdns domain.com"
                exit 1
            fi
            setup_slowdns "$2"
            ;;
        *)
            echo "Usage: $0 {setup|remove|slowdns domain.com}"
            exit 1
            ;;
    esac
fi 