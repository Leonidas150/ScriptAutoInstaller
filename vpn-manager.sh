#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CONFIG_DIR="/etc/vpn-manager"
USERS_DIR="$CONFIG_DIR/users"
LOG_FILE="/var/log/vpn-manager.log"

# Create necessary directories
mkdir -p "$CONFIG_DIR" "$USERS_DIR"
touch "$LOG_FILE"

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo -e "$1"
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
    log_message "${RED}This script must be run as root${NC}"
    exit 1
fi

# Function to check OS compatibility
check_os() {
    if [[ -e /etc/debian_version ]]; then
        OS="debian"
        source /etc/os-release
    elif [[ -e /etc/centos-release ]]; then
        OS="centos"
    else
        log_message "${RED}This script only works on Debian and CentOS systems${NC}"
        exit 1
    fi
}

# Update system packages
update_system() {
    log_message "${YELLOW}Updating system packages...${NC}"
    if [[ "$OS" == "debian" ]]; then
        apt update -y && apt upgrade -y
        apt install -y curl wget unzip tar iptables
    elif [[ "$OS" == "centos" ]]; then
        yum update -y
        yum install -y curl wget unzip tar iptables
    fi
}

# User Management Functions
create_user() {
    local username="$1"
    local days="$2"
    local bandwidth="$3"
    local expiry_date=$(date -d "+$days days" '+%Y-%m-%d')
    
    # Create user config
    cat > "$USERS_DIR/${username}.conf" << EOF
USERNAME=$username
CREATED_DATE=$(date '+%Y-%m-%d')
EXPIRY_DATE=$expiry_date
BANDWIDTH_LIMIT=$bandwidth
BANDWIDTH_USED=0
EOF
    
    # Generate random passwords
    local ssh_password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
    local ss_password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
    local trojan_password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
    local l2tp_password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
    
    # Create SSH user
    add_ssh_user "$username" "$ssh_password"
    
    # Create V2Ray user
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    add_v2ray_user "$username" "$uuid"
    
    # Create Shadowsocks user
    add_shadowsocks_user "$username" "$ss_password"
    
    # Create WireGuard user
    add_wireguard_user "$username"
    
    # Create Trojan user
    add_trojan_user "$username" "$trojan_password"

    # Create OpenVPN user
    add_openvpn_user "$username"

    # Create L2TP user
    add_l2tp_user "$username" "$l2tp_password"
    
    log_message "${GREEN}User $username created successfully${NC}"
    
    # Show user credentials
    show_user_credentials "$username"
}

remove_user() {
    local username="$1"
    
    if [[ -f "$USERS_DIR/${username}.conf" ]]; then
        # Remove user configs
        rm -f "$USERS_DIR/${username}.conf"
        remove_v2ray_user "$username"
        remove_shadowsocks_user "$username"
        remove_wireguard_user "$username"
        remove_trojan_user "$username"
        remove_openvpn_user "$username"
        remove_l2tp_user "$username"
        log_message "${GREEN}User $username removed successfully${NC}"
    else
        log_message "${RED}User $username not found${NC}"
    fi
}

extend_user() {
    local username="$1"
    local days="$2"
    
    if [[ -f "$USERS_DIR/${username}.conf" ]]; then
        source "$USERS_DIR/${username}.conf"
        local new_expiry=$(date -d "$EXPIRY_DATE +$days days" '+%Y-%m-%d')
        sed -i "s/EXPIRY_DATE=.*/EXPIRY_DATE=$new_expiry/" "$USERS_DIR/${username}.conf"
        log_message "${GREEN}Extended user $username expiry to $new_expiry${NC}"
    else
        log_message "${RED}User $username not found${NC}"
    fi
}

set_bandwidth() {
    local username="$1"
    local bandwidth="$2"
    
    if [[ -f "$USERS_DIR/${username}.conf" ]]; then
        sed -i "s/BANDWIDTH_LIMIT=.*/BANDWIDTH_LIMIT=$bandwidth/" "$USERS_DIR/${username}.conf"
        log_message "${GREEN}Set bandwidth limit for user $username to ${bandwidth}GB${NC}"
    else
        log_message "${RED}User $username not found${NC}"
    fi
}

# Server Management Functions
show_server_status() {
    echo -e "\n${BLUE}=== Server Status ===${NC}"
    echo -e "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
    echo -e "Memory Usage: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')"
    echo -e "Disk Usage: $(df -h / | awk 'NR==2{print $5}')"
    echo -e "Uptime: $(uptime -p)"
    echo -e "\n${BLUE}=== Active Users ===${NC}"
    ls -1 "$USERS_DIR" | grep .conf | sed 's/.conf//'
}

show_user_status() {
    local username="$1"
    
    if [[ -f "$USERS_DIR/${username}.conf" ]]; then
        source "$USERS_DIR/${username}.conf"
        echo -e "\n${BLUE}=== User Status: $username ===${NC}"
        echo -e "Created Date: $CREATED_DATE"
        echo -e "Expiry Date: $EXPIRY_DATE"
        echo -e "Bandwidth Limit: ${BANDWIDTH_LIMIT}GB"
        echo -e "Bandwidth Used: ${BANDWIDTH_USED}GB"
    else
        log_message "${RED}User $username not found${NC}"
    fi
}

# Function to show user credentials
show_user_credentials() {
    local username="$1"
    
    if [[ ! -f "$USERS_DIR/${username}.conf" ]]; then
        log_message "${RED}User $username not found${NC}"
        return 1
    fi
    
    # Header
    echo -e "\n${BLUE}════════════════════════════════════════════${NC}"
    echo -e "${BLUE}           User Credentials: $username${NC}"
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
    
    # Basic Info
    source "$USERS_DIR/${username}.conf"
    echo -e "\n${GREEN}▼ Basic Information${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Username     : $username"
    echo -e "Created Date : $CREATED_DATE"
    echo -e "Expiry Date  : $EXPIRY_DATE"
    echo -e "Bandwidth    : ${BANDWIDTH_USED}GB / ${BANDWIDTH_LIMIT}GB"
    
    # SSH Information
    if id "$username" >/dev/null 2>&1; then
        echo -e "\n${GREEN}▼ SSH Access${NC}"
        echo -e "━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "Host         : $(curl -s ifconfig.me)"
        echo -e "Port         : 22"
        echo -e "Username     : $username"
        if [[ -n "$SSH_PASS" ]]; then
            echo -e "Password     : $SSH_PASS"
        fi
    fi
    
    # V2Ray
    local v2ray_uuid=$(jq -r --arg email "$username" '.inbounds[0].settings.clients[] | select(.email==$email) | .id' /usr/local/etc/v2ray/config.json 2>/dev/null)
    if [[ ! -z "$v2ray_uuid" ]]; then
        echo -e "\n${GREEN}▼ V2Ray (VMess)${NC}"
        echo -e "━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "Address      : $(curl -s ifconfig.me)"
        echo -e "Port         : $V2RAY_PORT"
        echo -e "UUID         : $v2ray_uuid"
        echo -e "AlterID      : 0"
        echo -e "Network      : ws"
        echo -e "Path         : /v2ray"
    fi
    
    # Shadowsocks
    if [[ -f "/etc/shadowsocks-libev/${username}.json" ]]; then
        echo -e "\n${GREEN}▼ Shadowsocks${NC}"
        echo -e "━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "Address      : $(curl -s ifconfig.me)"
        local ss_port=$(jq -r '.server_port' "/etc/shadowsocks-libev/${username}.json")
        local ss_pass=$(jq -r '.password' "/etc/shadowsocks-libev/${username}.json")
        local ss_method=$(jq -r '.method' "/etc/shadowsocks-libev/${username}.json")
        echo -e "Port         : $ss_port"
        echo -e "Password     : $ss_pass"
        echo -e "Method       : $ss_method"
    fi
    
    # WireGuard
    if [[ -f "/etc/wireguard/clients/${username}.conf" ]]; then
        echo -e "\n${GREEN}▼ WireGuard${NC}"
        echo -e "━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "Config File  : /etc/wireguard/clients/${username}.conf"
        echo -e "\nConfig Content:"
        echo -e "────────────────────────"
        cat "/etc/wireguard/clients/${username}.conf"
        echo -e "────────────────────────"
    fi
    
    # Trojan
    if [[ -f "/etc/trojan/config.json" ]]; then
        echo -e "\n${GREEN}▼ Trojan${NC}"
        echo -e "━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "Address      : $(curl -s ifconfig.me)"
        echo -e "Port         : $TROJAN_PORT"
        if [[ -n "$TROJAN_PASS" ]]; then
            echo -e "Password     : $TROJAN_PASS"
        fi
    fi

    # OpenVPN
    if [[ -f "/etc/openvpn/clients/${username}.ovpn" ]]; then
        echo -e "\n${GREEN}▼ OpenVPN${NC}"
        echo -e "━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "Config File  : /etc/openvpn/clients/${username}.ovpn"
        echo -e "Download the .ovpn file to use with your OpenVPN client"
    fi

    # L2TP/IPsec
    if grep -q "^$username " /etc/ppp/chap-secrets; then
        echo -e "\n${GREEN}▼ L2TP/IPsec${NC}"
        echo -e "━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "Address      : $(curl -s ifconfig.me)"
        echo -e "Username     : $username"
        if [[ -n "$L2TP_PASS" ]]; then
            echo -e "Password     : $L2TP_PASS"
        fi
        source /etc/vpn-manager/config.conf
        echo -e "IPsec PSK    : $L2TP_PSK"
    fi
    
    # Footer
    echo -e "\n${BLUE}════════════════════════════════════════════${NC}"
    
    # Save to file option
    read -p "Do you want to save these credentials to a file? [y/N] " save_choice
    if [[ "${save_choice,,}" == "y" ]]; then
        local save_file="${username}_credentials.txt"
        show_user_credentials "$username" > "$save_file" 2>&1
        echo -e "${GREEN}Credentials saved to $save_file${NC}"
    fi
}

# Main Menu
show_menu() {
    clear
    echo -e "${GREEN}=== VPN Manager ===${NC}"
    echo "1. Create User"
    echo "2. Remove User"
    echo "3. Extend User"
    echo "4. Set Bandwidth"
    echo "5. Show Server Status"
    echo "6. Show User Status"
    echo "7. Show User Credentials"
    echo "8. Install/Reinstall VPN Services"
    echo "9. Setup SSH Server"
    echo "10. Check Ports Status"
    echo "11. Configure Firewall"
    echo "12. Edit Banner"
    echo "13. Exit"
}

# Main Loop
while true; do
    show_menu
    read -p "Select an option [1-13]: " choice
    
    case $choice in
        1)
            read -p "Enter username: " username
            read -p "Enter duration (days): " days
            read -p "Enter bandwidth limit (GB): " bandwidth
            create_user "$username" "$days" "$bandwidth"
            ;;
        2)
            read -p "Enter username to remove: " username
            remove_user "$username"
            ;;
        3)
            read -p "Enter username: " username
            read -p "Enter additional days: " days
            extend_user "$username" "$days"
            ;;
        4)
            read -p "Enter username: " username
            read -p "Enter new bandwidth limit (GB): " bandwidth
            set_bandwidth "$username" "$bandwidth"
            ;;
        5)
            show_server_status
            ;;
        6)
            read -p "Enter username: " username
            show_user_status "$username"
            ;;
        7)
            read -p "Enter username: " username
            show_user_credentials "$username"
            ;;
        8)
            check_os
            update_system
            install_v2ray
            install_shadowsocks
            install_wireguard
            install_trojan
            install_slowdns
            setup_openvpn
            setup_l2tp
            setup_firewall
            ;;
        9)
            setup_ssh_server
            ;;
        10)
            check_ports_status
            ;;
        11)
            setup_firewall
            ;;
        12)
            edit_banner
            ;;
        13)
            echo -e "${GREEN}Thank you for using VPN Manager${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
done 