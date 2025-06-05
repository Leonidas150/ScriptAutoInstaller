#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to check if script is run as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

# Function to stop all VPN services
stop_services() {
    echo -e "${YELLOW}Stopping all VPN services...${NC}"
    services=("v2ray" "nginx" "trojan" "openvpn@server" "wg-quick@wg0" 
             "shadowsocks-libev" "bind9" "strongswan" "xl2tpd")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            systemctl stop $service
            systemctl disable $service
            echo -e "${GREEN}Stopped and disabled $service${NC}"
        fi
    done
}

# Function to remove all VPN packages
remove_packages() {
    echo -e "${YELLOW}Removing VPN packages...${NC}"
    apt-get purge -y v2ray nginx trojan openvpn wireguard shadowsocks-libev \
                     strongswan xl2tpd bind9 fail2ban
    apt-get autoremove -y
    apt-get clean
}

# Function to remove all VPN directories and files
remove_files() {
    echo -e "${YELLOW}Removing VPN directories and files...${NC}"
    directories=(
        "/etc/vpn-manager"
        "/var/www/download"
        "/var/www/html/monitor"
        "/var/log/vpn-manager"
        "/etc/v2ray"
        "/etc/wireguard"
        "/etc/openvpn"
        "/etc/shadowsocks-libev"
        "/etc/trojan"
        "/etc/slowdns"
    )
    
    for dir in "${directories[@]}"; do
        if [ -d "$dir" ]; then
            rm -rf "$dir"
            echo -e "${GREEN}Removed $dir${NC}"
        fi
    done
    
    # Remove binary files
    rm -f /usr/local/bin/vpn
    rm -f /usr/local/bin/vpn-uninstall
    rm -f /usr/local/bin/vpn-functions.sh
}

# Function to reset firewall rules
reset_firewall() {
    echo -e "${YELLOW}Resetting firewall rules...${NC}"
    ufw --force reset
    ufw --force disable
    
    # Remove all iptables rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Save iptables rules
    netfilter-persistent save
}

# Function to backup current configuration
backup_config() {
    echo -e "${YELLOW}Creating backup of current configuration...${NC}"
    backup_dir="/root/vpn-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup important configurations
    if [ -d "/etc/vpn-manager" ]; then
        cp -r /etc/vpn-manager "$backup_dir/"
    fi
    if [ -d "/etc/v2ray" ]; then
        cp -r /etc/v2ray "$backup_dir/"
    fi
    if [ -d "/etc/wireguard" ]; then
        cp -r /etc/wireguard "$backup_dir/"
    fi
    if [ -d "/etc/openvpn" ]; then
        cp -r /etc/openvpn "$backup_dir/"
    fi
    
    echo -e "${GREEN}Backup created at: $backup_dir${NC}"
}

# Function for complete cleanup
complete_cleanup() {
    echo -e "${RED}WARNING: This will completely remove all VPN services and configurations${NC}"
    echo -e "${RED}Are you sure you want to continue? (y/n)${NC}"
    read -r response
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        backup_config
        stop_services
        remove_packages
        remove_files
        reset_firewall
        echo -e "${GREEN}Complete cleanup finished. Your VPS has been restored to pre-installation state.${NC}"
        echo -e "${YELLOW}A backup of your configuration has been saved to /root/vpn-backup-*${NC}"
    else
        echo -e "${YELLOW}Cleanup cancelled${NC}"
    fi
}

# Function to display menu
show_menu() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       ${GREEN}VPN EMERGENCY MENU${NC}                ${BLUE}║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════╝${NC}"
    echo -e ""
    echo -e "${YELLOW}1${NC}. Stop All VPN Services"
    echo -e "${YELLOW}2${NC}. Remove VPN Packages"
    echo -e "${YELLOW}3${NC}. Reset Firewall Rules"
    echo -e "${YELLOW}4${NC}. Backup Current Configuration"
    echo -e "${RED}5${NC}. Complete System Cleanup (Uninstall Everything)"
    echo -e "${YELLOW}6${NC}. Exit"
    echo -e ""
    echo -e "${GREEN}Select an option:${NC} "
    read -r choice

    case $choice in
        1) stop_services ;;
        2) remove_packages ;;
        3) reset_firewall ;;
        4) backup_config ;;
        5) complete_cleanup ;;
        6) exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
    
    echo -e "\nPress Enter to continue..."
    read -r
    show_menu
}

# Main execution
check_root
show_menu 