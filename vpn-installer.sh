#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Check OS
if [[ ! -f /etc/os-release ]]; then
    echo -e "${RED}Cannot detect OS version${NC}"
    exit 1
fi

source /etc/os-release
OS=$ID
VER=$VERSION_ID

# Check compatibility
case "$OS" in
    "ubuntu")
        if [[ "$VER" != "18.04" && "$VER" != "20.04" ]]; then
            echo -e "${RED}This script only supports Ubuntu 18.04 and 20.04${NC}"
            exit 1
        fi
        ;;
    "debian")
        if [[ "$VER" != "10" ]]; then
            echo -e "${RED}This script only supports Debian 10${NC}"
            exit 1
        fi
        ;;
    *)
        echo -e "${RED}This script only supports Ubuntu and Debian systems${NC}"
        exit 1
        ;;
esac

# Show banner
clear
echo -e "${BLUE}╔═════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       ${GREEN}VPN MANAGEMENT INSTALLER${NC}         ${BLUE}║${NC}"
echo -e "${BLUE}║          ${YELLOW}All-In-One Setup${NC}              ${BLUE}║${NC}"
echo -e "${BLUE}╚═════════════════════════════════════════╝${NC}"
echo -e "\nInstalling on: ${GREEN}$OS $VER${NC}\n"

# Create installation directory
mkdir -p /etc/vpn-manager
cd /etc/vpn-manager

# Update system
echo -e "${YELLOW}Updating system packages...${NC}"
apt-get update
apt-get upgrade -y
apt-get dist-upgrade -y

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
apt-get install -y \
    curl wget unzip \
    git build-essential \
    nginx certbot python3-certbot-nginx \
    fail2ban net-tools \
    iptables-persistent \
    qrencode socat \
    apache2-utils \
    cron at \
    vnstat \
    jq \
    uuid-runtime \
    dropbear \
    stunnel4 \
    python3-pip \
    websocket \
    openssh-server

# Create all necessary directories
echo -e "${YELLOW}Creating directory structure...${NC}"
mkdir -p /etc/vpn-manager/{users,backups,logs,configs}
mkdir -p /var/www/{download,html/monitor}
mkdir -p /var/log/vpn-manager
mkdir -p /etc/slowdns/{users,keys}

# Setup logging with proper permissions
echo -e "${YELLOW}Setting up logging system...${NC}"
touch /var/log/vpn-manager/{events.log,access.log,error.log,install.log}
chmod 640 /var/log/vpn-manager/*.log
chown -R root:adm /var/log/vpn-manager

# Download main script and verify
echo -e "${YELLOW}Downloading VPN Manager...${NC}"
wget -O /usr/local/bin/vpn-functions.sh "https://raw.githubusercontent.com/Leonidas150/ScriptAutoInstaller/main/vpn-functions.sh"
if [ ! -f /usr/local/bin/vpn-functions.sh ]; then
    echo -e "${RED}Failed to download vpn-functions.sh${NC}"
    exit 1
fi
chmod +x /usr/local/bin/vpn-functions.sh

# Install VPN services with error checking
echo -e "${YELLOW}Installing VPN services...${NC}"

# Install V2Ray
echo -e "${GREEN}Installing V2Ray...${NC}"
if ! bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh); then
    echo -e "${RED}V2Ray installation failed${NC}"
    exit 1
fi

# Install WireGuard
echo -e "${GREEN}Installing WireGuard...${NC}"
if ! apt-get install -y wireguard; then
    echo -e "${RED}WireGuard installation failed${NC}"
    exit 1
fi

# Install OpenVPN
echo -e "${GREEN}Installing OpenVPN...${NC}"
if ! apt-get install -y openvpn easy-rsa; then
    echo -e "${RED}OpenVPN installation failed${NC}"
    exit 1
fi

# Install Shadowsocks
echo -e "${GREEN}Installing Shadowsocks...${NC}"
if ! apt-get install -y shadowsocks-libev; then
    echo -e "${RED}Shadowsocks installation failed${NC}"
    exit 1
fi

# Install Trojan
echo -e "${GREEN}Installing Trojan...${NC}"
if ! bash -c "$(curl -fsSL https://raw.githubusercontent.com/trojan-gfw/trojan-quickstart/master/trojan-quickstart.sh)"; then
    echo -e "${RED}Trojan installation failed${NC}"
    exit 1
fi

# Install DNS Tunnel with better error handling
echo -e "${YELLOW}Installing DNS Tunnel...${NC}"
apt-get update
apt-get install -y bind9 dnsutils resolvconf

# Detect and install correct bind service
if ! systemctl list-unit-files | grep -q "bind9.service"; then
    apt-get install -y bind9
fi

# Configure bind9
echo -e "${YELLOW}Configuring DNS Server...${NC}"
# Backup original config if exists
if [ -f "/etc/bind/named.conf.options" ]; then
    cp /etc/bind/named.conf.options /etc/bind/named.conf.options.bak
fi

# Create bind config directory if it doesn't exist
mkdir -p /etc/bind

# Configure DNS options
cat > /etc/bind/named.conf.options << EOF
options {
    directory "/var/cache/bind";
    listen-on { any; };
    listen-on-v6 { any; };
    allow-query { any; };
    forwarders {
        8.8.8.8;
        8.8.4.4;
    };
    auth-nxdomain no;
    version none;
    hostname none;
    server-id none;
    dnssec-validation auto;
};
EOF

# Set correct permissions
chown -R bind:bind /etc/bind
chown -R bind:bind /var/cache/bind

# Restart DNS service
echo -e "${YELLOW}Starting DNS Service...${NC}"
systemctl restart bind9
systemctl enable bind9

# Verify DNS service
if ! systemctl is-active --quiet bind9; then
    echo -e "${RED}DNS service failed to start. Installing named instead...${NC}"
    apt-get install -y named
    systemctl restart named
    systemctl enable named
    
    if ! systemctl is-active --quiet named; then
        echo -e "${RED}Both bind9 and named failed to start. Please check system logs${NC}"
        echo -e "${YELLOW}Continuing with installation...${NC}"
    fi
fi

# Install SSH Over DNS with error handling
echo -e "${YELLOW}Installing SSH Over DNS...${NC}"
# Install dns2tcp
apt-get install -y dns2tcp

# Create simple sshover script
cat > /usr/bin/sshover << 'EOF'
#!/bin/bash
dns_server="$1"
ssh_port="$2"
[ -z "$dns_server" ] && dns_server="8.8.8.8"
[ -z "$ssh_port" ] && ssh_port="22"
socat TCP4-LISTEN:5300,reuseaddr,fork TCP4:127.0.0.1:$ssh_port &
dns2tcp -L 0.0.0.0:53 -R $dns_server:53 &
EOF
chmod +x /usr/bin/sshover

# Install required dependencies for SSH over DNS
echo -e "${YELLOW}Installing SSH over DNS dependencies...${NC}"
apt-get install -y dns2tcp socat || {
    echo -e "${RED}Failed to install some dependencies${NC}"
    echo -e "${YELLOW}You may need to install them manually: dns2tcp socat${NC}"
}

# Update firewall rules for DNS
echo -e "${YELLOW}Updating firewall rules for DNS...${NC}"
ufw allow 53/tcp
ufw allow 53/udp
ufw allow 5300/tcp

# Test DNS resolution
echo -e "${YELLOW}Testing DNS resolution...${NC}"
if host google.com >/dev/null 2>&1; then
    echo -e "${GREEN}DNS resolution working correctly${NC}"
else
    echo -e "${RED}DNS resolution test failed. This might not affect overall functionality${NC}"
    echo -e "${YELLOW}You may need to configure DNS manually later${NC}"
fi

# Create DNS service status check script
cat > /usr/local/bin/check-dns << 'EOF'
#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Checking DNS Service Status...${NC}"

# Check if named/bind9 is running
if pgrep named >/dev/null || pgrep bind >/dev/null; then
    echo -e "${GREEN}DNS Service is running${NC}"
else
    echo -e "${RED}DNS Service is not running${NC}"
    echo -e "${YELLOW}Attempting to restart...${NC}"
    systemctl restart bind9 || systemctl restart named
fi

# Test DNS resolution
if host google.com >/dev/null 2>&1; then
    echo -e "${GREEN}DNS resolution is working${NC}"
else
    echo -e "${RED}DNS resolution is not working${NC}"
fi

# Check DNS ports
if netstat -tuln | grep -q ":53 "; then
    echo -e "${GREEN}DNS ports are open${NC}"
else
    echo -e "${RED}DNS ports are not open${NC}"
fi
EOF
chmod +x /usr/local/bin/check-dns

echo -e "${GREEN}SlowDNS installation completed${NC}"
echo -e "You can check DNS status anytime using: ${YELLOW}check-dns${NC}"

# Setup L2TP/IPsec with proper installation
echo -e "${GREEN}Setting up L2TP/IPsec...${NC}"
# Install required packages
apt-get update
apt-get install -y strongswan strongswan-pki libcharon-extra-plugins xl2tpd

# Configure strongSwan
cat > /etc/ipsec.conf << EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn L2TP-PSK-NAT
    keyexchange=ikev1
    authby=secret
    type=transport
    left=%defaultroute
    leftprotoport=17/1701
    rightprotoport=17/1701
    right=%any
    rekey=no
    forceencaps=yes
    auto=add
EOF

# Generate random PSK
PSK=$(openssl rand -hex 30)
echo ": PSK \"$PSK\"" > /etc/ipsec.secrets

# Configure xl2tpd
cat > /etc/xl2tpd/xl2tpd.conf << EOF
[global]
port = 1701
auth file = /etc/ppp/chap-secrets
ipsec saref = yes

[lns default]
ip range = 192.168.42.10-192.168.42.250
local ip = 192.168.42.1
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

# Configure PPP
cat > /etc/ppp/options.xl2tpd << EOF
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
crtscts
idle 1800
mtu 1280
mru 1280
nodefaultroute
debug
lock
proxyarp
connect-delay 5000
EOF

# Start and enable services
systemctl restart strongswan
systemctl restart xl2tpd
systemctl enable strongswan
systemctl enable xl2tpd

# Verify L2TP/IPsec services
if ! systemctl is-active --quiet strongswan || ! systemctl is-active --quiet xl2tpd; then
    echo -e "${RED}L2TP/IPsec services failed to start. Please check logs at /var/log/syslog${NC}"
else
    echo -e "${GREEN}L2TP/IPsec services started successfully${NC}"
fi

# Configure firewall with all ports
echo -e "${YELLOW}Configuring firewall...${NC}"
# Reset UFW
ufw --force reset

# Basic ports
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS

# VPN ports
ufw allow 1194/udp  # OpenVPN
ufw allow 51820/udp # WireGuard
ufw allow 8388/tcp  # Shadowsocks
ufw allow 8388/udp  # Shadowsocks
ufw allow 10086/tcp # V2Ray

# SlowDNS ports
ufw allow 53/tcp
ufw allow 53/udp
ufw allow 5300/tcp

# L2TP/IPsec ports
ufw allow 500/udp
ufw allow 4500/udp
ufw allow 1701/udp

# Additional security ports
ufw allow 8443/tcp  # HTTPS alt
ufw allow 2053/tcp  # DNS over HTTPS

# Enable firewall
echo "y" | ufw enable

# Setup default configurations
echo -e "${YELLOW}Setting up default configurations...${NC}"

# Create default config directory
mkdir -p /etc/vpn-manager/defaults

# Save default configurations
cat > /etc/vpn-manager/defaults/settings.conf << EOF
TRIAL_DURATION=1
TRIAL_BANDWIDTH=1
TRIAL_PREFIX="trial"
TRIAL_PROTOCOLS="ssh,openvpn,v2ray,trojan,wireguard,shadowsocks"
EOF

# Create menu shortcut with error handling
echo -e "${YELLOW}Creating menu shortcut...${NC}"
cat > /usr/local/bin/vpn << EOF
#!/bin/bash
if [ -f /usr/local/bin/vpn-functions.sh ]; then
    bash /usr/local/bin/vpn-functions.sh
else
    echo "VPN Manager not found. Please reinstall."
    exit 1
fi
EOF
chmod +x /usr/local/bin/vpn

# Create comprehensive uninstaller
cat > /usr/local/bin/vpn-uninstall << EOF
#!/bin/bash
echo "Uninstalling VPN Manager..."

# Stop all services
services=("v2ray" "nginx" "trojan" "openvpn@server" "wg-quick@wg0" "shadowsocks-libev" "bind9" "strongswan" "xl2tpd")
for service in "\${services[@]}"; do
    systemctl stop \$service 2>/dev/null
    systemctl disable \$service 2>/dev/null
done

# Remove files
rm -rf /etc/vpn-manager
rm -rf /var/www/download
rm -rf /var/www/html/monitor
rm -f /usr/local/bin/vpn-functions.sh
rm -f /usr/local/bin/vpn
rm -f /usr/local/bin/vpn-uninstall
rm -rf /var/log/vpn-manager

# Remove firewall rules
ufw --force reset

echo "VPN Manager has been uninstalled"
EOF
chmod +x /usr/local/bin/vpn-uninstall

# Log installation completion
echo "Installation completed at $(date)" >> /var/log/vpn-manager/install.log

# Final setup
echo -e "${GREEN}Installation completed!${NC}"
echo -e "\nYou can now:"
echo -e "1. Run ${YELLOW}vpn${NC} to start VPN Manager"
echo -e "2. Run ${YELLOW}vpn-uninstall${NC} to remove VPN Manager"
echo -e "\n${RED}Please note your credentials and keep them safe!${NC}"
echo -e "\nInstallation log saved to: ${YELLOW}/var/log/vpn-manager/install.log${NC}"

# Create first run marker
touch /etc/vpn-manager/.first_run

# Restart all services
echo -e "${YELLOW}Starting services...${NC}"
services=("nginx" "v2ray" "trojan" "openvpn@server" "wg-quick@wg0" "shadowsocks-libev" "bind9" "strongswan" "xl2tpd")
for service in "${services[@]}"; do
    systemctl restart $service 2>/dev/null
    systemctl enable $service 2>/dev/null
done

echo -e "\n${GREEN}Press Enter to start VPN Manager...${NC}"
read

# Start VPN Manager
vpn

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

# Function to show emergency menu
show_emergency_menu() {
    clear
    echo -e "${RED}╔═════════════════════════════════════════╗${NC}"
    echo -e "${RED}║       ${YELLOW}VPN EMERGENCY MENU${NC}                ${RED}║${NC}"
    echo -e "${RED}╚═════════════════════════════════════════╝${NC}"
    echo -e ""
    echo -e "${YELLOW}1${NC}. Stop All VPN Services"
    echo -e "${YELLOW}2${NC}. Remove VPN Packages"
    echo -e "${YELLOW}3${NC}. Reset Firewall Rules"
    echo -e "${YELLOW}4${NC}. Backup Current Configuration"
    echo -e "${RED}5${NC}. Complete System Cleanup (Uninstall Everything)"
    echo -e "${YELLOW}6${NC}. Back to Main Menu"
    echo -e ""
    echo -e "${GREEN}Select an option:${NC} "
    read -r choice

    case $choice in
        1) stop_services ;;
        2) remove_packages ;;
        3) reset_firewall ;;
        4) backup_config ;;
        5) complete_cleanup ;;
        6) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
    
    echo -e "\nPress Enter to continue..."
    read -r
    show_emergency_menu
}

# Function to manage API settings
manage_api_settings() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       ${GREEN}API SETTINGS MANAGER${NC}              ${BLUE}║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════╝${NC}"
    echo -e ""
    echo -e "${YELLOW}1${NC}. Configure Telegram Bot"
    echo -e "${YELLOW}2${NC}. Configure Cloudflare API"
    echo -e "${YELLOW}3${NC}. Configure Domain Settings"
    echo -e "${YELLOW}4${NC}. View Current Settings"
    echo -e "${YELLOW}5${NC}. Test API Connections"
    echo -e "${YELLOW}6${NC}. Back to Main Menu"
    echo -e ""
    echo -e "${GREEN}Select an option:${NC} "
    read -r choice

    case $choice in
        1) configure_telegram ;;
        2) configure_cloudflare ;;
        3) configure_domain ;;
        4) view_settings ;;
        5) test_connections ;;
        6) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
    
    echo -e "\nPress Enter to continue..."
    read -r
    manage_api_settings
}

# Function to configure Telegram
configure_telegram() {
    clear
    echo -e "${YELLOW}Telegram Bot Configuration${NC}"
    echo -e "Current settings (if any):"
    if [ -f "/etc/vpn-manager/api/telegram.conf" ]; then
        source "/etc/vpn-manager/api/telegram.conf"
        echo -e "Bot Token: ${GREEN}${BOT_TOKEN:-Not Set}${NC}"
        echo -e "Admin ID: ${GREEN}${ADMIN_ID:-Not Set}${NC}"
    fi
    echo -e "\nEnter new settings (or press Enter to keep current):"
    
    echo -n "Bot Token: "
    read -r new_token
    echo -n "Admin ID: "
    read -r new_admin

    if [ ! -d "/etc/vpn-manager/api" ]; then
        mkdir -p /etc/vpn-manager/api
    fi

    # Only update if new values are provided
    if [ ! -z "$new_token" ] || [ ! -z "$new_admin" ]; then
        cat > /etc/vpn-manager/api/telegram.conf << EOF
BOT_TOKEN="${new_token:-$BOT_TOKEN}"
ADMIN_ID="${new_admin:-$ADMIN_ID}"
EOF
        echo -e "${GREEN}Telegram settings updated successfully!${NC}"
    fi
}

# Function to configure Cloudflare
configure_cloudflare() {
    clear
    echo -e "${YELLOW}Cloudflare API Configuration${NC}"
    echo -e "Current settings (if any):"
    if [ -f "/etc/vpn-manager/api/cloudflare.conf" ]; then
        source "/etc/vpn-manager/api/cloudflare.conf"
        echo -e "API Key: ${GREEN}${CF_API_KEY:-Not Set}${NC}"
        echo -e "Email: ${GREEN}${CF_EMAIL:-Not Set}${NC}"
        echo -e "Zone ID: ${GREEN}${CF_ZONE_ID:-Not Set}${NC}"
    fi
    echo -e "\nEnter new settings (or press Enter to keep current):"
    
    echo -n "API Key: "
    read -r new_key
    echo -n "Email: "
    read -r new_email
    echo -n "Zone ID: "
    read -r new_zone

    if [ ! -d "/etc/vpn-manager/api" ]; then
        mkdir -p /etc/vpn-manager/api
    fi

    # Only update if new values are provided
    if [ ! -z "$new_key" ] || [ ! -z "$new_email" ] || [ ! -z "$new_zone" ]; then
        cat > /etc/vpn-manager/api/cloudflare.conf << EOF
CF_API_KEY="${new_key:-$CF_API_KEY}"
CF_EMAIL="${new_email:-$CF_EMAIL}"
CF_ZONE_ID="${new_zone:-$CF_ZONE_ID}"
EOF
        echo -e "${GREEN}Cloudflare settings updated successfully!${NC}"
    fi
}

# Function to configure domain settings
configure_domain() {
    clear
    echo -e "${YELLOW}Domain Configuration${NC}"
    echo -e "Current settings (if any):"
    if [ -f "/etc/vpn-manager/api/domain.conf" ]; then
        source "/etc/vpn-manager/api/domain.conf"
        echo -e "Main Domain: ${GREEN}${MAIN_DOMAIN:-Not Set}${NC}"
        echo -e "Subdomain Prefix: ${GREEN}${SUB_PREFIX:-Not Set}${NC}"
    fi
    echo -e "\nEnter new settings (or press Enter to keep current):"
    
    echo -n "Main Domain (e.g., example.com): "
    read -r new_domain
    echo -n "Subdomain Prefix (e.g., vpn): "
    read -r new_prefix

    if [ ! -d "/etc/vpn-manager/api" ]; then
        mkdir -p /etc/vpn-manager/api
    fi

    # Only update if new values are provided
    if [ ! -z "$new_domain" ] || [ ! -z "$new_prefix" ]; then
        cat > /etc/vpn-manager/api/domain.conf << EOF
MAIN_DOMAIN="${new_domain:-$MAIN_DOMAIN}"
SUB_PREFIX="${new_prefix:-$SUB_PREFIX}"
EOF
        echo -e "${GREEN}Domain settings updated successfully!${NC}"
    fi
}

# Function to view current settings
view_settings() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       ${GREEN}CURRENT API SETTINGS${NC}              ${BLUE}║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════╝${NC}"
    echo -e ""
    
    echo -e "${YELLOW}Telegram Settings:${NC}"
    if [ -f "/etc/vpn-manager/api/telegram.conf" ]; then
        source "/etc/vpn-manager/api/telegram.conf"
        echo -e "Bot Token: ${GREEN}${BOT_TOKEN:-Not Set}${NC}"
        echo -e "Admin ID: ${GREEN}${ADMIN_ID:-Not Set}${NC}"
    else
        echo -e "${RED}No Telegram settings found${NC}"
    fi
    
    echo -e "\n${YELLOW}Cloudflare Settings:${NC}"
    if [ -f "/etc/vpn-manager/api/cloudflare.conf" ]; then
        source "/etc/vpn-manager/api/cloudflare.conf"
        echo -e "API Key: ${GREEN}${CF_API_KEY:-Not Set}${NC}"
        echo -e "Email: ${GREEN}${CF_EMAIL:-Not Set}${NC}"
        echo -e "Zone ID: ${GREEN}${CF_ZONE_ID:-Not Set}${NC}"
    else
        echo -e "${RED}No Cloudflare settings found${NC}"
    fi
    
    echo -e "\n${YELLOW}Domain Settings:${NC}"
    if [ -f "/etc/vpn-manager/api/domain.conf" ]; then
        source "/etc/vpn-manager/api/domain.conf"
        echo -e "Main Domain: ${GREEN}${MAIN_DOMAIN:-Not Set}${NC}"
        echo -e "Subdomain Prefix: ${GREEN}${SUB_PREFIX:-Not Set}${NC}"
    else
        echo -e "${RED}No Domain settings found${NC}"
    fi
}

# Function to test API connections
test_connections() {
    clear
    echo -e "${YELLOW}Testing API Connections...${NC}\n"
    
    # Test Telegram
    echo -e "Testing Telegram Bot..."
    if [ -f "/etc/vpn-manager/api/telegram.conf" ]; then
        source "/etc/vpn-manager/api/telegram.conf"
        if [ ! -z "$BOT_TOKEN" ]; then
            response=$(curl -s "https://api.telegram.org/bot$BOT_TOKEN/getMe")
            if echo "$response" | grep -q "\"ok\":true"; then
                echo -e "${GREEN}✓ Telegram Bot connection successful${NC}"
            else
                echo -e "${RED}✗ Telegram Bot connection failed${NC}"
            fi
        else
            echo -e "${RED}✗ Telegram Bot token not set${NC}"
        fi
    else
        echo -e "${RED}✗ Telegram configuration not found${NC}"
    fi
    
    # Test Cloudflare
    echo -e "\nTesting Cloudflare API..."
    if [ -f "/etc/vpn-manager/api/cloudflare.conf" ]; then
        source "/etc/vpn-manager/api/cloudflare.conf"
        if [ ! -z "$CF_API_KEY" ] && [ ! -z "$CF_EMAIL" ]; then
            response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
                 -H "Authorization: Bearer $CF_API_KEY" \
                 -H "Content-Type: application/json")
            if echo "$response" | grep -q "\"success\":true"; then
                echo -e "${GREEN}✓ Cloudflare API connection successful${NC}"
            else
                echo -e "${RED}✗ Cloudflare API connection failed${NC}"
            fi
        else
            echo -e "${RED}✗ Cloudflare credentials not set${NC}"
        fi
    else
        echo -e "${RED}✗ Cloudflare configuration not found${NC}"
    fi
    
    # Test Domain
    echo -e "\nTesting Domain Resolution..."
    if [ -f "/etc/vpn-manager/api/domain.conf" ]; then
        source "/etc/vpn-manager/api/domain.conf"
        if [ ! -z "$MAIN_DOMAIN" ]; then
            if host "$MAIN_DOMAIN" > /dev/null 2>&1; then
                echo -e "${GREEN}✓ Domain resolution successful${NC}"
            else
                echo -e "${RED}✗ Domain resolution failed${NC}"
            fi
        else
            echo -e "${RED}✗ Domain not set${NC}"
        fi
    else
        echo -e "${RED}✗ Domain configuration not found${NC}"
    fi
}

# Function to show main menu
show_menu() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       ${GREEN}VPN MANAGEMENT MENU${NC}              ${BLUE}║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════╝${NC}"
    echo -e ""
    echo -e "${YELLOW}1${NC}. User Management"
    echo -e "${YELLOW}2${NC}. Service Management"
    echo -e "${YELLOW}3${NC}. System Management"
    echo -e "${YELLOW}4${NC}. Monitoring"
    echo -e "${YELLOW}5${NC}. Domain Settings"
    echo -e "${YELLOW}6${NC}. Cloudflare Settings"
    echo -e "${RED}7${NC}. Emergency Menu"
    echo -e "${YELLOW}8${NC}. Exit"
    echo -e ""
    echo -e "${GREEN}Select an option:${NC} "
    read -r choice

    case $choice in
        1) user_management_menu ;;
        2) service_management_menu ;;
        3) system_management_menu ;;
        4) monitoring_menu ;;
        5) domain_settings_menu ;;
        6) cloudflare_settings_menu ;;
        7) show_emergency_menu ;;
        8) exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
    
    echo -e "\nPress Enter to continue..."
    read -r
    show_menu
}

# Function to update config file
update_config() {
    local file="$1"
    local key="$2"
    local value="$3"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$file")"
    
    # If file doesn't exist, create it
    touch "$file"
    
    # Remove existing key if it exists
    sed -i "/^$key=/d" "$file"
    
    # Add new key-value pair
    echo "$key=\"$value\"" >> "$file"
}

# Function to manage domain settings
domain_settings_menu() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       ${GREEN}DOMAIN SETTINGS MENU${NC}             ${BLUE}║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════╝${NC}"
    echo -e ""
    echo -e "${YELLOW}1${NC}. Set Main Domain"
    echo -e "${YELLOW}2${NC}. Set Subdomain Prefix"
    echo -e "${YELLOW}3${NC}. View Current Domain Settings"
    echo -e "${YELLOW}4${NC}. Back to Main Menu"
    echo -e ""
    echo -e "${GREEN}Select an option:${NC} "
    read -r choice

    DOMAIN_CONF="/etc/vpn-manager/api/domain.conf"

    case $choice in
        1)
            echo -n "Enter main domain (e.g., example.com): "
            read -r domain
            if [ ! -z "$domain" ]; then
                update_config "$DOMAIN_CONF" "MAIN_DOMAIN" "$domain"
                echo -e "${GREEN}Main domain set to: $domain${NC}"
            fi
            ;;
        2)
            echo -n "Enter subdomain prefix (e.g., vpn): "
            read -r prefix
            if [ ! -z "$prefix" ]; then
                update_config "$DOMAIN_CONF" "SUB_PREFIX" "$prefix"
                echo -e "${GREEN}Subdomain prefix set to: $prefix${NC}"
            fi
            ;;
        3)
            if [ -f "$DOMAIN_CONF" ]; then
                source "$DOMAIN_CONF"
                echo -e "\nCurrent Domain Settings:"
                echo -e "Main Domain: ${GREEN}${MAIN_DOMAIN:-Not Set}${NC}"
                echo -e "Subdomain Prefix: ${GREEN}${SUB_PREFIX:-Not Set}${NC}"
                if [ ! -z "$MAIN_DOMAIN" ] && [ ! -z "$SUB_PREFIX" ]; then
                    echo -e "Full Subdomain: ${GREEN}${SUB_PREFIX}.${MAIN_DOMAIN}${NC}"
                fi
            else
                echo -e "${RED}No domain settings found${NC}"
            fi
            ;;
        4) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
    
    echo -e "\nPress Enter to continue..."
    read -r
    domain_settings_menu
}

# Function to manage Cloudflare settings
cloudflare_settings_menu() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║      ${GREEN}CLOUDFLARE SETTINGS MENU${NC}          ${BLUE}║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════╝${NC}"
    echo -e ""
    echo -e "${YELLOW}1${NC}. Set API Key"
    echo -e "${YELLOW}2${NC}. Set Email"
    echo -e "${YELLOW}3${NC}. Set Zone ID"
    echo -e "${YELLOW}4${NC}. View Current Settings"
    echo -e "${YELLOW}5${NC}. Test API Connection"
    echo -e "${YELLOW}6${NC}. Back to Main Menu"
    echo -e ""
    echo -e "${GREEN}Select an option:${NC} "
    read -r choice

    CF_CONF="/etc/vpn-manager/api/cloudflare.conf"

    case $choice in
        1)
            echo -n "Enter Cloudflare API Key: "
            read -r apikey
            if [ ! -z "$apikey" ]; then
                update_config "$CF_CONF" "CF_API_KEY" "$apikey"
                echo -e "${GREEN}API Key has been set${NC}"
            fi
            ;;
        2)
            echo -n "Enter Cloudflare Email: "
            read -r email
            if [ ! -z "$email" ]; then
                update_config "$CF_CONF" "CF_EMAIL" "$email"
                echo -e "${GREEN}Email has been set${NC}"
            fi
            ;;
        3)
            echo -n "Enter Cloudflare Zone ID: "
            read -r zoneid
            if [ ! -z "$zoneid" ]; then
                update_config "$CF_CONF" "CF_ZONE_ID" "$zoneid"
                echo -e "${GREEN}Zone ID has been set${NC}"
            fi
            ;;
        4)
            if [ -f "$CF_CONF" ]; then
                source "$CF_CONF"
                echo -e "\nCurrent Cloudflare Settings:"
                echo -e "API Key: ${GREEN}${CF_API_KEY:-Not Set}${NC}"
                echo -e "Email: ${GREEN}${CF_EMAIL:-Not Set}${NC}"
                echo -e "Zone ID: ${GREEN}${CF_ZONE_ID:-Not Set}${NC}"
                
                # Show DNS records from Cloudflare if credentials are set
                if [ ! -z "$CF_API_KEY" ] && [ ! -z "$CF_EMAIL" ] && [ ! -z "$CF_ZONE_ID" ]; then
                    echo -e "\nFetching DNS records from Cloudflare..."
                    response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
                         -H "Authorization: Bearer $CF_API_KEY" \
                         -H "Content-Type: application/json")
                    
                    if echo "$response" | grep -q "\"success\":true"; then
                        echo -e "\n${YELLOW}DNS Records in Cloudflare:${NC}"
                        echo "$response" | jq -r '.result[] | "Type: \(.type), Name: \(.name), Content: \(.content)"'
                    fi
                fi
            else
                echo -e "${RED}No Cloudflare settings found${NC}"
            fi
            ;;
        5)
            if [ -f "$CF_CONF" ]; then
                source "$CF_CONF"
                if [ ! -z "$CF_API_KEY" ] && [ ! -z "$CF_EMAIL" ]; then
                    echo -e "Testing Cloudflare API connection..."
                    response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
                         -H "Authorization: Bearer $CF_API_KEY" \
                         -H "Content-Type: application/json")
                    if echo "$response" | grep -q "\"success\":true"; then
                        echo -e "${GREEN}✓ Cloudflare API connection successful${NC}"
                        
                        # Test zone access
                        if [ ! -z "$CF_ZONE_ID" ]; then
                            echo -e "\nTesting zone access..."
                            response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID" \
                                 -H "Authorization: Bearer $CF_API_KEY" \
                                 -H "Content-Type: application/json")
                            if echo "$response" | grep -q "\"success\":true"; then
                                echo -e "${GREEN}✓ Zone access successful${NC}"
                                zone_name=$(echo "$response" | jq -r '.result.name')
                                echo -e "Zone Name: ${GREEN}$zone_name${NC}"
                            else
                                echo -e "${RED}✗ Zone access failed${NC}"
                            fi
                        fi
                    else
                        echo -e "${RED}✗ Cloudflare API connection failed${NC}"
                    fi
                else
                    echo -e "${RED}API Key or Email not set${NC}"
                fi
            else
                echo -e "${RED}No Cloudflare settings found${NC}"
            fi
            ;;
        6) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
    
    echo -e "\nPress Enter to continue..."
    read -r
    cloudflare_settings_menu
}

# Function to setup SSH VPN
setup_ssh_vpn() {
    echo -e "${YELLOW}Setting up SSH VPN...${NC}"
    
    # Configure SSH
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Update SSH config
    cat > /etc/ssh/sshd_config << EOF
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
EOF

    # Configure Dropbear
    cat > /etc/default/dropbear << EOF
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 50000 -p 109"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RECEIVE_WINDOW=65536
EOF

    # Configure Stunnel
    cat > /etc/stunnel/stunnel.conf << EOF
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 443
connect = 127.0.0.1:143

[openssh]
accept = 777
connect = 127.0.0.1:22
EOF

    # Generate Stunnel certificate
    openssl req -new -x509 -days 365 -nodes -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem -subj "/C=ID/ST=None/L=None/O=None/CN=None"

    # Restart services
    systemctl restart ssh
    systemctl restart dropbear
    systemctl restart stunnel4

    echo -e "${GREEN}SSH VPN setup completed${NC}"
}

# Configure SSH
echo -e "${YELLOW}Configuring SSH...${NC}"
# Backup original sshd config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Configure SSH
cat > /etc/ssh/sshd_config << EOF
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
EOF

# Configure Dropbear
echo -e "${YELLOW}Configuring Dropbear...${NC}"
cat > /etc/default/dropbear << EOF
# Dropbear Settings
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 50000 -p 109"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RECEIVE_WINDOW=65536
EOF

# Configure Stunnel for SSH
echo -e "${YELLOW}Configuring Stunnel...${NC}"
cat > /etc/stunnel/stunnel.conf << EOF
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 443
connect = 127.0.0.1:143

[openssh]
accept = 777
connect = 127.0.0.1:22
EOF

# Generate Stunnel certificate
openssl req -new -x509 -days 365 -nodes -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem -subj "/C=ID/ST=None/L=None/O=None/CN=None"

# Configure SSH Banner
cat > /etc/issue.net << EOF
<font color="blue"><b>================================</b></font><br>
<font color="red"><b>         SSH PREMIUM          </b></font><br>
<font color="blue"><b>================================</b></font><br>
<font color="green"><b>         NO SPAM           </b></font><br>
<font color="red"><b>         NO DDOS           </b></font><br>
<font color="blue"><b>       NO HACKING         </b></font><br>
<font color="green"><b>       NO CARDING        </b></font><br>
<font color="red"><b>       NO CRIMINAL        </b></font><br>
<font color="blue"><b>================================</b></font><br>
EOF

# Configure WebSocket
echo -e "${YELLOW}Configuring WebSocket...${NC}"
# Install WebSocket proxy
pip3 install websockify

# Create WebSocket service
cat > /etc/systemd/system/websocket.service << EOF
[Unit]
Description=WebSocket SSH Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/websockify --web=/var/www/html 8880 localhost:22
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Update firewall for SSH ports
echo -e "${YELLOW}Updating firewall rules for SSH...${NC}"
# Allow SSH ports
ufw allow 22/tcp     # Default SSH
ufw allow 143/tcp    # Dropbear 1
ufw allow 109/tcp    # Dropbear 2
ufw allow 50000/tcp  # Dropbear 3
ufw allow 443/tcp    # Stunnel
ufw allow 777/tcp    # Stunnel OpenSSH
ufw allow 8880/tcp   # WebSocket

# Restart services
systemctl restart ssh
systemctl restart dropbear
systemctl restart stunnel4
systemctl enable websocket
systemctl start websocket

# Install BadVPN UDPGW
echo -e "${YELLOW}Installing BadVPN UDPGW...${NC}"
# Download and compile BadVPN
cd /usr/src/
wget https://github.com/ambrop72/badvpn/archive/refs/tags/1.999.130.tar.gz
tar xf 1.999.130.tar.gz
cd badvpn-1.999.130
cmake -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
cd ..
rm -rf badvpn-1.999.130 1.999.130.tar.gz

# Create BadVPN service
cat > /etc/systemd/system/badvpn.service << EOF
[Unit]
Description=BadVPN UDPGW Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 100
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Install SSH Over DNS
echo -e "${YELLOW}Installing SSH Over DNS...${NC}"
# Install dns2tcp
apt-get install -y dns2tcp

# Create simple sshover script
cat > /usr/bin/sshover << 'EOF'
#!/bin/bash
dns_server="$1"
ssh_port="$2"
[ -z "$dns_server" ] && dns_server="8.8.8.8"
[ -z "$ssh_port" ] && ssh_port="22"
socat TCP4-LISTEN:5300,reuseaddr,fork TCP4:127.0.0.1:$ssh_port &
dns2tcp -L 0.0.0.0:53 -R $dns_server:53 &
EOF
chmod +x /usr/bin/sshover

# Create SSH monitoring script
echo -e "${YELLOW}Setting up SSH monitoring...${NC}"
cat > /usr/local/bin/ssh-monitor << EOF
#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "\${BLUE}═══════════════════════════════════════════\${NC}"
echo -e "\${GREEN}           SSH CONNECTION MONITOR          \${NC}"
echo -e "\${BLUE}═══════════════════════════════════════════\${NC}"
echo -e ""
echo -e "\${YELLOW}OpenSSH Connections:\${NC}"
netstat -natp | grep ESTABLISHED.*sshd
echo -e ""
echo -e "\${YELLOW}Dropbear Connections:\${NC}"
netstat -natp | grep ESTABLISHED.*dropbear
echo -e ""
echo -e "\${YELLOW}SSL Connections:\${NC}"
netstat -natp | grep ESTABLISHED.*stunnel
echo -e ""
echo -e "\${YELLOW}BadVPN-UDPGW Connections:\${NC}"
netstat -natp | grep ESTABLISHED.*badvpn-udpgw
echo -e ""
echo -e "\${YELLOW}WebSocket Connections:\${NC}"
netstat -natp | grep ESTABLISHED.*websockify
echo -e ""
echo -e "\${BLUE}═══════════════════════════════════════════\${NC}"
EOF
chmod +x /usr/local/bin/ssh-monitor

# Create SSH speed test script
echo -e "${YELLOW}Setting up SSH speed test...${NC}"
cat > /usr/local/bin/ssh-speedtest << EOF
#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "\${YELLOW}Testing download speed...\${NC}"
wget -O /dev/null "http://speedtest.wdc01.softlayer.com/downloads/test100.zip" 2>&1 | grep -o "[0-9.]\+ [KM]B/s"

echo -e "\${YELLOW}Testing upload speed...\${NC}"
dd if=/dev/zero bs=1M count=100 2>/dev/null | pv -N "Upload" | ssh -p 22 localhost "cat > /dev/null"
EOF
chmod +x /usr/local/bin/ssh-speedtest

# Create SSH auto-kill script
echo -e "${YELLOW}Setting up SSH auto-kill...${NC}"
cat > /usr/local/bin/ssh-autokill << EOF
#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [ -z "\$1" ]; then
    echo -e "\${RED}Usage: ssh-autokill <max_connections>\${NC}"
    exit 1
fi

MAX_CONN=\$1
while true; do
    for user in \$(cat /etc/passwd | grep -v "nobody" | awk -F: '\$3 >= 1000 {print \$1}'); do
        conn=\$(ps -u \$user | grep -c sshd)
        if [ \$conn -gt \$MAX_CONN ]; then
            pkill -u \$user
            echo -e "\${RED}User \$user exceeded max connections (\$conn). Connections terminated.\${NC}"
        fi
    done
    sleep 60
done
EOF
chmod +x /usr/local/bin/ssh-autokill

# Create SSH user limiter
echo -e "${YELLOW}Setting up SSH user limiter...${NC}"
cat > /usr/local/bin/ssh-limit << EOF
#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [ -z "\$1" ] || [ -z "\$2" ]; then
    echo -e "\${RED}Usage: ssh-limit <username> <max_connections>\${NC}"
    exit 1
fi

USER=\$1
LIMIT=\$2

# Add limit to user
echo "\$USER \$LIMIT" >> /etc/security/limits.conf
echo -e "\${GREEN}Connection limit for \$USER set to \$LIMIT\${NC}"
EOF
chmod +x /usr/local/bin/ssh-limit

# Start and enable services
systemctl enable badvpn
systemctl start badvpn
systemctl restart bind9

# Add new ports to firewall
ufw allow 7300/udp  # BadVPN
ufw allow 53/tcp    # DNS TCP
ufw allow 53/udp    # DNS UDP

# Update SSH banner with new features
cat >> /etc/issue.net << EOF
<font color="green"><b>Available Features:</b></font><br>
- Multi-Port SSH (22, 143, 109, 50000)<br>
- SSL/TLS (443, 777)<br>
- WebSocket (8880)<br>
- UDP Support via BadVPN<br>
- SSH Over DNS<br>
- Speed Optimizer<br>
- Auto Kill Multi Login<br>
- User Limiter<br>
<font color="blue"><b>================================</b></font><br>
EOF

echo -e "${GREEN}Additional SSH features installed successfully!${NC}"
echo -e "Available commands:"
echo -e "${YELLOW}ssh-monitor${NC} - Monitor SSH connections"
echo -e "${YELLOW}ssh-speedtest${NC} - Test SSH speed"
echo -e "${YELLOW}ssh-autokill${NC} - Auto kill multiple connections"
echo -e "${YELLOW}ssh-limit${NC} - Set user connection limits" 