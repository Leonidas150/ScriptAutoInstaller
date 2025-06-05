#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
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
        echo -e "${RED}This script only works on Debian and CentOS systems${NC}"
        exit 1
    fi
}

# Update system packages
update_system() {
    echo -e "${YELLOW}Updating system packages...${NC}"
    if [[ "$OS" == "debian" ]]; then
        apt update -y && apt upgrade -y
        apt install -y curl wget unzip tar python3 python3-pip
    elif [[ "$OS" == "centos" ]]; then
        yum update -y
        yum install -y curl wget unzip tar python3 python3-pip
    fi
}

# Install V2Ray
install_v2ray() {
    echo -e "${YELLOW}Installing V2Ray...${NC}"
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
    # Configure V2Ray
    cat > /usr/local/etc/v2ray/config.json << EOF
{
  "inbounds": [{
    "port": 8443,
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "$(cat /proc/sys/kernel/random/uuid)",
        "alterId": 0
      }]
    },
    "streamSettings": {
      "network": "ws",
      "wsSettings": {
        "path": "/v2ray"
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOF

    systemctl enable v2ray
    systemctl restart v2ray
}

# Install Shadowsocks
install_shadowsocks() {
    echo -e "${YELLOW}Installing Shadowsocks...${NC}"
    if [[ "$OS" == "debian" ]]; then
        apt install -y shadowsocks-libev
    elif [[ "$OS" == "centos" ]]; then
        yum install -y shadowsocks-libev
    fi

    # Configure Shadowsocks
    cat > /etc/shadowsocks-libev/config.json << EOF
{
    "server":"0.0.0.0",
    "server_port":8388,
    "password":"$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)",
    "timeout":300,
    "method":"chacha20-ietf-poly1305",
    "fast_open":true
}
EOF

    systemctl enable shadowsocks-libev
    systemctl restart shadowsocks-libev
}

# Install WireGuard
install_wireguard() {
    echo -e "${YELLOW}Installing WireGuard...${NC}"
    if [[ "$OS" == "debian" ]]; then
        apt install -y wireguard
    elif [[ "$OS" == "centos" ]]; then
        yum install -y epel-release
        yum install -y wireguard-tools
    fi

    # Generate private and public keys
    wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
    chmod 600 /etc/wireguard/private.key

    # Configure WireGuard
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $(cat /etc/wireguard/private.key)
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF

    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
}

# Install Trojan
install_trojan() {
    echo -e "${YELLOW}Installing Trojan...${NC}"
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/trojan-gfw/trojan-quickstart/master/trojan-quickstart.sh)"
    
    # Generate self-signed certificate (for testing, replace with valid cert in production)
    openssl req -x509 -nodes -days 365 -newkey rsa:3072 \
        -keyout /etc/trojan/private.key \
        -out /etc/trojan/cert.crt \
        -subj "/CN=trojan/O=trojan/C=US"

    # Configure Trojan
    cat > /etc/trojan/config.json << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)"
    ],
    "ssl": {
        "cert": "/etc/trojan/cert.crt",
        "key": "/etc/trojan/private.key"
    }
}
EOF

    systemctl enable trojan
    systemctl restart trojan
}

# Install SlowDNS
install_slowdns() {
    echo -e "${YELLOW}Installing SlowDNS...${NC}"
    git clone https://github.com/sshsebastian/slowdns
    cd slowdns
    chmod +x install
    ./install
    # Configure DNS settings
    ./slowdns ns example.com 3600
}

# Main menu
main_menu() {
    echo -e "${GREEN}VPN Auto Installer Script${NC}"
    echo "1. Install V2Ray (VMess)"
    echo "2. Install Shadowsocks"
    echo "3. Install WireGuard"
    echo "4. Install Trojan"
    echo "5. Install SlowDNS"
    echo "6. Install All"
    echo "7. Exit"
    
    read -p "Select an option [1-7]: " choice
    
    case $choice in
        1) install_v2ray ;;
        2) install_shadowsocks ;;
        3) install_wireguard ;;
        4) install_trojan ;;
        5) install_slowdns ;;
        6)
            install_v2ray
            install_shadowsocks
            install_wireguard
            install_trojan
            install_slowdns
            ;;
        7) exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

# Run the script
check_os
update_system
main_menu 