#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# V2Ray User Management
add_v2ray_user() {
    local username="$1"
    local uuid="$2"
    
    # Add user to V2Ray config
    local config_file="/usr/local/etc/v2ray/config.json"
    local temp_file="/tmp/v2ray_config.tmp"
    
    jq --arg uuid "$uuid" --arg email "$username" '.inbounds[0].settings.clients += [{"id": $uuid, "alterId": 0, "email": $email}]' "$config_file" > "$temp_file"
    mv "$temp_file" "$config_file"
    
    systemctl restart v2ray
}

remove_v2ray_user() {
    local username="$1"
    local config_file="/usr/local/etc/v2ray/config.json"
    local temp_file="/tmp/v2ray_config.tmp"
    
    jq --arg email "$username" '.inbounds[0].settings.clients = [.inbounds[0].settings.clients[] | select(.email != $email)]' "$config_file" > "$temp_file"
    mv "$temp_file" "$config_file"
    
    systemctl restart v2ray
}

# Shadowsocks User Management
add_shadowsocks_user() {
    local username="$1"
    local password="$2"
    local port=$((8388 + $(ls -1 "$USERS_DIR" | wc -l)))
    
    cat > "/etc/shadowsocks-libev/${username}.json" << EOF
{
    "server":"0.0.0.0",
    "server_port":$port,
    "password":"$password",
    "timeout":300,
    "method":"chacha20-ietf-poly1305",
    "fast_open":true
}
EOF
    
    systemctl start shadowsocks-libev@${username}
    systemctl enable shadowsocks-libev@${username}
}

remove_shadowsocks_user() {
    local username="$1"
    
    systemctl stop shadowsocks-libev@${username}
    systemctl disable shadowsocks-libev@${username}
    rm -f "/etc/shadowsocks-libev/${username}.json"
}

# WireGuard User Management
add_wireguard_user() {
    local username="$1"
    local clients_dir="/etc/wireguard/clients"
    mkdir -p "$clients_dir"
    
    # Generate keys
    wg genkey | tee "${clients_dir}/${username}_private.key" | wg pubkey > "${clients_dir}/${username}_public.key"
    
    # Add client to server config
    local private_key=$(cat "${clients_dir}/${username}_private.key")
    local public_key=$(cat "${clients_dir}/${username}_public.key")
    local ip="10.0.0.$(ls -1 "$clients_dir"/*_private.key | wc -l)"
    
    # Add peer to server config
    cat >> /etc/wireguard/wg0.conf << EOF

[Peer]
PublicKey = $public_key
AllowedIPs = $ip/32
EOF
    
    # Create client config
    cat > "${clients_dir}/${username}.conf" << EOF
[Interface]
PrivateKey = $private_key
Address = $ip/24
DNS = 8.8.8.8

[Peer]
PublicKey = $(cat /etc/wireguard/public.key)
Endpoint = $(curl -s ifconfig.me):51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    systemctl restart wg-quick@wg0
}

remove_wireguard_user() {
    local username="$1"
    local clients_dir="/etc/wireguard/clients"
    
    # Remove peer from server config
    local public_key=$(cat "${clients_dir}/${username}_public.key")
    sed -i "/PublicKey = $public_key/,+2d" /etc/wireguard/wg0.conf
    
    # Remove client files
    rm -f "${clients_dir}/${username}.conf"
    rm -f "${clients_dir}/${username}_private.key"
    rm -f "${clients_dir}/${username}_public.key"
    
    systemctl restart wg-quick@wg0
}

# Trojan User Management
add_trojan_user() {
    local username="$1"
    local password="$2"
    local config_file="/etc/trojan/config.json"
    local temp_file="/tmp/trojan_config.tmp"
    
    # Add password to Trojan config
    jq --arg pass "$password" '.password += [$pass]' "$config_file" > "$temp_file"
    mv "$temp_file" "$config_file"
    
    # Store password in user config
    sed -i "/^BANDWIDTH_USED=/a TROJAN_PASS=$password" "$USERS_DIR/${username}.conf"
    
    systemctl restart trojan
}

remove_trojan_user() {
    local username="$1"
    local config_file="/etc/trojan/config.json"
    local temp_file="/tmp/trojan_config.tmp"
    
    # Remove password from the array
    jq --arg pass "$password" '.password -= [$pass]' "$config_file" > "$temp_file"
    mv "$temp_file" "$config_file"
    
    systemctl restart trojan
}

# Bandwidth Management
update_bandwidth_usage() {
    local username="$1"
    local interface="eth0"
    
    # Get current bandwidth usage for the user's IP
    if [[ -f "$USERS_DIR/${username}.conf" ]]; then
        source "$USERS_DIR/${username}.conf"
        local ip=$(grep -r "$username" /etc/wireguard/clients/ | grep "Address" | cut -d= -f2 | tr -d ' ' | cut -d/ -f1)
        
        if [[ ! -z "$ip" ]]; then
            local rx_bytes=$(iptables -nvx -L | grep "$ip" | awk '{print $2}')
            local tx_bytes=$(iptables -nvx -L | grep "$ip" | awk '{print $3}')
            local total_gb=$(( (rx_bytes + tx_bytes) / 1024 / 1024 / 1024 ))
            
            sed -i "s/BANDWIDTH_USED=.*/BANDWIDTH_USED=$total_gb/" "$USERS_DIR/${username}.conf"
        fi
    fi
}

# Setup bandwidth monitoring
setup_bandwidth_monitoring() {
    # Create iptables rules for bandwidth monitoring
    iptables -N BANDWIDTH_MONITOR 2>/dev/null || true
    iptables -F BANDWIDTH_MONITOR
    iptables -A FORWARD -j BANDWIDTH_MONITOR
    
    # Add rules for each user
    for user_conf in "$USERS_DIR"/*.conf; do
        if [[ -f "$user_conf" ]]; then
            source "$user_conf"
            local ip=$(grep -r "$USERNAME" /etc/wireguard/clients/ | grep "Address" | cut -d= -f2 | tr -d ' ' | cut -d/ -f1)
            if [[ ! -z "$ip" ]]; then
                iptables -A BANDWIDTH_MONITOR -d "$ip"
                iptables -A BANDWIDTH_MONITOR -s "$ip"
            fi
        fi
    done
}

# Cleanup expired users
cleanup_expired_users() {
    for user_conf in "$USERS_DIR"/*.conf; do
        if [[ -f "$user_conf" ]]; then
            source "$user_conf"
            if [[ $(date -d "$EXPIRY_DATE" +%s) -lt $(date +%s) ]]; then
                username=$(basename "$user_conf" .conf)
                
                # Remove user configs from download directory
                if [ -f /etc/vpn-manager/download.conf ]; then
                    source /etc/vpn-manager/download.conf
                    if [ "$DOWNLOAD_ENABLED" = "yes" ]; then
                        echo -e "${YELLOW}Removing expired user configs for: $username${NC}"
                        rm -rf "/var/www/download/$username"
                    fi
                fi
                
                # Remove the user
                remove_user "$username"
                log_message "Removed expired user: $username"
            fi
        fi
    done
}

# SSH User Management
add_ssh_user() {
    local username="$1"
    local password="$2"
    
    # Check if user exists
    if id "$username" >/dev/null 2>&1; then
        log_message "${RED}SSH user $username already exists${NC}"
        return 1
    fi
    
    # Create user with home directory
    useradd -m -s /bin/bash "$username"
    
    # Set password
    echo "$username:$password" | chpasswd
    
    # Add user to SSH allowed users
    echo "AllowUsers $username" >> /etc/ssh/sshd_config
    
    # Create .ssh directory
    mkdir -p "/home/$username/.ssh"
    chmod 700 "/home/$username/.ssh"
    touch "/home/$username/.ssh/authorized_keys"
    chmod 600 "/home/$username/.ssh/authorized_keys"
    chown -R "$username:$username" "/home/$username/.ssh"
    
    # Store SSH credentials in user config
    sed -i "/^BANDWIDTH_USED=/a SSH_PASS=$password" "$USERS_DIR/${username}.conf"
    
    # Restart SSH service
    systemctl restart sshd
}

remove_ssh_user() {
    local username="$1"
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        log_message "${RED}SSH user $username does not exist${NC}"
        return 1
    fi
    
    # Remove user from SSH allowed users
    sed -i "/^AllowUsers.*$username/d" /etc/ssh/sshd_config
    
    # Delete user and their home directory
    userdel -r "$username"
    
    # Remove SSH credentials from user config
    sed -i "/^SSH_PASS=/d" "$USERS_DIR/${username}.conf"
    
    # Restart SSH service
    systemctl restart sshd
}

setup_ssh_server() {
    echo -e "${YELLOW}Setting up SSH server...${NC}"
    
    # Install SSH server if not installed
    if [[ "$OS" == "debian" ]] || [[ "$OS" == "ubuntu" ]]; then
        apt install -y openssh-server fail2ban
    elif [[ "$OS" == "centos" ]]; then
        yum install -y openssh-server fail2ban
    fi
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Configure SSH server with enhanced security
    cat > /etc/ssh/sshd_config << EOF
# SSH Server Configuration
Port 22
Protocol 2

# HostKeys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 60
MaxSessions 2

# Security
X11Forwarding no
AllowTcpForwarding yes
AllowAgentForwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
MaxStartups 10:30:60

# Strict Mode and Logging
StrictModes yes
SyslogFacility AUTH
LogLevel VERBOSE

# Accept locale-related environment variables
AcceptEnv LANG LC_*

# Subsystem
Subsystem sftp /usr/lib/openssh/sftp-server

# Allowed Users
AllowUsers 
EOF
    
    # Generate new host keys with stronger algorithms
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
    ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N ""
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    
    # Set correct permissions
    chmod 600 /etc/ssh/ssh_host_*_key
    chmod 644 /etc/ssh/ssh_host_*_key.pub
    
    # Configure fail2ban for SSH
    cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 300
bantime = 3600
EOF

    # Create SSH banner
    cat > /etc/ssh/banner << EOF
╔════════════════════════════════════════════╗
║         AUTHORIZED ACCESS ONLY             ║
║                                           ║
║ This system is restricted to authorized   ║
║ users only. All activities are logged     ║
║ and monitored.                            ║
║                                           ║
║ Disconnect immediately if you are not an  ║
║ authorized user!                          ║
╚════════════════════════════════════════════╝
EOF

    # Add banner to SSH config
    echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
    
    # Create SSH directory structure
    mkdir -p /etc/ssh/authorized_keys
    chmod 755 /etc/ssh/authorized_keys
    
    # Enable and restart services
    systemctl enable sshd fail2ban
    systemctl restart sshd fail2ban
    
    # Configure firewall for SSH
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 22/tcp
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --reload
    fi
    
    # Add SSH monitoring to cron
    cat > /etc/cron.d/ssh-monitor << EOF
*/5 * * * * root /usr/bin/find /var/log -name "auth.log*" -exec grep -l "Failed password" {} \; | xargs -l tail -n0 -f | grep -i "Failed password" >> /var/log/ssh-attempts.log
EOF
    
    # Create log rotation for SSH monitoring
    cat > /etc/logrotate.d/ssh-monitor << EOF
/var/log/ssh-attempts.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
EOF

    echo -e "${GREEN}SSH server setup completed with enhanced security${NC}"
    echo -e "${YELLOW}Default SSH port: 22${NC}"
    echo -e "${YELLOW}SSH logs: /var/log/auth.log${NC}"
    echo -e "${YELLOW}Failed attempts log: /var/log/ssh-attempts.log${NC}"
    
    # Show current SSH status
    systemctl status sshd
    
    # Show fail2ban status
    fail2ban-client status sshd
}

# OpenVPN Management
setup_openvpn() {
    # Install OpenVPN
    if [[ "$OS" == "debian" ]]; then
        apt install -y openvpn easy-rsa
    elif [[ "$OS" == "centos" ]]; then
        yum install -y epel-release
        yum install -y openvpn easy-rsa
    fi

    # Initialize PKI
    mkdir -p /etc/openvpn/easy-rsa
    cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
    cd /etc/openvpn/easy-rsa

    # Initialize PKI
    ./easyrsa init-pki
    echo "yes" | ./easyrsa build-ca nopass
    echo "yes" | ./easyrsa gen-dh
    echo "yes" | ./easyrsa build-server-full server nopass
    openvpn --genkey secret /etc/openvpn/ta.key

    # Create server config
    cat > /etc/openvpn/server.conf << EOF
port 1194
proto udp
dev tun
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem
tls-auth /etc/openvpn/ta.key 0
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
EOF

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p

    # Configure firewall
    setup_firewall

    # Enable and start OpenVPN
    systemctl enable openvpn@server
    systemctl start openvpn@server
}

add_openvpn_user() {
    local username="$1"
    cd /etc/openvpn/easy-rsa

    # Generate client certificate
    echo "yes" | ./easyrsa build-client-full "$username" nopass

    # Create client config directory
    mkdir -p /etc/openvpn/clients

    # Create client config
    cat > "/etc/openvpn/clients/${username}.ovpn" << EOF
client
dev tun
proto udp
remote $(curl -s ifconfig.me) 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3
<ca>
$(cat /etc/openvpn/easy-rsa/pki/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/easy-rsa/pki/issued/${username}.crt)
</cert>
<key>
$(cat /etc/openvpn/easy-rsa/pki/private/${username}.key)
</key>
<tls-auth>
$(cat /etc/openvpn/ta.key)
key-direction 1
</tls-auth>
EOF

    # Store OpenVPN status in user config
    sed -i "/^BANDWIDTH_USED=/a OPENVPN=enabled" "$USERS_DIR/${username}.conf"
}

remove_openvpn_user() {
    local username="$1"
    cd /etc/openvpn/easy-rsa

    # Revoke client certificate
    echo "yes" | ./easyrsa revoke "$username"
    ./easyrsa gen-crl

    # Remove client config
    rm -f "/etc/openvpn/clients/${username}.ovpn"

    # Remove OpenVPN status from user config
    sed -i "/^OPENVPN=/d" "$USERS_DIR/${username}.conf"
}

# L2TP/IPsec Management
setup_l2tp() {
    # Install L2TP and IPsec
    if [[ "$OS" == "debian" ]]; then
        apt install -y strongswan xl2tpd
    elif [[ "$OS" == "centos" ]]; then
        yum install -y strongswan xl2tpd
    fi

    # Generate PSK
    PSK=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
    echo "$PSK" > /etc/ipsec.secrets

    # Configure IPsec
    cat > /etc/ipsec.conf << EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn L2TP-PSK-NAT
    type=transport
    keyexchange=ikev1
    authby=secret
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    rekey=no
    forceencaps=yes
    auto=add
EOF

    # Configure xl2tpd
    cat > /etc/xl2tpd/xl2tpd.conf << EOF
[global]
port = 1701

[lns default]
ip range = 10.10.10.100-10.10.10.200
local ip = 10.10.10.1
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

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p

    # Configure firewall
    setup_firewall

    # Start services
    systemctl enable strongswan xl2tpd
    systemctl restart strongswan xl2tpd

    # Save PSK to config
    echo "L2TP_PSK=$PSK" >> /etc/vpn-manager/config.conf
}

add_l2tp_user() {
    local username="$1"
    local password="$2"

    # Add user to ppp config
    echo "$username * $password *" >> /etc/ppp/chap-secrets

    # Store L2TP credentials in user config
    sed -i "/^BANDWIDTH_USED=/a L2TP_PASS=$password" "$USERS_DIR/${username}.conf"
}

remove_l2tp_user() {
    local username="$1"

    # Remove user from ppp config
    sed -i "/^$username \*/d" /etc/ppp/chap-secrets

    # Remove L2TP credentials from user config
    sed -i "/^L2TP_PASS=/d" "$USERS_DIR/${username}.conf"
}

# V2Ray Setup
setup_v2ray() {
    # Install V2Ray
    if [[ "$OS" == "debian" ]]; then
        apt install -y curl unzip nginx certbot python3-certbot-nginx
    elif [[ "$OS" == "centos" ]]; then
        yum install -y curl unzip nginx certbot python3-certbot-nginx
    fi

    # Download and install V2Ray
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

    # Get domain for TLS
    read -p "Enter your domain name for V2Ray: " domain
    
    # Get SSL certificate
    certbot --nginx -d "$domain" --non-interactive --agree-tos --email admin@"$domain"
    
    # Configure V2Ray
    cat > /usr/local/etc/v2ray/config.json << EOF
{
  "inbounds": [{
    "port": 10086,
    "protocol": "vmess",
    "settings": {
      "clients": []
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

    # Configure Nginx
    cat > /etc/nginx/conf.d/v2ray.conf << EOF
server {
    listen 443 ssl;
    server_name $domain;

    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    location /v2ray {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10086;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF

    # Store domain in config
    echo "V2RAY_DOMAIN=$domain" >> /etc/vpn-manager/config.conf
    echo "V2RAY_PORT=443" >> /etc/vpn-manager/config.conf

    # Configure firewall
    setup_firewall

    # Start services
    systemctl enable v2ray nginx
    systemctl restart v2ray nginx

    # Create and update banner
    create_connection_banner
    update_banner_info "default"
    setup_http_custom
}

# Trojan Setup
setup_trojan() {
    # Install dependencies
    if [[ "$OS" == "debian" ]]; then
        apt install -y curl unzip nginx certbot python3-certbot-nginx
    elif [[ "$OS" == "centos" ]]; then
        yum install -y curl unzip nginx certbot python3-certbot-nginx
    fi

    # Download and install Trojan
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/trojan-gfw/trojan-quickstart/master/trojan-quickstart.sh)"

    # Get domain for TLS
    read -p "Enter your domain name for Trojan: " domain
    
    # Get SSL certificate
    certbot --nginx -d "$domain" --non-interactive --agree-tos --email admin@"$domain"
    
    # Generate password
    local password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
    
    # Configure Trojan
    cat > /usr/local/etc/trojan/config.json << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "$password"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/etc/letsencrypt/live/$domain/fullchain.pem",
        "key": "/etc/letsencrypt/live/$domain/privkey.pem",
        "alpn": [
            "http/1.1"
        ]
    },
    "tcp": {
        "prefer_ipv4": true,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": true,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
EOF

    # Configure Nginx for fallback
    cat > /etc/nginx/conf.d/trojan.conf << EOF
server {
    listen 80;
    server_name $domain;
    
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 127.0.0.1:80;
    server_name $domain;
    
    location / {
        root /var/www/html;
        index index.html;
    }
}
EOF

    # Store configuration
    echo "TROJAN_DOMAIN=$domain" >> /etc/vpn-manager/config.conf
    echo "TROJAN_PORT=443" >> /etc/vpn-manager/config.conf

    # Configure firewall
    setup_firewall

    # Start services
    systemctl enable trojan nginx
    systemctl restart trojan nginx

    # Create and update banner
    create_connection_banner
    update_banner_info "default"
    setup_http_custom
}

# SlowDNS Management
setup_slowdns() {
    echo -e "${YELLOW}Setting up SlowDNS server...${NC}"
    
    # Detect OS and version
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    fi
    
    # Install dependencies based on OS version
    echo -e "${YELLOW}Installing dependencies for $OS $VER...${NC}"
    case "$OS" in
        "ubuntu")
            # Add universe repository for older versions
            add-apt-repository universe -y
            apt update
            
            case "$VER" in
                "18.04")
                    # Ubuntu 18.04 specific
                    apt install -y bind9=1:9.11* dnsutils git build-essential
                    ;;
                "20.04")
                    # Ubuntu 20.04 specific
                    apt install -y bind9=1:9.16* dnsutils git build-essential
                    ;;
                *)
                    apt install -y bind9 dnsutils git build-essential
                    ;;
            esac
            ;;
        "debian")
            # Add backports for newer versions of packages
            case "$VER" in
                "9")
                    # Debian 9 (Stretch)
                    echo "deb http://deb.debian.org/debian stretch-backports main" > /etc/apt/sources.list.d/backports.list
                    apt update
                    apt install -y -t stretch-backports bind9
                    apt install -y dnsutils git build-essential
                    ;;
                "10")
                    # Debian 10 (Buster)
                    echo "deb http://deb.debian.org/debian buster-backports main" > /etc/apt/sources.list.d/backports.list
                    apt update
                    apt install -y -t buster-backports bind9
                    apt install -y dnsutils git build-essential
                    ;;
                *)
                    apt install -y bind9 dnsutils git build-essential
                    ;;
            esac
            ;;
    esac

    # Create directories
    mkdir -p /etc/slowdns
    cd /etc/slowdns

    # Generate DNS key pair with compatibility mode
    echo -e "${YELLOW}Generating DNS key pair...${NC}"
    if [[ "$OS" == "debian" && "$VER" == "9" ]]; then
        # Use older HMAC-SHA256 for Debian 9 compatibility
        dnssec-keygen -a HMAC-SHA256 -b 256 -n HOST slowdns
    else
        dnssec-keygen -a HMAC-SHA512 -b 512 -n HOST slowdns
    fi

    # Get NS domain
    read -p "Enter your NS domain for SlowDNS: " ns_domain
    read -p "Enter your NS subdomain (default: ns): " ns_subdomain
    ns_subdomain=${ns_subdomain:-ns}

    # Save domain info
    echo "SLOWDNS_DOMAIN=$ns_domain" > /etc/slowdns/config
    echo "SLOWDNS_SUBDOMAIN=$ns_subdomain" >> /etc/slowdns/config
    
    # Configure Bind9 with version-specific settings
    echo -e "${YELLOW}Configuring Bind9...${NC}"
    
    # Base configuration compatible with all versions
    cat > /etc/bind/named.conf.options << EOF
options {
    directory "/var/cache/bind";
    listen-on { any; };
    listen-on-v6 { any; };
    allow-query { any; };
    recursion yes;
    allow-recursion { any; };
    forwarders {
        8.8.8.8;
        8.8.4.4;
    };
EOF

    # Add version-specific options
    if [[ "$OS" == "ubuntu" && "$VER" == "20.04" ]] || [[ "$OS" == "debian" && "$VER" == "10" ]]; then
        # Newer versions support these options
        cat >> /etc/bind/named.conf.options << EOF
    dnssec-validation auto;
    auth-nxdomain no;
    version none;
    hostname none;
EOF
    else
        # Older versions need simpler configuration
        cat >> /etc/bind/named.conf.options << EOF
    dnssec-enable yes;
    dnssec-validation yes;
EOF
    fi

    # Close options block
    echo "};" >> /etc/bind/named.conf.options

    # Configure zone with version-specific settings
    cat > /etc/bind/named.conf.local << EOF
zone "$ns_domain" {
    type master;
    file "/etc/bind/db.$ns_domain";
    allow-update { any; };
};
EOF

    # Create zone file with appropriate TTL for different versions
    if [[ "$OS" == "ubuntu" && "$VER" == "18.04" ]] || [[ "$OS" == "debian" && "$VER" == "9" ]]; then
        TTL=86400  # Older versions prefer longer TTL
    else
        TTL=3600   # Newer versions can handle shorter TTL
    fi

    cat > "/etc/bind/db.$ns_domain" << EOF
\$TTL    $TTL
@       IN      SOA     $ns_domain. admin.$ns_domain. (
                     $(date +%Y%m%d)01     ; Serial
                         3600         ; Refresh
                          180         ; Retry
                        604800         ; Expire
                         $TTL )       ; Negative Cache TTL
;
@       IN      NS      $ns_subdomain.$ns_domain.
@       IN      A       $(curl -s ifconfig.me)
$ns_subdomain   IN      A       $(curl -s ifconfig.me)
EOF

    # Set correct permissions
    chown -R bind:bind /etc/bind
    chmod -R 755 /etc/bind

    # Install SlowDNS with version-specific compilation
    echo -e "${YELLOW}Installing SlowDNS...${NC}"
    git clone https://github.com/sshsedang/slowdns.git
    cd slowdns
    
    # Use specific compilation flags for older systems
    if [[ "$OS" == "debian" && "$VER" == "9" ]] || [[ "$OS" == "ubuntu" && "$VER" == "18.04" ]]; then
        CFLAGS="-O2 -Wall" make
    else
        make
    fi
    
    cp slowdns /usr/local/bin/
    chmod +x /usr/local/bin/slowdns

    # Create systemd service with version-specific settings
    cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=SlowDNS Service
After=network.target bind9.service

[Service]
Type=simple
ExecStart=/usr/local/bin/slowdns -server -key /etc/slowdns/Kslowdns.*.key -dnsport 53 -dnsip 127.0.0.1
Restart=always
RestartSec=3
EOF

    # Add specific settings for older systems
    if [[ "$OS" == "debian" && "$VER" == "9" ]] || [[ "$OS" == "ubuntu" && "$VER" == "18.04" ]]; then
        echo "StartLimitInterval=0" >> /etc/systemd/system/slowdns.service
    fi

    echo "[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/slowdns.service

    # Configure firewall
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 53/tcp
        ufw allow 53/udp
        ufw allow 5300/tcp
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=53/tcp
        firewall-cmd --permanent --add-port=53/udp
        firewall-cmd --permanent --add-port=5300/tcp
        firewall-cmd --reload
    fi

    # Enable and start services with version-specific service names
    if [[ "$OS" == "debian" && "$VER" == "9" ]]; then
        systemctl enable bind9
        systemctl restart bind9
    else
        systemctl enable named bind9
        systemctl restart named bind9
    fi
    
    systemctl enable slowdns
    systemctl start slowdns

    # Save key information
    cp /etc/slowdns/Kslowdns.*.key /etc/slowdns/server.key
    cp /etc/slowdns/Kslowdns.*.private /etc/slowdns/server.private

    echo -e "${GREEN}SlowDNS setup completed!${NC}"
    echo -e "NS Domain: $ns_domain"
    echo -e "NS Subdomain: $ns_subdomain.$ns_domain"
    echo -e "DNS Key: $(cat /etc/slowdns/server.key)"
    echo -e "OS Version: $OS $VER"
}

add_slowdns_user() {
    local username="$1"
    local ns_domain
    local ns_subdomain
    
    # Load SlowDNS config
    source /etc/slowdns/config
    
    # Create user directory
    mkdir -p "/etc/slowdns/users/$username"
    
    # Generate user key
    cd /etc/slowdns/users/$username
    dnssec-keygen -a HMAC-SHA512 -b 512 -n HOST "$username"
    
    # Create user config
    cat > "/etc/slowdns/users/$username/config.conf" << EOF
NS_DOMAIN=$SLOWDNS_DOMAIN
NS_SUBDOMAIN=$SLOWDNS_SUBDOMAIN
DNS_KEY=$(cat Kslowdns.*.key)
EOF
    
    # Store SlowDNS info in user config
    sed -i "/^BANDWIDTH_USED=/a SLOWDNS_KEY=$(cat Kslowdns.*.key)" "$USERS_DIR/${username}.conf"
    
    # Create client config
    cat > "/etc/slowdns/users/$username/client.conf" << EOF
# SlowDNS Client Configuration
nameserver $SLOWDNS_SUBDOMAIN.$SLOWDNS_DOMAIN
dns-key $(cat Kslowdns.*.key)
EOF
}

remove_slowdns_user() {
    local username="$1"
    
    # Remove user directory and configs
    rm -rf "/etc/slowdns/users/$username"
    
    # Remove SlowDNS info from user config
    sed -i "/^SLOWDNS_KEY=/d" "$USERS_DIR/${username}.conf"
}

show_slowdns_info() {
    local username="$1"
    
    if [[ -f "/etc/slowdns/users/$username/config.conf" ]]; then
        source "/etc/slowdns/users/$username/config.conf"
        echo -e "\n${BLUE}▼ SlowDNS Configuration${NC}"
        echo -e "━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "NS Domain     : $NS_DOMAIN"
        echo -e "NS Subdomain  : $NS_SUBDOMAIN"
        echo -e "DNS Key       : $DNS_KEY"
        echo -e "\nClient config file: /etc/slowdns/users/$username/client.conf"
    fi
}

# Update create_user function to include SlowDNS
create_user() {
    # ... existing user creation code ...
    
    # Add SlowDNS user
    add_slowdns_user "$username"
    
    # ... rest of the function ...
}

# Update remove_user function to include SlowDNS
remove_user() {
    # ... existing user removal code ...
    
    # Remove SlowDNS user
    remove_slowdns_user "$username"
    
    # ... rest of the function ...
}

# Update show_user_credentials to include SlowDNS
show_user_credentials() {
    local username="$1"
    local domain=$(curl -s ifconfig.me)
    local password=$(get_user_password "$username")
    
    if [ ! -z "$password" ]; then
        echo -e "\n${BLUE}▼ SSH VPN Configuration${NC}"
        echo -e "━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "Format: domain:port@username:password\n"
        echo -e "${GREEN}SSL/TLS Connection:${NC}"
        echo -e "$domain:443@$username:$password"
        echo -e "\n${GREEN}Direct SSH:${NC}"
        echo -e "$domain:22@$username:$password"
        echo -e "\n${GREEN}Dropbear:${NC}"
        echo -e "$domain:80@$username:$password"
        echo -e "$domain:143@$username:$password"
        
        echo -e "\n${YELLOW}Available Ports:${NC}"
        echo -e "SSL/TLS    : 443"
        echo -e "SSH        : 22"
        echo -e "Dropbear   : 80, 143"
        
        echo -e "\n${YELLOW}Additional Info:${NC}"
        echo -e "Created    : $(date '+%Y-%m-%d')"
        echo -e "Expires    : $(chage -l $username | grep "Account expires" | cut -d: -f2)"
    else
        echo -e "${RED}User not found or configuration missing${NC}"
    fi
}

# Function to check OS compatibility
check_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_message "${RED}Cannot detect OS version. This script requires Ubuntu 18.04/20.04 or Debian 10${NC}"
        exit 1
    fi

    source /etc/os-release
    OS=$ID
    VER=$VERSION_ID

    case "$OS" in
        "ubuntu")
            case "$VER" in
                "18.04"|"20.04")
                    log_message "${GREEN}Detected Ubuntu $VER - Compatible${NC}"
                    ;;
                *)
                    log_message "${RED}This script only supports Ubuntu 18.04 and 20.04${NC}"
                    exit 1
                    ;;
            esac
            ;;
        "debian")
            case "$VER" in
                "10")
                    log_message "${GREEN}Detected Debian $VER (Buster) - Compatible${NC}"
                    ;;
                *)
                    log_message "${RED}This script only supports Debian 10${NC}"
                    exit 1
                    ;;
            esac
            ;;
        *)
            log_message "${RED}This script only supports Ubuntu and Debian systems${NC}"
            exit 1
            ;;
    esac

    # Export variables for use in other functions
    export OS_NAME=$OS
    export OS_VERSION=$VER
}

# Update system packages with version-specific repositories
update_system() {
    log_message "${YELLOW}Updating system packages for $OS_NAME $OS_VERSION...${NC}"

    case "$OS_NAME" in
        "ubuntu")
            # Add required repositories for Ubuntu
            apt-get update
            apt-get install -y software-properties-common apt-transport-https ca-certificates curl wget gnupg lsb-release

            # Add universe and multiverse repositories
            add-apt-repository universe -y
            add-apt-repository multiverse -y

            # Add additional repositories based on version
            case "$OS_VERSION" in
                "18.04")
                    # Add Backports for 18.04
                    add-apt-repository -y ppa:ubuntu-toolchain-r/ppa
                    ;;
                "20.04")
                    # Add specific repos for 20.04 if needed
                    add-apt-repository -y ppa:ondrej/php
                    ;;
            esac
            ;;
        "debian")
            # Add required repositories for Debian 10
            apt-get update
            apt-get install -y apt-transport-https ca-certificates curl wget gnupg lsb-release

            # Add Backports repository
            echo "deb http://deb.debian.org/debian buster-backports main" > /etc/apt/sources.list.d/backports.list
            
            # Add additional required repositories
            echo "deb http://deb.debian.org/debian buster-updates main" > /etc/apt/sources.list.d/updates.list
            ;;
    esac

    # Update package lists
    apt-get update

    # Install common dependencies with version-specific packages
    case "$OS_NAME" in
        "ubuntu")
            case "$OS_VERSION" in
                "18.04")
                    apt-get install -y build-essential libssl1.0* net-tools iptables-persistent \
                    python3.6 python3-pip git unzip wget curl jq uuid-runtime qrencode socat
                    ;;
                "20.04")
                    apt-get install -y build-essential libssl1.1* net-tools iptables-persistent \
                    python3.8 python3-pip git unzip wget curl jq uuid-runtime qrencode socat
                    ;;
            esac
            ;;
        "debian")
            apt-get install -y build-essential libssl1.1* net-tools iptables-persistent \
            python3 python3-pip git unzip wget curl jq uuid-runtime qrencode socat
            ;;
    esac

    # Install additional required packages
    apt-get install -y \
        iptables \
        netfilter-persistent \
        nano \
        rng-tools \
        openvpn \
        openssl \
        cron \
        fail2ban \
        vnstat \
        ufw \
        systemd

    # Version specific installations
    case "$OS_NAME" in
        "ubuntu")
            case "$OS_VERSION" in
                "18.04")
                    # Install specific version of Node.js for 18.04
                    curl -fsSL https://deb.nodesource.com/setup_14.x | bash -
                    apt-get install -y nodejs
                    ;;
                "20.04")
                    # Install newer version of Node.js for 20.04
                    curl -fsSL https://deb.nodesource.com/setup_16.x | bash -
                    apt-get install -y nodejs
                    ;;
            esac
            ;;
        "debian")
            # Install Node.js for Debian 10
            curl -fsSL https://deb.nodesource.com/setup_14.x | bash -
            apt-get install -y nodejs
            ;;
    esac

    # Enable BBR for better performance
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p

    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p

    # Configure timezone
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    dpkg-reconfigure -f noninteractive tzdata

    log_message "${GREEN}System update completed successfully${NC}"
}

# Function to configure firewall with version-specific rules
setup_firewall() {
    log_message "${YELLOW}Setting up firewall rules...${NC}"

    # Reset UFW
    ufw --force reset

    # Configure UFW defaults
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH (always first)
    ufw allow 22/tcp

    # Version specific firewall configurations
    case "$OS_NAME" in
        "ubuntu")
            case "$OS_VERSION" in
                "18.04")
                    # Additional rules for 18.04
                    ufw allow 80/tcp
                    ufw allow 443/tcp
                    ufw allow 1194/udp
                    ufw allow 51820/udp
                    ufw allow 500,4500/udp
                    ufw allow 7100:7900/tcp
                    ufw allow 7100:7900/udp
                    ;;
                "20.04")
                    # Additional rules for 20.04
                    ufw allow 80/tcp
                    ufw allow 443/tcp
                    ufw allow 1194/udp
                    ufw allow 51820/udp
                    ufw allow 500,4500/udp
                    ufw allow 7100:7900/tcp
                    ufw allow 7100:7900/udp
                    # Additional modern protocol support
                    ufw allow 8443/tcp  # HTTPS alt
                    ufw allow 2053/tcp  # DNS over HTTPS
                    ;;
            esac
            ;;
        "debian")
            # Debian 10 specific rules
            ufw allow 80/tcp
            ufw allow 443/tcp
            ufw allow 1194/udp
            ufw allow 51820/udp
            ufw allow 500,4500/udp
            ufw allow 7100:7900/tcp
            ufw allow 7100:7900/udp
            # Additional security rules for Debian
            ufw limit ssh
            ufw allow 53/tcp
            ufw allow 53/udp
            ;;
    esac

    # Common rules for all versions
    # V2Ray
    ufw allow 8000:9000/tcp
    
    # Shadowsocks
    ufw allow 8388/tcp
    ufw allow 8388/udp
    
    # Trojan
    ufw allow 443/tcp
    
    # OpenVPN
    ufw allow 1194/udp
    
    # WireGuard
    ufw allow 51820/udp
    
    # L2TP/IPsec
    ufw allow 500/udp
    ufw allow 4500/udp
    ufw allow 1701/udp
    
    # SlowDNS
    ufw allow 53/tcp
    ufw allow 53/udp
    ufw allow 5300/tcp

    # Enable UFW
    echo "y" | ufw enable

    log_message "${GREEN}Firewall configuration completed${NC}"
}

# Speed Test Functions
speedtest_menu() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           ${GREEN}VPS SPEED TEST MENU${NC}           ${BLUE}║${NC}"
    echo -e "${BLUE}╠═════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC} 1. Network Speed Test (speedtest-cli)    ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 2. Disk Speed Test                       ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 3. CPU Performance Test                  ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 4. Memory Speed Test                     ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 5. Network Latency Test                  ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 6. Bandwidth Usage Monitor               ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 7. Complete System Benchmark             ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 8. Back to Main Menu                     ${BLUE}║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════╝${NC}"
    echo
    read -p "Select an option [1-8]: " choice

    case $choice in
        1) network_speedtest ;;
        2) disk_speedtest ;;
        3) cpu_test ;;
        4) memory_test ;;
        5) latency_test ;;
        6) bandwidth_monitor ;;
        7) complete_benchmark ;;
        8) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

network_speedtest() {
    echo -e "${YELLOW}Running Network Speed Test...${NC}"
    
    # Install speedtest-cli if not installed
    if ! command -v speedtest-cli &> /dev/null; then
        apt-get install -y python3-pip
        pip3 install speedtest-cli
    fi
    
    echo -e "\n${GREEN}Testing Download and Upload Speeds...${NC}"
    speedtest-cli --simple
    
    # Test to different servers
    echo -e "\n${GREEN}Testing speeds to different locations:${NC}"
    servers=(
        "2406"  # Singapore
        "7311"  # Hong Kong
        "6527"  # Japan
        "8158"  # USA
    )
    
    for server in "${servers[@]}"; do
        echo -e "\n${YELLOW}Testing server $server...${NC}"
        speedtest-cli --server $server --simple
    done
}

disk_speedtest() {
    echo -e "${YELLOW}Running Disk Speed Test...${NC}"
    
    # Install required tools
    apt-get install -y hdparm dd
    
    # Direct disk read speed
    echo -e "\n${GREEN}Testing direct disk read speed:${NC}"
    hdparm -Tt /dev/sda
    
    # Write speed test
    echo -e "\n${GREEN}Testing disk write speed:${NC}"
    dd if=/dev/zero of=tempfile bs=1M count=1024 conv=fdatasync 2>&1
    
    # Read speed test
    echo -e "\n${GREEN}Testing disk read speed:${NC}"
    dd if=tempfile of=/dev/null bs=1M count=1024 2>&1
    
    # Clean up
    rm -f tempfile
}

cpu_test() {
    echo -e "${YELLOW}Running CPU Performance Test...${NC}"
    
    # Install required tools
    apt-get install -y sysbench
    
    # CPU test parameters
    threads=$(nproc)
    
    echo -e "\n${GREEN}Running CPU prime number test...${NC}"
    sysbench cpu --cpu-max-prime=20000 --threads=$threads run
    
    echo -e "\n${GREEN}CPU Information:${NC}"
    lscpu
    
    echo -e "\n${GREEN}CPU Temperature:${NC}"
    if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
        temp=$(cat /sys/class/thermal/thermal_zone0/temp)
        temp=$((temp/1000))
        echo "${temp}°C"
    else
        echo "Temperature information not available"
    fi
}

memory_test() {
    echo -e "${YELLOW}Running Memory Speed Test...${NC}"
    
    # Install required tools
    apt-get install -y sysbench
    
    # Memory test parameters
    total_mem=$(free -m | awk '/Mem:/ {print $2}')
    test_size=$((total_mem / 2))
    
    echo -e "\n${GREEN}Running memory read test...${NC}"
    sysbench memory --memory-block-size=1K --memory-total-size=${test_size}M --memory-access-mode=seq run
    
    echo -e "\n${GREEN}Running memory write test...${NC}"
    sysbench memory --memory-block-size=1K --memory-total-size=${test_size}M --memory-access-mode=rnd run
    
    echo -e "\n${GREEN}Memory Information:${NC}"
    free -h
}

latency_test() {
    echo -e "${YELLOW}Running Network Latency Test...${NC}"
    
    # Install required tools
    apt-get install -y mtr
    
    # Test targets
    targets=(
        "8.8.8.8"         # Google DNS
        "1.1.1.1"         # Cloudflare DNS
        "amazon.com"      # AWS
        "facebook.com"    # Facebook
    )
    
    for target in "${targets[@]}"; do
        echo -e "\n${GREEN}Testing latency to $target:${NC}"
        mtr --report --report-cycles=10 $target
    done
}

bandwidth_monitor() {
    echo -e "${YELLOW}Setting up Bandwidth Monitoring...${NC}"
    
    # Install required tools
    apt-get install -y vnstat
    
    # Initialize vnstat
    vnstat -u -i $(route | grep '^default' | grep -o '[^ ]*$')
    systemctl start vnstat
    
    # Show bandwidth usage
    echo -e "\n${GREEN}Hourly Bandwidth Usage:${NC}"
    vnstat -h
    
    echo -e "\n${GREEN}Daily Bandwidth Usage:${NC}"
    vnstat -d
    
    echo -e "\n${GREEN}Monthly Bandwidth Usage:${NC}"
    vnstat -m
}

complete_benchmark() {
    echo -e "${YELLOW}Running Complete System Benchmark...${NC}"
    
    # Create result directory
    mkdir -p /root/benchmark_results
    result_file="/root/benchmark_results/benchmark_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "=== VPS Complete Benchmark Results ==="
        echo "Date: $(date)"
        echo "System: $(uname -a)"
        echo
        
        echo "=== CPU Information ==="
        lscpu
        echo
        
        echo "=== Memory Information ==="
        free -h
        echo
        
        echo "=== Disk Information ==="
        df -h
        echo
        
        echo "=== Network Speed Test ==="
        speedtest-cli --simple
        echo
        
        echo "=== CPU Benchmark ==="
        sysbench cpu --cpu-max-prime=20000 --threads=$(nproc) run
        echo
        
        echo "=== Memory Benchmark ==="
        sysbench memory --memory-block-size=1K --memory-total-size=1G run
        echo
        
        echo "=== Disk Benchmark ==="
        dd if=/dev/zero of=tempfile bs=1M count=1024 conv=fdatasync 2>&1
        rm -f tempfile
        echo
        
        echo "=== Network Latency ==="
        ping -c 10 8.8.8.8
        echo
        
    } | tee "$result_file"
    
    echo -e "${GREEN}Benchmark complete! Results saved to: $result_file${NC}"
}

# System Cleanup Functions
cleanup_system() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         ${GREEN}SYSTEM CLEANUP MENU${NC}            ${BLUE}║${NC}"
    echo -e "${BLUE}╠═════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC} 1. Clean Package Cache               ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 2. Remove Old Kernels               ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 3. Clean System Logs                ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 4. Remove Unused Dependencies       ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 5. Clean Temp Files                 ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 6. Remove Old VPN Configs           ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 7. Clean All (Full System Cleanup)  ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 8. Back to Main Menu                ${BLUE}║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════╝${NC}"
    
    read -p "Select an option [1-8]: " choice
    
    case $choice in
        1) clean_package_cache ;;
        2) remove_old_kernels ;;
        3) clean_system_logs ;;
        4) remove_unused_dependencies ;;
        5) clean_temp_files ;;
        6) clean_vpn_configs ;;
        7) clean_all ;;
        8) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

clean_package_cache() {
    echo -e "${YELLOW}Cleaning package cache...${NC}"
    
    # Clean apt cache
    apt-get clean
    apt-get autoclean
    
    # Remove package cache
    rm -rf /var/lib/apt/lists/*
    apt-get update
    
    echo -e "${GREEN}Package cache cleaned successfully${NC}"
}

remove_old_kernels() {
    echo -e "${YELLOW}Removing old kernels...${NC}"
    
    # Get current kernel version
    current_kernel=$(uname -r)
    
    # Remove old kernels but keep the current one
    dpkg -l | grep linux-image | awk '{print $2}' | grep -v $(uname -r) | xargs -r apt-get purge -y
    
    # Update grub
    update-grub
    
    echo -e "${GREEN}Old kernels removed successfully${NC}"
}

clean_system_logs() {
    echo -e "${YELLOW}Cleaning system logs...${NC}"
    
    # Clean journal logs
    journalctl --vacuum-time=3d
    
    # Clean old log files
    find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
    find /var/log -type f -name "*.gz" -delete
    
    # Clean VPN logs
    find /var/log -type f -name "*vpn*.log" -exec truncate -s 0 {} \;
    
    echo -e "${GREEN}System logs cleaned successfully${NC}"
}

remove_unused_dependencies() {
    echo -e "${YELLOW}Removing unused dependencies...${NC}"
    
    # Remove unused packages
    apt-get autoremove -y
    
    # Remove orphaned packages
    deborphan | xargs apt-get -y remove --purge
    
    echo -e "${GREEN}Unused dependencies removed successfully${NC}"
}

clean_temp_files() {
    echo -e "${YELLOW}Cleaning temporary files...${NC}"
    
    # Clean /tmp directory
    rm -rf /tmp/*
    
    # Clean user cache
    rm -rf /root/.cache/*
    
    # Clean thumbnail cache
    rm -rf /root/.thumbnails/*
    
    # Clean other temp directories
    rm -rf /var/tmp/*
    
    echo -e "${GREEN}Temporary files cleaned successfully${NC}"
}

clean_vpn_configs() {
    echo -e "${YELLOW}Cleaning old VPN configurations...${NC}"
    
    # Get list of active users
    active_users=$(ls "$USERS_DIR" | grep .conf | sed 's/.conf//')
    
    # Clean OpenVPN configs
    for conf in /etc/openvpn/clients/*.ovpn; do
        username=$(basename "$conf" .ovpn)
        if [[ ! " ${active_users[@]} " =~ " ${username} " ]]; then
            rm -f "$conf"
        fi
    done
    
    # Clean WireGuard configs
    for conf in /etc/wireguard/clients/*.conf; do
        username=$(basename "$conf" .conf)
        if [[ ! " ${active_users[@]} " =~ " ${username} " ]]; then
            rm -f "$conf"
            rm -f "/etc/wireguard/clients/${username}_private.key"
            rm -f "/etc/wireguard/clients/${username}_public.key"
        fi
    done
    
    # Clean Shadowsocks configs
    for conf in /etc/shadowsocks-libev/*.json; do
        username=$(basename "$conf" .json)
        if [[ ! " ${active_users[@]} " =~ " ${username} " ]] && [[ "$username" != "config" ]]; then
            rm -f "$conf"
        fi
    done
    
    # Clean SlowDNS configs
    for dir in /etc/slowdns/users/*; do
        username=$(basename "$dir")
        if [[ ! " ${active_users[@]} " =~ " ${username} " ]]; then
            rm -rf "$dir"
        fi
    done
    
    echo -e "${GREEN}Old VPN configurations cleaned successfully${NC}"
}

clean_all() {
    echo -e "${YELLOW}Starting full system cleanup...${NC}"
    
    clean_package_cache
    remove_old_kernels
    clean_system_logs
    remove_unused_dependencies
    clean_temp_files
    clean_vpn_configs
    
    # Final cleanup
    apt-get clean
    apt-get autoremove -y
    
    # Show disk usage before and after
    echo -e "\n${GREEN}Cleanup completed. Disk usage summary:${NC}"
    df -h /
}

# Schedule Management Functions
setup_auto_reboot() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         ${GREEN}AUTO REBOOT SETTINGS${NC}           ${BLUE}║${NC}"
    echo -e "${BLUE}╠═════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC} 1. Set Custom Reboot Time              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 2. Use Default (12:00 AM)             ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 3. Disable Auto Reboot                ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 4. Show Current Schedule              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 5. Back to Main Menu                  ${BLUE}║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════╝${NC}"
    
    read -p "Select an option [1-5]: " choice
    
    case $choice in
        1)
            set_custom_reboot_time
            ;;
        2)
            configure_auto_reboot "0 0"  # 12:00 AM
            ;;
        3)
            disable_auto_reboot
            ;;
        4)
            show_reboot_schedule
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
}

set_custom_reboot_time() {
    echo -e "\n${YELLOW}Set Custom Reboot Time${NC}"
    echo -e "Please enter the hour (0-23) and minute (0-59) for daily reboot"
    
    while true; do
        read -p "Hour (0-23): " hour
        if [[ "$hour" =~ ^[0-9]+$ ]] && [ "$hour" -ge 0 ] && [ "$hour" -le 23 ]; then
            break
        else
            echo -e "${RED}Invalid hour. Please enter a number between 0 and 23${NC}"
        fi
    done
    
    while true; do
        read -p "Minute (0-59): " minute
        if [[ "$minute" =~ ^[0-9]+$ ]] && [ "$minute" -ge 0 ] && [ "$minute" -le 59 ]; then
            break
        else
            echo -e "${RED}Invalid minute. Please enter a number between 0 and 59${NC}"
        fi
    done
    
    configure_auto_reboot "$minute $hour"
}

configure_auto_reboot() {
    local schedule="$1"
    
    # Backup existing crontab
    crontab -l > /tmp/crontab.bak 2>/dev/null || echo "" > /tmp/crontab.bak
    
    # Check if reboot schedule already exists
    if grep -q "auto_reboot" /tmp/crontab.bak; then
        # Remove existing schedule
        sed -i '/auto_reboot/d' /tmp/crontab.bak
    fi
    
    # Create reboot script
    cat > /usr/local/sbin/auto_reboot.sh << 'EOF'
#!/bin/bash

# Log file for reboot events
LOG_FILE="/var/log/auto_reboot.log"

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Check active connections
check_connections() {
    # Count SSH connections
    ssh_count=$(who | wc -l)
    # Count OpenVPN connections
    ovpn_count=$(pgrep -f "openvpn.*client" | wc -l)
    # Count WireGuard connections
    wg_count=$(wg show all | grep -c "latest handshake")
    
    echo "$((ssh_count + ovpn_count + wg_count))"
}

# Get current system status
uptime_info=$(uptime)
memory_used=$(free -m | awk '/Mem:/ {printf "%.2f%%", $3*100/$2}')
disk_used=$(df -h / | awk 'NR==2 {print $5}')

# Log system status before reboot
log_message "=== System Status Before Reboot ==="
log_message "Uptime: $uptime_info"
log_message "Memory Usage: $memory_used"
log_message "Disk Usage: $disk_used"

# Check active connections
active_conn=$(check_connections)
log_message "Active Connections: $active_conn"

# Broadcast reboot message to all users
wall "
╔════════════════════════════════════════════╗
║          SYSTEM REBOOT NOTICE              ║
║                                           ║
║ This server will reboot in 5 minutes      ║
║ Please save your work and disconnect      ║
║                                           ║
║ Time: $(date '+%Y-%m-%d %H:%M:%S')           ║
╚════════════════════════════════════════════╝
"

# Wait 5 minutes
sleep 300

# Final connection check
final_conn=$(check_connections)
log_message "Final Active Connections: $final_conn"

# Sync filesystem
sync

# Reboot the system
log_message "Initiating system reboot"
/sbin/reboot
EOF

    # Make script executable
    chmod +x /usr/local/sbin/auto_reboot.sh
    
    # Add to crontab
    echo "$schedule * * * /usr/local/sbin/auto_reboot.sh # auto_reboot" >> /tmp/crontab.bak
    crontab /tmp/crontab.bak
    
    # Create log file if it doesn't exist
    touch /var/log/auto_reboot.log
    chmod 644 /var/log/auto_reboot.log
    
    # Setup log rotation if not already configured
    if [ ! -f /etc/logrotate.d/auto-reboot ]; then
        cat > /etc/logrotate.d/auto-reboot << EOF
/var/log/auto_reboot.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
EOF
    fi
    
    # Convert 24-hour format to 12-hour format for display
    hour=$(echo $schedule | awk '{print $2}')
    minute=$(echo $schedule | awk '{print $1}')
    if [ "$hour" -ge 12 ]; then
        if [ "$hour" -gt 12 ]; then
            display_hour=$((hour - 12))
        else
            display_hour=12
        fi
        ampm="PM"
    else
        if [ "$hour" -eq 0 ]; then
            display_hour=12
        else
            display_hour=$hour
        fi
        ampm="AM"
    fi
    
    echo -e "${GREEN}Auto reboot has been scheduled for $display_hour:$(printf "%02d" $minute) $ampm daily${NC}"
    echo -e "${YELLOW}Reboot logs will be saved to: /var/log/auto_reboot.log${NC}"
    
    # Show current crontab
    echo -e "\n${GREEN}Current crontab schedule:${NC}"
    crontab -l
}

disable_auto_reboot() {
    # Backup existing crontab
    crontab -l > /tmp/crontab.bak 2>/dev/null || echo "" > /tmp/crontab.bak
    
    # Remove auto reboot entry if it exists
    if grep -q "auto_reboot" /tmp/crontab.bak; then
        sed -i '/auto_reboot/d' /tmp/crontab.bak
        crontab /tmp/crontab.bak
        echo -e "${GREEN}Auto reboot has been disabled${NC}"
    else
        echo -e "${YELLOW}No auto reboot schedule found${NC}"
    fi
}

show_reboot_schedule() {
    echo -e "\n${GREEN}Current Auto Reboot Schedule:${NC}"
    if crontab -l | grep -q "auto_reboot"; then
        schedule=$(crontab -l | grep "auto_reboot")
        minute=$(echo $schedule | awk '{print $1}')
        hour=$(echo $schedule | awk '{print $2}')
        
        # Convert to 12-hour format
        if [ "$hour" -ge 12 ]; then
            if [ "$hour" -gt 12 ]; then
                display_hour=$((hour - 12))
            else
                display_hour=12
            fi
            ampm="PM"
        else
            if [ "$hour" -eq 0 ]; then
                display_hour=12
            else
                display_hour=$hour
            fi
            ampm="AM"
        fi
        
        echo -e "Server will reboot daily at $display_hour:$(printf "%02d" $minute) $ampm"
    else
        echo -e "${YELLOW}No auto reboot schedule is currently set${NC}"
    fi
    
    # Show last reboot time if available
    if [ -f /var/log/auto_reboot.log ]; then
        echo -e "\n${GREEN}Last Reboot Log:${NC}"
        tail -n 5 /var/log/auto_reboot.log
    fi
}

# Config Download Management
setup_config_download() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       ${GREEN}CONFIG DOWNLOAD SETTINGS${NC}         ${BLUE}║${NC}"
    echo -e "${BLUE}╠═════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC} 1. Setup/Change Download Domain         ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 2. Enable/Disable Config Download      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 3. Show Download URLs                  ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 4. Configure Auto Cleanup              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} 5. Back to Main Menu                   ${BLUE}║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════╝${NC}"
    
    read -p "Select an option [1-5]: " choice
    
    case $choice in
        1) setup_download_domain ;;
        2) toggle_config_download ;;
        3) show_download_urls ;;
        4) setup_auto_cleanup ;;
        5) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

setup_download_domain() {
    echo -e "\n${YELLOW}Setup Config Download Domain${NC}"
    
    # Check if download is already configured
    if [ -f /etc/vpn-manager/download.conf ]; then
        source /etc/vpn-manager/download.conf
        echo -e "Current download domain: ${GREEN}$DOWNLOAD_DOMAIN${NC}"
    fi
    
    # Get new domain
    read -p "Enter subdomain for config downloads (e.g., download.yourdomain.com): " domain
    
    # Validate domain format
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}Invalid domain format${NC}"
        return 1
    fi
    
    # Install required packages if not installed
    apt-get install -y nginx certbot python3-certbot-nginx
    
    # Get SSL certificate
    certbot --nginx -d "$domain" --non-interactive --agree-tos --email "admin@$domain"
    
    # Create download directory
    mkdir -p /var/www/download
    chown -R www-data:www-data /var/www/download
    chmod -R 755 /var/www/download
    
    # Configure Nginx for download site
    cat > /etc/nginx/conf.d/config-download.conf << EOF
server {
    listen 443 ssl;
    server_name $domain;

    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    root /var/www/download;
    index index.html;

    # Basic authentication
    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    location / {
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
        
        # Allow only config files
        location ~* \.(ovpn|conf|json|txt)$ {
            add_header Content-Disposition "attachment";
        }
        
        # Deny access to other file types
        location ~* \.(php|html|htm|asp|aspx|js|jsp)$ {
            deny all;
        }
    }
    
    # Custom error pages
    error_page 401 403 404 /error.html;
    location = /error.html {
        internal;
    }
}

server {
    listen 80;
    server_name $domain;
    return 301 https://$host$request_uri;
}
EOF

    # Create basic error page
    cat > /var/www/download/error.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
        }
        h1 { color: #e74c3c; }
    </style>
</head>
<body>
    <h1>Error</h1>
    <p>The requested resource is not available.</p>
</body>
</html>
EOF

    # Create or update download configuration
    mkdir -p /etc/vpn-manager
    cat > /etc/vpn-manager/download.conf << EOF
DOWNLOAD_DOMAIN="$domain"
DOWNLOAD_ENABLED="yes"
EOF

    # Create default credentials
    DOWNLOAD_USER="vpnuser"
    DOWNLOAD_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)
    
    # Create htpasswd file
    apt-get install -y apache2-utils
    htpasswd -bc /etc/nginx/.htpasswd "$DOWNLOAD_USER" "$DOWNLOAD_PASS"
    
    # Secure the credentials file
    chmod 600 /etc/nginx/.htpasswd
    
    # Save credentials
    echo "DOWNLOAD_USER=\"$DOWNLOAD_USER\"" >> /etc/vpn-manager/download.conf
    echo "DOWNLOAD_PASS=\"$DOWNLOAD_PASS\"" >> /etc/vpn-manager/download.conf
    
    # Restart Nginx
    systemctl restart nginx
    
    echo -e "\n${GREEN}Download site configured successfully!${NC}"
    echo -e "Domain: ${YELLOW}$domain${NC}"
    echo -e "Username: ${YELLOW}$DOWNLOAD_USER${NC}"
    echo -e "Password: ${YELLOW}$DOWNLOAD_PASS${NC}"
    echo -e "\nAutomatic cleanup of expired users configured"
    echo -e "Cleanup runs daily at midnight"
    echo -e "\nPlease save these credentials!"
    
    # Setup automatic cleanup
    setup_auto_cleanup
}

toggle_config_download() {
    if [ ! -f /etc/vpn-manager/download.conf ]; then
        echo -e "${RED}Download site not configured. Please set up domain first.${NC}"
        return 1
    fi
    
    source /etc/vpn-manager/download.conf
    
    if [ "$DOWNLOAD_ENABLED" = "yes" ]; then
        sed -i 's/DOWNLOAD_ENABLED="yes"/DOWNLOAD_ENABLED="no"/' /etc/vpn-manager/download.conf
        rm -f /etc/nginx/conf.d/config-download.conf
        echo -e "${YELLOW}Config download has been disabled${NC}"
    else
        sed -i 's/DOWNLOAD_ENABLED="no"/DOWNLOAD_ENABLED="yes"/' /etc/vpn-manager/download.conf
        setup_download_domain
        echo -e "${GREEN}Config download has been enabled${NC}"
    fi
    
    systemctl restart nginx
}

show_download_urls() {
    if [ ! -f /etc/vpn-manager/download.conf ]; then
        echo -e "${RED}Download site not configured. Please set up domain first.${NC}"
        return 1
    fi
    
    source /etc/vpn-manager/download.conf
    
    if [ "$DOWNLOAD_ENABLED" != "yes" ]; then
        echo -e "${RED}Config download is currently disabled${NC}"
        return 1
    fi
    
    echo -e "\n${GREEN}Config Download Information${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Download URL : https://$DOWNLOAD_DOMAIN"
    echo -e "Username     : $DOWNLOAD_USER"
    echo -e "Password     : $DOWNLOAD_PASS"
    echo -e "\n${YELLOW}Available Config Files:${NC}"
    
    # List available config files
    find /var/www/download -type f \( -name "*.ovpn" -o -name "*.conf" -o -name "*.json" \) -printf "▸ %f\n"
}

# Update copy_config_to_download function to copy configs to download directory
copy_config_to_download() {
    local username="$1"
    
    # Check if download is enabled
    if [ ! -f /etc/vpn-manager/download.conf ]; then
        return 0
    fi
    
    source /etc/vpn-manager/download.conf
    if [ "$DOWNLOAD_ENABLED" != "yes" ]; then
        return 0
    fi
    
    # Create user directory in download folder
    mkdir -p "/var/www/download/$username"
    
    # Copy OpenVPN config
    if [ -f "/etc/openvpn/clients/${username}.ovpn" ]; then
        cp "/etc/openvpn/clients/${username}.ovpn" "/var/www/download/$username/"
    fi
    
    # Copy WireGuard config
    if [ -f "/etc/wireguard/clients/${username}.conf" ]; then
        cp "/etc/wireguard/clients/${username}.conf" "/var/www/download/$username/wireguard.conf"
    fi
    
    # Copy V2Ray config if exists
    if [ -f "/etc/v2ray/clients/${username}.json" ]; then
        cp "/etc/v2ray/clients/${username}.json" "/var/www/download/$username/"
    fi
    
    # Copy Trojan config if exists
    if [ -f "/etc/trojan/clients/${username}.json" ]; then
        cp "/etc/trojan/clients/${username}.json" "/var/www/download/$username/"
    fi
    
    # Create combined credentials file
    if [ -f "$USERS_DIR/${username}.conf" ]; then
        {
            echo "VPN Credentials for $username"
            echo "================================"
            echo "Created: $(date)"
            echo ""
            source "$USERS_DIR/${username}.conf"
            
            if [ ! -z "$SSH_PASS" ]; then
                echo "SSH Credentials:"
                echo "Username: $username"
                echo "Password: $SSH_PASS"
                echo ""
            fi
            
            if [ ! -z "$OPENVPN" ]; then
                echo "OpenVPN Config: ${username}.ovpn"
            fi
            
            if [ ! -z "$WIREGUARD" ]; then
                echo "WireGuard Config: wireguard.conf"
            fi
            
            if [ ! -z "$V2RAY_UUID" ]; then
                echo "V2Ray UUID: $V2RAY_UUID"
            fi
            
            if [ ! -z "$TROJAN_PASS" ]; then
                echo "Trojan Password: $TROJAN_PASS"
            fi
            
            if [ ! -z "$SLOWDNS_KEY" ]; then
                echo "SlowDNS Key: $SLOWDNS_KEY"
            fi
        } > "/var/www/download/$username/credentials.txt"
    fi
    
    # Set correct permissions
    chown -R www-data:www-data "/var/www/download/$username"
    chmod -R 644 "/var/www/download/$username"/*
    find "/var/www/download/$username" -type d -exec chmod 755 {} \;
}

# Update show_menu to include the new option
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
    echo "9. Setup SSH VPN"
    echo "10. Check Ports Status"
    echo "11. Configure Firewall"
    echo "12. Edit Banner"
    echo "13. Speed Test VPS"
    echo "14. System Cleanup"
    echo "15. Schedule Auto Reboot"
    echo "16. Config Download Settings"
    echo "17. Update System Dependencies"
    echo "18. Backup System"
    echo "19. Setup Notifications"
    echo "20. Monitoring Dashboard"
    echo "21. Trial Account Management"
    echo "22. Exit"
}

# Update main loop to include the new option
while true; do
    show_menu
    read -p "Select an option [1-22]: " choice
    
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
            setup_ssh_vpn
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
            speedtest_menu
            ;;
        14)
            cleanup_system
            ;;
        15)
            setup_auto_reboot
            ;;
        16)
            setup_config_download
            ;;
        17)
            update_system_dependencies
            ;;
        18)
            setup_backup_system
            ;;
        19)
            setup_notifications
            ;;
        20)
            create_monitoring_dashboard
            ;;
        21)
            setup_trial_account
            ;;
        22)
            echo -e "${GREEN}Thank you for using VPN Manager${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
done

# ... rest of the code ... 