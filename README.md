# VPN Manager - All-in-One VPN Server Solution

A comprehensive VPN server management system supporting multiple protocols and advanced features.

## Supported Protocols
- SSH (Multi-Features)
  - OpenSSH
  - Dropbear
  - Stunnel4 (SSL/TLS)
  - WebSocket
  - BadVPN UDP
  - SSH Over DNS
- V2Ray
- WireGuard
- OpenVPN
- Shadowsocks
- Trojan
- SlowDNS
- L2TP/IPsec

## Features
- Multi-protocol support
- User management system
- Bandwidth monitoring
- Auto-cleanup for expired users
- Trial account system
- Backup system (auto & manual)
- Web-based monitoring dashboard
- Config download system with SSL/TLS
- Telegram notification integration

## SSH Features
- Multi-Port Support:
  - OpenSSH: 22
  - Dropbear: 143, 109, 50000
  - Stunnel4: 443 (Dropbear), 777 (OpenSSH)
  - WebSocket: 8880
  - BadVPN: 7300 (UDP)
  - DNS Tunnel: 53
- Management Tools:
  - Connection Monitor
  - Speed Test
  - Auto-Kill Multi Login
  - User Connection Limiter
- Additional Features:
  - UDP Support via BadVPN
  - DNS Tunneling
  - WebSocket Support
  - SSL/TLS Encryption

## System Requirements
- Ubuntu 18.04/20.04 or Debian 10
- Root access
- Clean server (no other VPN services installed)
- Minimum 1GB RAM
- Minimum 20GB Storage

## Quick Install
```bash
wget -O vpn-installer.sh https://raw.githubusercontent.com/Leonidas150/ScriptAutoInstaller/main/vpn-installer.sh
chmod +x vpn-installer.sh
./vpn-installer.sh
```

## Manual Installation
1. Clone this repository:
```bash
git clone https://github.com/Leonidas150/ScriptAutoInstaller.git
cd ScriptAutoInstaller
```

2. Make the installer executable:
```bash
chmod +x vpn-installer.sh
```

3. Run the installer:
```bash
./vpn-installer.sh
```

## Usage Guide

### Main Menu
After installation, you can:
1. Run `vpn` to access the management menu
2. Run `vpn-uninstall` to remove everything

### SSH Commands
- Monitor connections:
```bash
ssh-monitor
```

- Test connection speed:
```bash
ssh-speedtest
```

- Set auto-kill for multiple logins:
```bash
ssh-autokill <max_connections>
Example: ssh-autokill 2
```

- Set user connection limit:
```bash
ssh-limit <username> <max_connections>
Example: ssh-limit myuser 2
```

### Management Menu Options
1. User Management
   - Add user
   - Delete user
   - Extend user
   - List users
   - Trial accounts
   - Set user limits

2. Service Management
   - Start/Stop services
   - View service status
   - Update configurations
   - Monitor connections

3. System Management
   - Backup/Restore
   - View logs
   - System cleanup
   - Update system
   - Firewall settings

4. Monitoring
   - Bandwidth usage
   - Online users
   - Server status
   - Connection logs

5. Emergency Menu
   - Stop all services
   - Reset firewall
   - Backup config
   - Complete cleanup

## Port Information
| Service    | Port                          | Protocol      |
|------------|-------------------------------|---------------|
| OpenSSH    | 22                           | TCP          |
| Dropbear   | 143, 109, 50000             | TCP          |
| Stunnel4   | 443, 777                    | TCP          |
| WebSocket  | 8880                        | TCP          |
| BadVPN     | 7300                        | UDP          |
| DNS Tunnel | 53                          | TCP/UDP      |
| V2Ray      | 10086                       | TCP          |
| WireGuard  | 51820                       | UDP          |
| OpenVPN    | 1194                        | UDP          |
| L2TP/IPsec | 500, 4500, 1701            | UDP          |
| SlowDNS    | 53, 5300                    | TCP/UDP      |

## Security Features
- Automatic SSL/TLS certification
- Fail2ban integration
- UFW firewall configuration
- Secure file permissions
- Regular security updates
- Connection limiting
- Multi-login detection
- Brute-force protection

## Directory Structure
```
/etc/vpn-manager/
├── users/         # User configurations
├── backups/       # Backup files
├── logs/          # Log files
├── configs/       # Service configurations
└── defaults/      # Default settings

/var/www/
├── download/      # Config download directory
└── html/
    └── monitor/   # Web monitoring dashboard
```

## Logs
All logs are stored in `/var/log/vpn-manager/`:
- events.log: System events
- access.log: Access attempts
- error.log: Error messages
- install.log: Installation log

## Troubleshooting
1. Connection Issues
   - Check service status: `systemctl status [service-name]`
   - View logs: `tail -f /var/log/vpn-manager/error.log`
   - Check ports: `netstat -tulpn`

2. Performance Issues
   - Monitor resources: `htop`
   - Check bandwidth: `vnstat`
   - Test speed: `ssh-speedtest`

3. User Issues
   - Check limits: `ssh-monitor`
   - Reset user: `vpn` > User Management
   - View logs: `tail -f /var/log/auth.log`

## Contributing
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Support
If you find this project helpful, please consider:
- Giving it a star on GitHub
- Contributing to the code
- Reporting any issues you find

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer
This tool is provided as-is without any warranty. Always review the code before installing on your server. 