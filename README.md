# harden-server.sh

**harden-server.sh** is a Bash script designed to harden and optimize Ubuntu Server 24.04 and newer.  
It disables telemetry, removes unnecessary services, configures essential security tools, applies firewall rules, and enforces strict SSH and network configurations — all in a modular and user-friendly format.

This script is intended for clean or lightly configured Ubuntu Server environments.

## Features

- Disable Ubuntu telemetry and reporting services  
- Remove unnecessary packages and services  
- Harden SSH configuration:  
  - Disable root login  
  - Disable password authentication  
- Configure UFW firewall with sensible defaults  
- Enable automatic security updates  
- Install and configure:  
  - fail2ban for intrusion prevention  
  - auditd for system auditing  
  - Zabbix Agent (optional)  
- Network hardening:  
  - Disable ICMP ping  
  - Enable SYN cookies  
  - Disable IPv6 (optional)  
  - Adjust TCP buffer sizes  
- Full APT system update and cleanup utilities  

## Installation

Clone the repository and make the script executable:

```bash
git clone https://github.com/vitorcruzfaculdade/harden-server.sh.git
cd harden-server.sh
chmod +x harden-server.sh
````

## Usage

Execute the script with one or more options:

```bash
sudo ./harden-server.sh [OPTIONS]
```

### Available Options

| Option             | Description                                                        |
| ------------------ | ------------------------------------------------------------------ |
| `--all`            | Run all main tasks (update, cleanup, harden, firewall, etc.)       |
| `--clean`          | Remove temporary files, broken dependencies, and cache             |
| `--update`         | Update all packages (APT and Snap)                                 |
| `--harden`         | Apply hardening (telemetry removal, SSH, network, tools, firewall) |
| `--firewall`       | Enable and configure UFW firewall                                  |
| `--ssh`            | Harden SSH server settings                                         |
| `--auto-updates`   | Enable automatic security updates with unattended-upgrades         |
| `--security-tools` | Install and configure fail2ban and auditd                          |
| `--network`        | Apply network-level security tweaks                                |
| `--zabbix`         | Install and enable Zabbix Agent 7.0 LTS                            |
| `--logs`           | Clean up old system logs (if implemented)                          |
| `-v`, `--version`  | Show script version                                                |
| `-h`, `--help`     | Display help and usage information                                 |

## Recommended Usage

For new or unconfigured Ubuntu Server environments, the following command applies all safe and recommended actions:

```bash
sudo ./harden-server.sh --all
```

You may also run individual modules for testing or customization purposes.

## License

This project is licensed under the GNU General Public License v3.0. See the `LICENSE` file for details.

## Author

**Vitor Cruz**
GitHub: [@vitorcruzfaculdade](https://github.com/vitorcruzfaculdade)

## Repository

[https://github.com/vitorcruzfaculdade/harden-server.sh](https://github.com/vitorcruzfaculdade/harden-server.sh)

## Disclaimer

Review the script before execution. It is intended for advanced users or administrators familiar with Linux systems. Use at your own risk.

