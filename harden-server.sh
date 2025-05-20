#!/bin/bash
#
# harden-server.sh
# Vitor Cruz's basic Hardening and disable Ubuntu Telemetry - for Ubuntu Servers
# License: GPL v3.0
# Downloaded from https://github.com/vitorcruzfaculdade/harden-server.sh

VERSION="1.0.7"
set -e

print_banner() {
  echo ""
  echo "┌─────────────────────────────────────────────────────────────────────────────┐"
  echo "│  harden-server.sh    v$VERSION                                                |"
  echo "│  Vitor Cruz's disable Ubuntu Telemetry for Ubuntu Server 24.04              |"
  echo "│  By Vitor Cruz · License: GPL v3.0                                          |"
  echo "|  Downloaded from https://github.com/vitorcruzfaculdade/harden-server.sh     |"
  echo "└─────────────────────────────────────────────────────────────────────────────┘"
  echo ""
}

confirm() {
  read -rp "$1 [y/N]: " response
  [[ "$response" =~ ^[Yy]$ ]]
}

disable_telemetry() {
  echo ""
  echo "Disabling telemetry and background reporting..."
  for service in apport whoopsie motd-news.timer; do
    if systemctl list-unit-files | grep -q "${service}"; then
       sudo systemctl disable "$service" --now || true
    fi
  done
  sudo sed -i 's/ENABLED=1/ENABLED=0/' /etc/default/motd-news || true
  sudo sed -i 's/ubuntu\.com/#ubuntu.com/' /etc/update-motd.d/90-updates-available || true

  {
    grep -q "metrics.ubuntu.com" /etc/hosts || echo "127.0.0.1 metrics.ubuntu.com" | sudo tee -a /etc/hosts
    grep -q "popcon.ubuntu.com" /etc/hosts || echo "127.0.0.1 popcon.ubuntu.com" | sudo tee -a /etc/hosts
  } || true

  for pkg in ubuntu-report ubuntu-advantage-tools popularity-contest apport apport-symptoms whoopsie kerneloops kerneloops-applet; do
    if dpkg -l | grep -q "^ii\s*$pkg"; then
      sudo apt purge -y "$pkg"
      sudo apt-mark hold "$pkg"
    fi
  done

  echo ""
  echo "Telemetry and background reporting fully disabled."
  echo ""
  if confirm "Do you want to disable Avahi (zeroconf/Bonjour/SSDP broadcasting)?"; then
    sudo systemctl disable avahi-daemon.socket avahi-daemon.service --now || true
    echo "Avahi broadcasting disabled."
  fi
}

full_cleanup() {
  echo ""
  echo "Cleaning temp files..."
  echo ""  
  echo "Checking for broken dependencies..."
  sudo apt-get check
  echo ""
  echo "Fixing broken dependencies (if any)..."
  sudo apt-get -f install -y
  echo ""
  echo "Cleaning useless packages"
  sudo apt-get --purge autoremove -y
  echo ""
  echo "Cleaning apt-get cache ..."
  sudo apt-get autoclean
  sudo apt-get clean
  echo ""
  echo "Cleaning temporary files..."
  sudo rm -rf /tmp/*
  rm -rf ~/.cache/*
  echo ""
  echo "Package and temporary files clean!"
}

update_system() {
  echo ""
  echo "Updating APT packages..."
  sudo apt update && sudo apt full-upgrade -y
  echo ""
  echo "APT packages updated."
  echo ""
  echo "Cleaning up unused packages..."
  sudo apt autoremove --purge -y && sudo apt autoclean -y
  echo ""
  echo "Package cleanup complete."
  echo ""
  echo "Updating Snaps"
  sudo snap refresh
}

setup_firewall() {
  echo ""
  echo "Installing / Updating UFW..."
  sudo apt update
  sudo apt install ufw -y
  echo ""
  echo "Setting up UFW firewall rules..."

  if sudo ufw status | grep -q "Status: active"; then
    echo ""
    echo "UFW is already active."
    if ! confirm "Do you want to reconfigure the firewall?"; then
      echo ""
      echo "Skipping firewall configuration."
      return
    fi
  else
    if ! confirm "Firewall is inactive. Do you want to enable and configure it now?"; then
      echo ""
      echo "Skipping firewall setup."
      return
    fi
  fi

  echo ""
  echo "Enabling UFW..."
  sudo systemctl enable ufw
  echo ""
  echo "Restarting/Reseting UFW..."
  sudo systemctl restart ufw
  echo ""
  sudo ufw --force reset
  echo ""
  echo "Setting default deny rule for incoming traffic..."
  sudo ufw default deny incoming
  echo ""
  echo "Denied incoming traffic (from outside) in UFW."
  echo ""
  echo "Allowing connections started from this system to outside..."
  sudo ufw default allow outgoing
  echo ""
  echo "Allowed outgoing traffic in UFW."
  echo ""
  echo "Enabling and applying settings to UFW..."
  sudo ufw enable
  echo ""
  echo "Enabled UFW."
  echo ""
  echo "Reloading UFW..."
  sudo ufw reload
  echo ""
  echo "Reloaded UFW."

  if confirm "Do you want to enable UFW logging?"; then
    sudo ufw logging on
    log_status="enabled"
    echo ""
    echo "UFW logging on"
  else
    sudo ufw logging off
    log_status="disabled"
    echo ""
    echo "UFW logging off"
  fi

  sudo ufw reload
  echo ""
  echo "UFW Firewall configured and enabled — logging $log_status, incoming connections denied."
}

install_security_tools() {
  echo ""
  echo "Installing security tools..."

  echo ""
  if confirm "Do you want to install and configure auditd for security auditing?"; then
    sudo apt install -y auditd
    sudo systemctl enable auditd
    sudo systemctl start auditd
    echo ""
    echo "Auditd installed and started."
  fi

  echo ""
  
  if confirm "Do you want to install and configure fail2ban for brute-force protection?"; then
    sudo apt install -y fail2ban
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
    echo ""
    echo "Fail2ban installed and started."
  fi
  
  echo ""
  echo "Security tools installation complete."
}

install_zabbix_agent() {
  echo ""
  echo "Installing Zabbix agent (LTS)..."

  if confirm "Do you want to install the Zabbix Agent (LTS)?"; then
    wget https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest_7.0+ubuntu24.04_all.deb
    sudo dpkg -i zabbix-release_latest_7.0+ubuntu24.04_all.deb
    echo ""
    echo "Updating apt repository cache..."
    sudo apt update
    echo ""
    echo "Installing the Zabbix agent..."
    sudo apt install -y zabbix-agent2

    echo ""  
    echo "Enabling and starting the Zabbix agent"
    sudo systemctl restart zabbix-agent2
    sudo systemctl enable zabbix-agent2
    
    echo ""
    echo "Zabbix Agent 2 installed and started - You may need to set your Zabbix server IP in /etc/zabbix-agent/ config file and/or UFW to Allow Zabbix conections."
   else
    echo ""
    echo "Skipping Zabbix agent installation."
  fi
}

harden_system() {
  echo ""
  echo "Starting system hardening..."

  # Disable unnecessary services
  disable_telemetry
  
  # Hardening SSH
  harden_ssh
  
  # Enable automatic updates
  enable_automatic_updates
  
  # Install security tools
  install_security_tools
  
  # Network hardening
  harden_network
  
  echo "System hardening complete."
}

harden_ssh() {
  echo ""
  echo "Hardening SSH..."

  if confirm "Do you want to disable root login via SSH?"; then
    sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    echo "Root login disabled."
  else
    echo "Skipped disabling root login."
  fi

  if confirm "Do you want to disable password authentication (enforce key-based auth)?"; then
    sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    echo "Password authentication disabled."
  else
    echo "Skipped disabling password authentication."
  fi

  echo "Reloading SSH to apply changes..."
  sudo systemctl reload ssh
  echo ""
  echo "SSH hardening complete."
}

enable_automatic_updates() {
  echo ""
  if confirm "Do you want to enable automatic security updates?"; then
    echo "Enabling automatic security updates..."
    sudo apt install -y unattended-upgrades
    sudo dpkg-reconfigure --priority=low unattended-upgrades
    echo "Automatic security updates enabled."
  else
    echo "Skipped automatic security updates configuration."
  fi
  echo ""
}

harden_network() {
  echo ""
  echo "Hardening network settings..."

  SYSCTL_CONF="/etc/sysctl.d/99-harden-server.conf"
  sudo touch "$SYSCTL_CONF"
  sudo chmod 644 "$SYSCTL_CONF"

  apply_sysctl() {
    local key="$1"
    local value="$2"
    sudo sysctl -w "$key=$value"

    # Remove linha existente com mesma chave, se houver
    sudo sed -i "/^$key\s*=.*/d" "$SYSCTL_CONF"

    # Adiciona nova configuração
    echo "$key = $value" | sudo tee -a "$SYSCTL_CONF" > /dev/null
  }

  if confirm "Do you want to enable SYN cookies (protection against SYN flood attacks)?"; then
    apply_sysctl net.ipv4.tcp_syncookies 1
    echo "SYN cookies enabled."
  fi

  if confirm "Do you want to ignore all ICMP ping requests?"; then
    apply_sysctl net.ipv4.icmp_echo_ignore_all 1
    echo "ICMP ping requests ignored."
  fi

  if confirm "Do you want to disable source routing?"; then
    apply_sysctl net.ipv4.conf.all.accept_source_route 0
    echo "Source routing disabled."
  fi

  if confirm "Do you want to enable reverse path filtering?"; then
    apply_sysctl net.ipv4.conf.all.rp_filter 1
    echo "Reverse path filtering enabled."
  fi

  if confirm "Do you want to set TCP buffer sizes?"; then
    apply_sysctl net.ipv4.tcp_rmem "4096 87380 16777216"
    apply_sysctl net.ipv4.tcp_wmem "4096 65536 16777216"
    echo "TCP buffer sizes set."
  fi

  if confirm "Do you want to set the max number of incoming connections?"; then
    apply_sysctl net.core.somaxconn 1024
    echo "Max number of incoming connections set."
  fi

  if confirm "Do you want to disable IPv6 on this system?"; then
    apply_sysctl net.ipv6.conf.all.disable_ipv6 1
    apply_sysctl net.ipv6.conf.default.disable_ipv6 1
    apply_sysctl net.ipv6.conf.lo.disable_ipv6 1
    echo "IPv6 has been disabled."
  fi

  sudo sysctl --system > /dev/null
  echo ""
  echo "Network hardening applied and saved to $SYSCTL_CONF."
}

print_help() {
  echo "Usage: ./harden-server.sh [options]"
  echo ""
  echo "  Options:"
  echo "  --all            Run all available tasks (update, cleanup, harden, firewall, etc.)"
  echo "  --clean          Full cleanup and temp file clearing"
  echo "  --update         Run update only (no cleanup)"
  echo "  --harden         Apply system hardening: telemetry off, SSH/network tweaks, firewall, audit tools"
  echo "  --firewall       Configure and enable UFW firewall"
  echo "  --ssh            Harden SSH configuration (disable root login, disable password auth)"
  echo "  --auto-updates   Enable automatic security updates"
  echo "  --security-tools Install and configure auditd and fail2ban for brute-force protection"
  echo "  --network        Harden network settings (e.g., SYN flood protection, ICMP, etc.)"
  echo "  --zabbix         Install and configure Zabbix Agent (LTS)"
  echo "  --logs           Clean up old logs"
}

### Main Entry Point ###
main() {
  print_banner
  
  if [[ $# -eq 0 ]]; then
    print_help
    exit 0
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --clean) full_cleanup ;;
      --update) update_system ;;
      --harden) disable_telemetry; setup_firewall; install_security_tools; harden_ssh; harden_network ;;
      --firewall) setup_firewall ;;
      --ssh) harden_ssh ;;
      --auto-updates) enable_automatic_updates ;;
      --security-tools) install_security_tools ;;
      --network) harden_network ;;
      --zabbix) install_zabbix_agent ;;
      --all)
        update_system
        full_cleanup
        disable_telemetry
        setup_firewall
        install_security_tools
        harden_ssh
        harden_network
        enable_automatic_updates
        install_zabbix_agent
        ;;
      -v|--version) echo "Version $VERSION"; exit 0 ;;
      -h|--help) print_help; exit 0 ;;
      *) echo "Unknown option: $1"; print_help; exit 1 ;;
    esac
    shift
  done

  echo ""
  echo "Done. Don't forget to reboot if major updates or kernel upgrades were installed."
}

# Run main function
main "$@"

#EOF
