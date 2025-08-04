#!/bin/bash

#################################################
# Working VPS Setup Script for Docker Manager
# No syntax errors - tested and working
#################################################

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration
ADMIN_USER="dockeradmin"
SSH_PORT="2222"
HOSTNAME="docker-manager"
TIMEZONE="UTC"

# Functions
print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

prompt_input() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    
    echo -e "${PURPLE}$prompt${NC} ${YELLOW}[default: $default]${NC}"
    read -r input
    
    if [ -z "$input" ]; then
        input="$default"
    fi
    
    eval "$var_name='$input'"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

collect_config() {
    print_step "Collecting configuration..."
    
    echo -e "${PURPLE}=== VPS Setup Configuration ===${NC}"
    echo ""
    
    prompt_input "Enter admin username:" "$ADMIN_USER" "ADMIN_USER"
    prompt_input "Enter SSH port:" "$SSH_PORT" "SSH_PORT"
    prompt_input "Enter hostname:" "$HOSTNAME" "HOSTNAME"
    
    echo ""
    echo -e "${PURPLE}Domain Configuration (optional):${NC}"
    prompt_input "Enter domain name (or press Enter to skip):" "" "DOMAIN_NAME"
    
    if [ -n "$DOMAIN_NAME" ]; then
        prompt_input "Enter email for SSL:" "" "SSL_EMAIL"
    else
        SSL_EMAIL=""
        print_warning "No domain - will use IP-based access"
    fi
    
    echo ""
    prompt_input "Enter your SSH public key (or press Enter to skip):" "" "SSH_PUBLIC_KEY"
    prompt_input "Enter alert email:" "" "ALERT_EMAIL"
}

update_system() {
    print_step "Updating system..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt update
    apt upgrade -y
    apt install -y curl wget git nano vim htop tree \
        apt-transport-https ca-certificates gnupg lsb-release \
        sudo ufw fail2ban logrotate rsync cron openssl
    
    print_status "System updated"
}

configure_system() {
    print_step "Configuring system..."
    
    timedatectl set-timezone "$TIMEZONE"
    hostnamectl set-hostname "$HOSTNAME"
    echo "127.0.0.1 $HOSTNAME" >> /etc/hosts
    
    print_status "System configured"
}

create_admin_user() {
    print_step "Creating admin user: $ADMIN_USER"
    
    if ! id "$ADMIN_USER" &>/dev/null; then
        adduser --disabled-password --gecos "" "$ADMIN_USER"
    fi
    
    usermod -aG sudo "$ADMIN_USER"
    
    # Setup SSH directory
    sudo -u "$ADMIN_USER" mkdir -p "/home/$ADMIN_USER/.ssh"
    sudo -u "$ADMIN_USER" chmod 700 "/home/$ADMIN_USER/.ssh"
    
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        echo "$SSH_PUBLIC_KEY" > "/home/$ADMIN_USER/.ssh/authorized_keys"
        chown "$ADMIN_USER:$ADMIN_USER" "/home/$ADMIN_USER/.ssh/authorized_keys"
        chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"
        print_status "SSH key added for $ADMIN_USER"
    fi
    
    print_status "Admin user created"
}

configure_ssh() {
    print_step "Configuring SSH security..."
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    cat > /etc/ssh/sshd_config << EOF
Port $SSH_PORT
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxStartups 2
LoginGraceTime 60
AllowUsers $ADMIN_USER
EOF
    
    sshd -t
    print_status "SSH configured"
}

configure_firewall() {
    print_step "Configuring firewall..."
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    ufw allow "$SSH_PORT"/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    ufw allow 3000/tcp comment 'Frontend'
    ufw allow 3001/tcp comment 'API'
    
    ufw --force enable
    print_status "Firewall configured"
}

configure_fail2ban() {
    print_step "Configuring Fail2Ban..."
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 ::1
backend = auto

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
    
    systemctl restart fail2ban
    systemctl enable fail2ban
    print_status "Fail2Ban configured"
}

install_docker() {
    print_step "Installing Docker..."
    
    # Remove old versions
    apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Add Docker GPG key
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    # Add repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    
    # Configure Docker daemon
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "userland-proxy": false,
  "live-restore": true
}
EOF
    
    usermod -aG docker "$ADMIN_USER"
    systemctl restart docker
    systemctl enable docker
    
    # Install Docker Compose standalone
    DOCKER_COMPOSE_VERSION="v2.24.0"
    curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    print_status "Docker installed"
}

install_nginx() {
    print_step "Installing Nginx..."
    
    apt install -y nginx
    
    # Get server IP
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    
    if [ -n "$DOMAIN_NAME" ]; then
        # Domain-based configuration
        cat > /etc/nginx/sites-available/docker-manager << EOF
server {
    listen 80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location /api/ {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    else
        # IP-based configuration
        cat > /etc/nginx/sites-available/docker-manager << EOF
server {
    listen 80;
    server_name $SERVER_IP _;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location /api/ {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    fi
    
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/docker-manager /etc/nginx/sites-enabled/
    nginx -t
    
    print_status "Nginx configured"
}

install_ssl() {
    print_step "Setting up SSL..."
    
    if [ -n "$DOMAIN_NAME" ] && [ -n "$SSL_EMAIL" ]; then
        # Install certbot
        apt install -y certbot python3-certbot-nginx
        
        # Stop nginx
        systemctl stop nginx
        
        # Get certificate
        if certbot certonly --standalone -d "$DOMAIN_NAME" -d "www.$DOMAIN_NAME" --email "$SSL_EMAIL" --agree-tos --non-interactive; then
            # Update nginx config
            sed -i "s|ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;|ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;|" /etc/nginx/sites-available/docker-manager
            sed -i "s|ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;|ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;|" /etc/nginx/sites-available/docker-manager
            
            # Setup auto-renewal
            echo "0 12 * * * /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'" | crontab -
            print_status "SSL certificate installed"
        else
            print_warning "SSL certificate installation failed"
        fi
        
        systemctl start nginx
    else
        print_warning "Skipping SSL - no domain provided"
    fi
    
    systemctl enable nginx
}

create_directories() {
    print_step "Creating directories..."
    
    mkdir -p /opt/docker-manager
    mkdir -p /opt/docker-data/{mongodb,redis,app}
    mkdir -p /var/log/docker-manager
    mkdir -p /opt/backups
    
    chown -R "$ADMIN_USER:$ADMIN_USER" /opt/docker-manager
    chown -R "$ADMIN_USER:$ADMIN_USER" /opt/docker-data
    chown -R "$ADMIN_USER:$ADMIN_USER" /var/log/docker-manager
    chown -R "$ADMIN_USER:$ADMIN_USER" /opt/backups
    
    print_status "Directories created"
}

create_env_template() {
    print_step "Creating environment template..."
    
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    
    if [ -n "$DOMAIN_NAME" ]; then
        CORS_ORIGIN="https://$DOMAIN_NAME"
    else
        CORS_ORIGIN="http://$SERVER_IP,https://$SERVER_IP"
    fi
    
    cat > /opt/docker-manager/.env.template << EOF
NODE_ENV=production
PORT=3001
MONGODB_URI=mongodb://mongodb:27017/docker-manager
REDIS_HOST=redis
REDIS_PORT=6379
JWT_SECRET=CHANGE_THIS_SECRET
JWT_REFRESH_SECRET=CHANGE_THIS_REFRESH_SECRET
CORS_ORIGIN=$CORS_ORIGIN
DOCKER_HOST=unix:///var/run/docker.sock
LOG_LEVEL=info
ALERT_EMAIL=$ALERT_EMAIL
EOF
    
    chown "$ADMIN_USER:$ADMIN_USER" /opt/docker-manager/.env.template
    print_status "Environment template created"
}

create_utility_scripts() {
    print_step "Creating utility scripts..."
    
    # System check script
    cat > /usr/local/bin/system-check.sh << 'EOF'
#!/bin/bash
echo "=== System Status Check ==="
echo "Date: $(date)"
echo "OS: $(lsb_release -d | cut -f2)"
echo "Uptime: $(uptime -p)"
echo "Memory: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
echo "Disk: $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"
echo "Docker: $(systemctl is-active docker 2>/dev/null || echo 'inactive')"
echo "Nginx: $(systemctl is-active nginx 2>/dev/null || echo 'inactive')"
echo "UFW: $(ufw status | head -1 | awk '{print $2}')"
echo "=========================="
EOF
    
    chmod +x /usr/local/bin/system-check.sh
    
    # Docker Manager prep script
    cat > /usr/local/bin/prepare-docker-manager.sh << EOF
#!/bin/bash
echo "=== Preparing Docker Manager ==="
cd /opt/docker-manager

if [ ! -f .env ]; then
    cp .env.template .env
    
    # Generate secrets
    JWT_SECRET=\$(openssl rand -base64 32)
    JWT_REFRESH_SECRET=\$(openssl rand -base64 32)
    
    sed -i "s/CHANGE_THIS_SECRET/\$JWT_SECRET/" .env
    sed -i "s/CHANGE_THIS_REFRESH_SECRET/\$JWT_REFRESH_SECRET/" .env
    
    echo "✓ Environment file created with generated secrets"
else
    echo "✓ Environment file already exists"
fi

echo ""
echo "Next steps:"
echo "1. su - $ADMIN_USER"
echo "2. cd /opt/docker-manager"
echo "3. Upload Docker Manager files"
echo "4. docker-compose up -d"
EOF
    
    chmod +x /usr/local/bin/prepare-docker-manager.sh
    
    print_status "Utility scripts created"
}

optimize_system() {
    print_step "Optimizing system..."
    
    # System limits
    cat > /etc/security/limits.d/99-docker.conf << EOF
* soft nofile 65536
* hard nofile 65536
$ADMIN_USER soft nofile 65536
$ADMIN_USER hard nofile 65536
EOF
    
    # Kernel parameters
    cat > /etc/sysctl.d/99-docker.conf << EOF
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
vm.swappiness=10
fs.file-max=2097152
EOF
    
    sysctl -p /etc/sysctl.d/99-docker.conf
    print_status "System optimized"
}

restart_services() {
    print_step "Restarting services..."
    
    systemctl restart ssh
    systemctl restart fail2ban
    systemctl restart nginx
    
    print_status "Services restarted"
}

generate_report() {
    print_step "Generating setup report..."
    
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    
    cat > /root/vps-setup-report.txt << EOF
=== VPS Setup Report ===
Date: $(date)
Hostname: $HOSTNAME
Admin User: $ADMIN_USER
SSH Port: $SSH_PORT
Server IP: $SERVER_IP
Domain: ${DOMAIN_NAME:-"None (IP-based access)"}

Access Information:
EOF
    
    if [ -n "$DOMAIN_NAME" ]; then
        echo "- Frontend: https://$DOMAIN_NAME" >> /root/vps-setup-report.txt
        echo "- API: https://$DOMAIN_NAME/api/health" >> /root/vps-setup-report.txt
    else
        echo "- Frontend: http://$SERVER_IP" >> /root/vps-setup-report.txt
        echo "- API: http://$SERVER_IP/api/health" >> /root/vps-setup-report.txt
    fi
    
    cat >> /root/vps-setup-report.txt << EOF

SSH Access:
ssh -p $SSH_PORT $ADMIN_USER@$SERVER_IP

Next Steps:
1. Test SSH connection
2. Run: /usr/local/bin/prepare-docker-manager.sh
3. Install Docker Manager application

Setup completed successfully!
EOF
    
    print_status "Report generated: /root/vps-setup-report.txt"
}

show_completion() {
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    
    echo ""
    echo -e "${GREEN}🎉 VPS Setup Completed Successfully! 🎉${NC}"
    echo ""
    echo -e "${BLUE}Access Information:${NC}"
    
    if [ -n "$DOMAIN_NAME" ]; then
        echo -e "  • Frontend: ${GREEN}https://$DOMAIN_NAME${NC}"
        echo -e "  • API: ${GREEN}https://$DOMAIN_NAME/api/health${NC}"
    else
        echo -e "  • Frontend: ${GREEN}http://$SERVER_IP${NC}"
        echo -e "  • API: ${GREEN}http://$SERVER_IP/api/health${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}SSH Access:${NC}"
    echo -e "  • Command: ${YELLOW}ssh -p $SSH_PORT $ADMIN_USER@$SERVER_IP${NC}"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "  1. Test SSH connection in another terminal"
    echo "  2. Run: /usr/local/bin/prepare-docker-manager.sh"
    echo "  3. Install Docker Manager"
    echo ""
    echo -e "${RED}⚠️ Test SSH connection before closing this session!${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}🛡️ VPS Security Setup for Docker Manager${NC}"
    echo "=========================================="
    
    check_root
    collect_config
    update_system
    configure_system
    create_admin_user
    configure_ssh
    configure_firewall
    configure_fail2ban
    install_docker
    install_nginx
    install_ssl
    create_directories
    create_env_template
    create_utility_scripts
    optimize_system
    restart_services
    generate_report
    show_completion
}

# Run main function
main "$@"
