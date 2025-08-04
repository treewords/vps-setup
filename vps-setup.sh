#!/bin/bash

#################################################
# Automated Debian VPS Security Setup Script
# For Docker Manager Deployment
# Version: 1.0.0
# Author: Docker Manager Team
#################################################

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration variables
SCRIPT_VERSION="1.0.0"
LOG_FILE="/var/log/vps-setup.log"
CONFIG_FILE="/tmp/vps-setup.conf"
ADMIN_USER="dockeradmin"
SSH_PORT="2222"
HOSTNAME="docker-manager-prod"
TIMEZONE="UTC"

# Function to print colored output
print_status() { echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }
print_step() { echo -e "${BLUE}[STEP]${NC} $1" | tee -a "$LOG_FILE"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }

# Function to prompt for user input with default value
prompt_input() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    
    echo -e "${CYAN}$prompt${NC} ${YELLOW}[default: $default]${NC}"
    read -r input
    
    if [ -z "$input" ]; then
        input="$default"
    fi
    
    eval "$var_name='$input'"
}

# Function to generate random password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Function to check if script is running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        echo "Please run: sudo $0"
        exit 1
    fi
}

# Function to check OS compatibility
check_os() {
    print_step "Checking operating system compatibility..."
    
    if [ ! -f /etc/os-release ]; then
        print_error "Cannot determine operating system"
        exit 1
    fi
    
    . /etc/os-release
    
    if [ "$ID" != "debian" ]; then
        print_error "This script is designed for Debian only"
        print_error "Detected OS: $PRETTY_NAME"
        exit 1
    fi
    
    print_success "Debian OS detected: $PRETTY_NAME"
}

# Function to collect configuration
collect_config() {
    print_step "Collecting configuration information..."
    
    echo ""
    echo -e "${PURPLE}=== VPS Setup Configuration ===${NC}"
    echo ""
    
    prompt_input "Enter admin username:" "$ADMIN_USER" "ADMIN_USER"
    prompt_input "Enter SSH port:" "$SSH_PORT" "SSH_PORT"
    prompt_input "Enter hostname:" "$HOSTNAME" "HOSTNAME"
    prompt_input "Enter timezone (e.g., UTC, Europe/London):" "$TIMEZONE" "TIMEZONE"
    
    echo ""
    echo -e "${CYAN}Domain and SSL Configuration:${NC}"
    prompt_input "Enter your domain name (e.g., example.com):" "" "DOMAIN_NAME"
    prompt_input "Enter your email for SSL certificates:" "" "SSL_EMAIL"
    
    echo ""
    echo -e "${CYAN}Security Configuration:${NC}"
    prompt_input "Enter your SSH public key (or press Enter to skip):" "" "SSH_PUBLIC_KEY"
    prompt_input "Enter alert email address:" "" "ALERT_EMAIL"
    prompt_input "Enter Slack webhook URL (optional):" "" "SLACK_WEBHOOK"
    
    # Save configuration
    cat > "$CONFIG_FILE" << EOF
ADMIN_USER="$ADMIN_USER"
SSH_PORT="$SSH_PORT"
HOSTNAME="$HOSTNAME"
TIMEZONE="$TIMEZONE"
DOMAIN_NAME="$DOMAIN_NAME"
SSL_EMAIL="$SSL_EMAIL"
SSH_PUBLIC_KEY="$SSH_PUBLIC_KEY"
ALERT_EMAIL="$ALERT_EMAIL"
SLACK_WEBHOOK="$SLACK_WEBHOOK"
EOF
    
    print_success "Configuration saved"
}

# Function to update system
update_system() {
    print_step "Updating system packages..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    apt update
    apt upgrade -y
    apt install -y curl wget git unzip nano vim htop tree software-properties-common \
        apt-transport-https ca-certificates gnupg lsb-release sudo ufw fail2ban \
        logrotate rsync cron openssl jq net-tools
    
    print_success "System packages updated"
}

# Function to configure timezone and hostname
configure_system() {
    print_step "Configuring system settings..."
    
    # Set timezone
    timedatectl set-timezone "$TIMEZONE"
    print_status "Timezone set to $TIMEZONE"
    
    # Set hostname
    hostnamectl set-hostname "$HOSTNAME"
    echo "127.0.0.1 $HOSTNAME" >> /etc/hosts
    print_status "Hostname set to $HOSTNAME"
    
    print_success "System configuration complete"
}

# Function to create admin user
create_admin_user() {
    print_step "Creating admin user: $ADMIN_USER..."
    
    if id "$ADMIN_USER" &>/dev/null; then
        print_warning "User $ADMIN_USER already exists"
    else
        adduser --disabled-password --gecos "" "$ADMIN_USER"
        print_status "User $ADMIN_USER created"
    fi
    
    # Add to sudo group
    usermod -aG sudo "$ADMIN_USER"
    
    # Configure SSH directory
    sudo -u "$ADMIN_USER" mkdir -p "/home/$ADMIN_USER/.ssh"
    sudo -u "$ADMIN_USER" chmod 700 "/home/$ADMIN_USER/.ssh"
    
    # Add SSH public key if provided
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        echo "$SSH_PUBLIC_KEY" > "/home/$ADMIN_USER/.ssh/authorized_keys"
        chown "$ADMIN_USER:$ADMIN_USER" "/home/$ADMIN_USER/.ssh/authorized_keys"
        chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"
        print_status "SSH public key added for $ADMIN_USER"
    else
        print_warning "No SSH public key provided. You'll need to add it manually."
    fi
    
    print_success "Admin user configuration complete"
}

# Function to configure SSH security
configure_ssh() {
    print_step "Configuring SSH security..."
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Create new SSH config
    cat > /etc/ssh/sshd_config << EOF
# SSH Security Configuration - Generated by VPS Setup Script
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

# Security options
HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
EOF
    
    # Test SSH configuration
    sshd -t
    
    print_success "SSH configuration updated"
    print_warning "SSH will be restarted later. Current connection will remain active."
}

# Function to configure firewall
configure_firewall() {
    print_step "Configuring UFW firewall..."
    
    # Reset UFW
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH on custom port
    ufw allow "$SSH_PORT"/tcp comment 'SSH'
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Allow Docker Manager ports
    ufw allow 3000/tcp comment 'Docker Manager Frontend'
    ufw allow 3001/tcp comment 'Docker Manager API'
    
    # Enable UFW
    ufw --force enable
    
    print_success "UFW firewall configured and enabled"
}

# Function to configure Fail2Ban
configure_fail2ban() {
    print_step "Configuring Fail2Ban..."
    
    # Create local configuration
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    
    # Configure Fail2Ban
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 ::1
backend = auto
action = %(action_mwl)s

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
EOF
    
    # Start and enable Fail2Ban
    systemctl restart fail2ban
    systemctl enable fail2ban
    
    print_success "Fail2Ban configured and started"
}

# Function to install and configure Docker
install_docker() {
    print_step "Installing Docker..."
    
    # Remove old Docker versions
    apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Add Docker GPG key
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Update package cache and install Docker
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
  "no-new-privileges": true,
  "icc": false,
  "live-restore": true,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  },
  "max-concurrent-downloads": 10,
  "max-concurrent-uploads": 5
}
EOF
    
    # Add admin user to docker group
    usermod -aG docker "$ADMIN_USER"
    
    # Start and enable Docker
    systemctl restart docker
    systemctl enable docker
    
    # Install Docker Compose standalone
    DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
    curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
    
    print_success "Docker installation complete"
}

# Function to install and configure Nginx
install_nginx() {
    print_step "Installing and configuring Nginx..."
    
    apt install -y nginx
    
    # Create nginx configuration for Docker Manager
    cat > /etc/nginx/sites-available/docker-manager << EOF
# Rate limiting
limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone \$binary_remote_addr zone=auth:10m rate=5r/s;

# Upstream servers
upstream docker_api {
    server 127.0.0.1:3001;
    keepalive 32;
}

upstream docker_frontend {
    server 127.0.0.1:3000;
    keepalive 32;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    return 301 https://$DOMAIN_NAME\$request_uri;
}

# Main HTTPS server (will be updated after SSL certificate generation)
server {
    listen 443 ssl http2;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;

    # SSL Configuration (placeholder - will be updated)
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    # Logging
    access_log /var/log/nginx/docker-manager.access.log;
    error_log /var/log/nginx/docker-manager.error.log;

    # Frontend
    location / {
        proxy_pass http://docker_frontend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }

    # API endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://docker_api;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://docker_api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    
    # Remove default site and enable docker-manager site
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/docker-manager /etc/nginx/sites-enabled/
    
    # Test nginx configuration
    nginx -t
    
    print_success "Nginx installed and configured"
}

# Function to install SSL certificate
install_ssl() {
    print_step "Installing SSL certificate..."
    
    if [ -z "$DOMAIN_NAME" ] || [ -z "$SSL_EMAIL" ]; then
        print_warning "Domain name or email not provided. Skipping SSL certificate installation."
        print_warning "You can install SSL later using: certbot --nginx -d $DOMAIN_NAME"
        return
    fi
    
    # Install certbot
    apt install -y certbot python3-certbot-nginx
    
    # Stop nginx temporarily
    systemctl stop nginx
    
    # Generate certificate
    certbot certonly --standalone -d "$DOMAIN_NAME" -d "www.$DOMAIN_NAME" \
        --email "$SSL_EMAIL" --agree-tos --non-interactive
    
    if [ $? -eq 0 ]; then
        # Update nginx configuration with real SSL certificate
        sed -i "s|ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;|ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;|" /etc/nginx/sites-available/docker-manager
        sed -i "s|ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;|ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;|" /etc/nginx/sites-available/docker-manager
        
        # Add SSL security configuration
        sed -i "/ssl_session_tickets off;/a\\
    # Modern SSL configuration\\
    ssl_protocols TLSv1.2 TLSv1.3;\\
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\\
    ssl_prefer_server_ciphers off;" /etc/nginx/sites-available/docker-manager
        
        # Setup auto-renewal
        echo "0 12 * * * /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'" | crontab -
        
        print_success "SSL certificate installed and auto-renewal configured"
    else
        print_error "SSL certificate installation failed"
        print_warning "Continuing with self-signed certificate"
    fi
    
    # Start nginx
    systemctl start nginx
    systemctl enable nginx
}

# Function to configure system monitoring
configure_monitoring() {
    print_step "Configuring system monitoring..."
    
    # Install monitoring tools
    apt install -y htop iotop nethogs ncdu
    
    # Create monitoring script
    cat > /usr/local/bin/system-monitor.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/system-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] === System Monitor Report ===" >> $LOG_FILE
echo "[$DATE] Load Average: $(uptime | awk -F'load average:' '{print $2}')" >> $LOG_FILE

MEMORY=$(free | grep Mem | awk '{printf("%.1f%%", $3/$2 * 100.0)}')
echo "[$DATE] Memory Usage: $MEMORY" >> $LOG_FILE

DISK=$(df -h / | awk 'NR==2 {print $5}')
echo "[$DATE] Disk Usage: $DISK" >> $LOG_FILE

if command -v docker &> /dev/null; then
    CONTAINERS=$(docker ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | wc -l)
    echo "[$DATE] Running Containers: $((CONTAINERS-1))" >> $LOG_FILE
fi

echo "[$DATE] === End Report ===" >> $LOG_FILE
EOF
    
    chmod +x /usr/local/bin/system-monitor.sh
    
    # Add to crontab (run every 5 minutes)
    echo "*/5 * * * * root /usr/local/bin/system-monitor.sh" >> /etc/crontab
    
    print_success "System monitoring configured"
}

# Function to configure backup system
configure_backups() {
    print_step "Configuring backup system..."
    
    # Create backup directories
    mkdir -p /opt/backups/{daily,weekly,monthly,config}
    chown -R "$ADMIN_USER:$ADMIN_USER" /opt/backups
    
    # Create backup script
    cat > /usr/local/bin/backup-system.sh << EOF
#!/bin/bash
BACKUP_DIR="/opt/backups"
DATE=\$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/backup.log"

log_message() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" | tee -a "\$LOG_FILE"
}

backup_database() {
    log_message "Starting database backup..."
    if docker ps | grep -q mongodb; then
        docker exec mongodb mongodump --archive --gzip > "\$BACKUP_DIR/daily/mongodb_\$DATE.gz"
        log_message "MongoDB backup completed"
    fi
}

backup_configs() {
    log_message "Starting configuration backup..."
    tar -czf "\$BACKUP_DIR/config/configs_\$DATE.tar.gz" \\
        /etc/nginx/sites-available/ \\
        /etc/docker/ \\
        /etc/fail2ban/ \\
        /etc/ufw/ \\
        2>/dev/null
    log_message "Configuration backup completed"
}

cleanup_backups() {
    log_message "Cleaning up old backups..."
    find "\$BACKUP_DIR/daily" -name "*.gz" -mtime +7 -delete
    find "\$BACKUP_DIR/weekly" -name "*.tar.gz" -mtime +30 -delete
    find "\$BACKUP_DIR/monthly" -name "*.tar.gz" -mtime +365 -delete
    log_message "Backup cleanup completed"
}

log_message "=== Starting backup process ==="
backup_database
backup_configs
cleanup_backups
log_message "=== Backup process completed ==="
EOF
    
    chmod +x /usr/local/bin/backup-system.sh
    
    # Schedule backups
    cat > /etc/cron.d/docker-manager-backup << EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Daily backup at 2 AM
0 2 * * * root /usr/local/bin/backup-system.sh
EOF
    
    print_success "Backup system configured"
}

# Function to optimize system performance
optimize_performance() {
    print_step "Optimizing system performance..."
    
    # Optimize system limits
    cat > /etc/security/limits.d/99-docker-manager.conf << EOF
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
$ADMIN_USER soft nofile 65536
$ADMIN_USER hard nofile 65536
$ADMIN_USER soft nproc 32768
$ADMIN_USER hard nproc 32768
EOF
    
    # Optimize kernel parameters
    cat > /etc/sysctl.d/99-docker-manager.conf << EOF
# Network optimizations
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000

# File system optimizations
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288

# Virtual memory optimizations
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# Security optimizations
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 1

# Docker optimizations
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
    
    # Apply kernel parameters
    sysctl -p /etc/sysctl.d/99-docker-manager.conf
    
    print_success "Performance optimization complete"
}

# Function to create useful scripts
create_utility_scripts() {
    print_step "Creating utility scripts..."
    
    # Create system check script
    cat > /usr/local/bin/system-check.sh << 'EOF'
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== System Status Check ===${NC}"
echo "Date: $(date)"
echo

echo "1. System Information:"
echo "   - OS: $(lsb_release -d | cut -f2)"
echo "   - Kernel: $(uname -r)"
echo "   - Uptime: $(uptime -p)"

echo
echo "2. Resource Usage:"
echo "   - Memory: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
echo "   - Disk: $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 " used)"}')"
echo "   - Load: $(uptime | awk -F'load average:' '{print $2}')"

echo
echo "3. Security Status:"
echo "   - UFW: $(ufw status | head -1 | awk '{print $2}')"
echo "   - Fail2Ban: $(systemctl is-active fail2ban)"
echo "   - SSH: $(systemctl is-active ssh)"

echo
echo "4. Docker Status:"
if command -v docker &> /dev/null; then
    echo "   - Docker: $(systemctl is-active docker)"
    echo "   - Containers: $(docker ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | wc -l | awk '{print $1-1}') running"
else
    echo "   - Docker: Not installed"
fi

echo
echo "5. Nginx Status:"
if command -v nginx &> /dev/null; then
    echo "   - Nginx: $(systemctl is-active nginx)"
else
    echo "   - Nginx: Not installed"
fi

echo
echo "=== Status Check Complete ==="
EOF
    
    chmod +x /usr/local/bin/system-check.sh
    
    # Create Docker Manager preparation script
    cat > /usr/local/bin/prepare-docker-manager.sh << EOF
#!/bin/bash

echo "=== Preparing for Docker Manager Installation ==="

# Create application directory
mkdir -p /opt/docker-manager
chown $ADMIN_USER:$ADMIN_USER /opt/docker-manager

# Create log directories
mkdir -p /var/log/docker-manager
chown $ADMIN_USER:$ADMIN_USER /var/log/docker-manager

# Create data directories
mkdir -p /opt/docker-data/{mongodb,redis,uploads,backups}
chown -R $ADMIN_USER:$ADMIN_USER /opt/docker-data

# Create environment template
cat > /opt/docker-manager/.env.template << 'ENV_EOF'
# Docker Manager Environment Configuration
NODE_ENV=production
PORT=3001

# Database Configuration
MONGODB_URI=mongodb://mongodb:27017/docker-manager
REDIS_HOST=redis
REDIS_PORT=6379

# Security Configuration
JWT_SECRET=\$(openssl rand -base64 32)
JWT_REFRESH_SECRET=\$(openssl rand -base64 32)
CORS_ORIGIN=https://$DOMAIN_NAME

# Application Configuration
DOCKER_HOST=unix:///var/run/docker.sock
LOG_LEVEL=info
ALERT_EMAIL=$ALERT_EMAIL
SLACK_WEBHOOK=$SLACK_WEBHOOK
ENV_EOF

chown $ADMIN_USER:$ADMIN_USER /opt/docker-manager/.env.template

echo "✓ Docker Manager preparation complete"
echo ""
echo "Next steps:"
echo "1. Switch to $ADMIN_USER user: su - $ADMIN_USER"
echo "2. Upload Docker Manager files to /opt/docker-manager/"
echo "3. Copy .env.template to .env and configure"
echo "4. Run docker-compose up -d"
EOF
    
    chmod +x /usr/local/bin/prepare-docker-manager.sh
    
    print_success "Utility scripts created"
}

# Function to configure automatic updates
configure_auto_updates() {
    print_step "Configuring automatic security updates..."
    
    apt install -y unattended-upgrades apt-listchanges
    
    # Configure unattended upgrades
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Package-Blacklist {
    // "docker-ce";
    // "nginx";
};

Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";

Unattended-Upgrade::Mail "$ALERT_EMAIL";
Unattended-Upgrade::MailOnlyOnError "true";

Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
EOF
    
    # Enable automatic updates
    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades
    
    print_success "Automatic security updates configured"
}

# Function to perform final security hardening
final_security_hardening() {
    print_step "Performing final security hardening..."
    
    # Secure shared memory
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    
    # Disable unused network protocols
    cat > /etc/modprobe.d/blacklist-rare-network.conf << EOF
# Disable rare network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
    
    # Set strict file permissions
    chmod 600 /etc/ssh/sshd_config
    chmod 600 /etc/docker/daemon.json
    chmod -R 700 /root
    
    # Configure log rotation
    cat > /etc/logrotate.d/docker-manager << EOF
/var/log/docker-manager/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    copytruncate
    create 644 $ADMIN_USER $ADMIN_USER
}

/var/log/system-monitor.log {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
    
    print_success "Security hardening complete"
}

# Function to restart services
restart_services() {
    print_step "Restarting services..."
    
    # Restart SSH service
    systemctl restart ssh
    print_status "SSH restarted on port $SSH_PORT"
    
    # Restart other services
    systemctl restart fail2ban
    systemctl restart nginx
    
    print_success "All services restarted"
}

# Function to generate final report
generate_report() {
    print_step "Generating setup report..."
    
    local report_file="/root/vps-setup-report.txt"
    
    cat > "$report_file" << EOF
=================================================
VPS Security Setup Report
Generated: $(date)
Script Version: $SCRIPT_VERSION
=================================================

SYSTEM INFORMATION:
- Hostname: $HOSTNAME
- OS: $(lsb_release -d | cut -f2)
- Kernel: $(uname -r)
- IP Address: $(curl -s ifconfig.me 2>/dev/null || echo "Unable to detect")

USER CONFIGURATION:
- Admin User: $ADMIN_USER
- SSH Port: $SSH_PORT
- SSH Key Auth: $([ -n "$SSH_PUBLIC_KEY" ] && echo "Enabled" || echo "Manual setup required")

SECURITY CONFIGURATION:
- UFW Firewall: $(ufw status | head -1 | awk '{print $2}')
- Fail2Ban: $(systemctl is-active fail2ban)
- SSH Security: Enhanced
- Docker Security: Configured

NETWORK CONFIGURATION:
- Domain: ${DOMAIN_NAME:-"Not configured"}
- SSL Certificate: $([ -d "/etc/letsencrypt/live/$DOMAIN_NAME" ] && echo "Installed" || echo "Not installed")
- Nginx: $(systemctl is-active nginx)

DOCKER CONFIGURATION:
- Docker Version: $(docker --version 2>/dev/null || echo "Not installed")
- Docker Compose: $(docker-compose --version 2>/dev/null || echo "Not installed")
- User Access: $ADMIN_USER added to docker group

MONITORING & BACKUP:
- System Monitoring: Enabled (every 5 minutes)
- Automated Backups: Enabled (daily at 2 AM)
- Log Rotation: Configured
- Auto Updates: Enabled

IMPORTANT INFORMATION:
=================================================

SSH ACCESS:
To connect to your server, use:
ssh -p $SSH_PORT $ADMIN_USER@$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")

FIREWALL PORTS:
- $SSH_PORT/tcp (SSH)
- 80/tcp (HTTP)
- 443/tcp (HTTPS)
- 3000/tcp (Docker Manager Frontend)
- 3001/tcp (Docker Manager API)

USEFUL COMMANDS:
- Check system status: /usr/local/bin/system-check.sh
- Prepare for Docker Manager: /usr/local/bin/prepare-docker-manager.sh
- Monitor system: tail -f /var/log/system-monitor.log
- View firewall status: ufw status verbose
- Check fail2ban status: fail2ban-client status

NEXT STEPS:
=================================================
1. Test SSH connection on port $SSH_PORT
2. If using domain: verify DNS points to this server
3. Run: /usr/local/bin/prepare-docker-manager.sh
4. Upload and install Docker Manager application
5. Configure SSL certificate if not done automatically

SECURITY REMINDERS:
=================================================
- Change default passwords for any applications
- Regularly update the system
- Monitor logs for suspicious activity
- Keep Docker images updated
- Backup your data regularly

LOG FILES:
=================================================
- Setup log: $LOG_FILE
- System monitor: /var/log/system-monitor.log
- SSH logs: /var/log/auth.log
- Nginx logs: /var/log/nginx/
- Fail2ban logs: /var/log/fail2ban.log

=================================================
Setup completed successfully!
=================================================
EOF
    
    print_success "Setup report generated: $report_file"
}

# Function to cleanup temporary files
cleanup() {
    print_step "Cleaning up temporary files..."
    
    rm -f "$CONFIG_FILE"
    apt autoremove -y
    apt autoclean
    
    print_success "Cleanup complete"
}

# Function to show completion message
show_completion() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                     🎉 VPS SETUP COMPLETED SUCCESSFULLY! 🎉                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}📋 Setup Summary:${NC}"
    echo -e "   ✅ System updated and secured"
    echo -e "   ✅ User '$ADMIN_USER' created with sudo access"
    echo -e "   ✅ SSH hardened (port $SSH_PORT, key-only auth)"
    echo -e "   ✅ Firewall configured and enabled"
    echo -e "   ✅ Fail2Ban installed and active"
    echo -e "   ✅ Docker installed and secured"
    echo -e "   ✅ Nginx installed and configured"
    echo -e "   ✅ SSL certificate $([ -d "/etc/letsencrypt/live/$DOMAIN_NAME" ] && echo "installed" || echo "ready for installation")"
    echo -e "   ✅ Monitoring and backup systems active"
    echo -e "   ✅ Performance optimizations applied"
    echo ""
    echo -e "${YELLOW}⚠️  IMPORTANT SECURITY REMINDERS:${NC}"
    echo -e "   🔑 Test SSH connection: ${CYAN}ssh -p $SSH_PORT $ADMIN_USER@$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")${NC}"
    echo -e "   🔐 SSH password authentication is DISABLED"
    echo -e "   🚪 Root SSH login is DISABLED"
    echo -e "   🔥 Firewall is ACTIVE - only specified ports are open"
    echo ""
    echo -e "${BLUE}📝 Next Steps:${NC}"
    echo -e "   1. ${GREEN}Test SSH connection${NC} before closing this session"
    echo -e "   2. Run: ${CYAN}/usr/local/bin/system-check.sh${NC} to verify system status"
    echo -e "   3. Run: ${CYAN}/usr/local/bin/prepare-docker-manager.sh${NC} to prepare for Docker Manager"
    echo -e "   4. Upload your Docker Manager files to ${CYAN}/opt/docker-manager/${NC}"
    echo ""
    echo -e "${PURPLE}📊 Useful Commands:${NC}"
    echo -e "   • System status: ${CYAN}/usr/local/bin/system-check.sh${NC}"
    echo -e "   • Firewall status: ${CYAN}ufw status verbose${NC}"
    echo -e "   • View logs: ${CYAN}tail -f /var/log/system-monitor.log${NC}"
    echo -e "   • Fail2ban status: ${CYAN}fail2ban-client status${NC}"
    echo ""
    echo -e "${GREEN}📋 Full setup report saved to: /root/vps-setup-report.txt${NC}"
    echo ""
    echo -e "${RED}⚠️  DO NOT CLOSE THIS SESSION UNTIL YOU'VE TESTED SSH ACCESS!${NC}"
    echo ""
}

# Main execution function
main() {
    clear
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    🛡️  AUTOMATED VPS SECURITY SETUP  🛡️                      ║"
    echo "║                                                                              ║"
    echo "║                     Debian VPS Security Configuration                       ║"
    echo "║                     For Docker Manager Deployment                           ║"
    echo "║                                                                              ║"
    echo "║                            Version: $SCRIPT_VERSION                                ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    # Initialize log file
    echo "VPS Setup Started: $(date)" > "$LOG_FILE"
    
    print_status "Starting VPS security setup..."
    
    # Pre-flight checks
    check_root
    check_os
    
    # Configuration
    collect_config
    
    echo ""
    print_step "Starting automated setup process..."
    echo -e "${YELLOW}This process will take 10-15 minutes depending on your server speed.${NC}"
    echo ""
    
    # Execute setup steps
    update_system
    configure_system
    create_admin_user
    configure_ssh
    configure_firewall
    configure_fail2ban
    install_docker
    install_nginx
    install_ssl
    configure_monitoring
    configure_backups
    optimize_performance
    configure_auto_updates
    create_utility_scripts
    final_security_hardening
    restart_services
    generate_report
    cleanup
    
    # Show completion
    show_completion
    
    print_success "VPS setup completed successfully!"
    echo "Setup log saved to: $LOG_FILE"
}

# Script execution starts here
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}:\${distro_codename}-updates";
};

Unattended-Upgrade