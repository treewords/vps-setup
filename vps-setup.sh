#!/bin/bash

#################################################
# Quick Fix VPS Setup Script
# Simplified version without syntax errors
#################################################

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo -e "${BLUE}🛡️ Quick VPS Setup for Docker Manager${NC}"
echo "====================================="

# Check root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root: sudo $0"
    exit 1
fi

# Variables
ADMIN_USER="dockeradmin"
SSH_PORT="2222"
HOSTNAME="docker-manager"

print_status "Starting quick VPS setup..."

# Update system
print_status "Updating system..."
apt update && apt upgrade -y
apt install -y curl wget git nano htop ufw fail2ban nginx

# Create admin user
print_status "Creating admin user: $ADMIN_USER"
if ! id "$ADMIN_USER" &>/dev/null; then
    adduser --disabled-password --gecos "" "$ADMIN_USER"
    usermod -aG sudo "$ADMIN_USER"
fi

# Configure firewall
print_status "Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "$SSH_PORT"/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3000/tcp
ufw allow 3001/tcp
ufw --force enable

# Install Docker
print_status "Installing Docker..."
curl -fsSL https://get.docker.com | sh
usermod -aG docker "$ADMIN_USER"

# Install Docker Compose
print_status "Installing Docker Compose..."
DOCKER_COMPOSE_VERSION="v2.24.0"
curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Basic SSH security
print_status "Configuring SSH security..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config << EOF
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
AllowUsers $ADMIN_USER
EOF

# Test SSH config
sshd -t

# Configure fail2ban
print_status "Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

systemctl restart fail2ban
systemctl enable fail2ban

# Create directories
print_status "Creating Docker Manager directories..."
mkdir -p /opt/docker-manager
mkdir -p /opt/docker-data/{mongodb,redis,app}
mkdir -p /var/log/docker-manager
chown -R "$ADMIN_USER:$ADMIN_USER" /opt/docker-manager
chown -R "$ADMIN_USER:$ADMIN_USER" /opt/docker-data
chown -R "$ADMIN_USER:$ADMIN_USER" /var/log/docker-manager

# Create basic nginx config
print_status "Configuring Nginx..."
cat > /etc/nginx/sites-available/docker-manager << 'EOF'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/docker-manager /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
systemctl enable nginx

# Create environment template
print_status "Creating environment template..."
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")

cat > /opt/docker-manager/.env.template << EOF
NODE_ENV=production
PORT=3001
MONGODB_URI=mongodb://mongodb:27017/docker-manager
REDIS_HOST=redis
REDIS_PORT=6379
JWT_SECRET=CHANGE_THIS_SECRET
JWT_REFRESH_SECRET=CHANGE_THIS_REFRESH_SECRET
CORS_ORIGIN=http://$SERVER_IP,https://$SERVER_IP
DOCKER_HOST=unix:///var/run/docker.sock
LOG_LEVEL=info
EOF

chown "$ADMIN_USER:$ADMIN_USER" /opt/docker-manager/.env.template

# Create utility scripts
print_status "Creating utility scripts..."

# System check script
cat > /usr/local/bin/system-check.sh << 'EOF'
#!/bin/bash
echo "=== System Status ==="
echo "Date: $(date)"
echo "OS: $(lsb_release -d | cut -f2)"
echo "Uptime: $(uptime -p)"
echo "Memory: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
echo "Disk: $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"
echo "Docker: $(systemctl is-active docker 2>/dev/null || echo 'inactive')"
echo "Nginx: $(systemctl is-active nginx 2>/dev/null || echo 'inactive')"
echo "UFW: $(ufw status | head -1 | awk '{print $2}')"
echo "===================="
EOF

chmod +x /usr/local/bin/system-check.sh

# Docker Manager preparation script
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
fi
echo "✓ Ready for Docker Manager installation"
echo "Next steps:"
echo "1. su - $ADMIN_USER"
echo "2. cd /opt/docker-manager"
echo "3. Upload your Docker Manager files"
echo "4. docker-compose up -d"
EOF

chmod +x /usr/local/bin/prepare-docker-manager.sh

# Restart SSH
print_status "Restarting SSH service..."
systemctl restart ssh

# Performance optimization
print_status "Applying performance optimizations..."
cat > /etc/sysctl.d/99-docker.conf << EOF
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
vm.swappiness=10
fs.file-max=2097152
EOF

sysctl -p /etc/sysctl.d/99-docker.conf

print_status "🎉 Quick setup completed!"
echo ""
echo -e "${GREEN}✅ System secured and ready for Docker Manager${NC}"
echo ""
echo -e "${BLUE}Important Information:${NC}"
echo -e "• SSH Port: ${YELLOW}$SSH_PORT${NC}"
echo -e "• Admin User: ${YELLOW}$ADMIN_USER${NC}"
echo -e "• Server IP: ${YELLOW}$SERVER_IP${NC}"
echo ""
echo -e "${RED}⚠️ IMPORTANT: Configure SSH keys before closing this session!${NC}"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "1. Add your SSH public key to /home/$ADMIN_USER/.ssh/authorized_keys"
echo "2. Test SSH: ssh -p $SSH_PORT $ADMIN_USER@$SERVER_IP"
echo "3. Run: /usr/local/bin/prepare-docker-manager.sh"
echo "4. Install Docker Manager application"
echo ""
echo -e "${YELLOW}Test connection in another terminal before closing this one!${NC}"
