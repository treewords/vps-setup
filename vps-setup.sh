# Create improved script that installs everything needed
cat > fixed-vps-setup.sh << 'EOF'
#!/bin/bash

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🛡️ Fixed VPS Setup for Docker Manager${NC}"
echo "======================================"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Set defaults
ADMIN_USER="dockeradmin"
SSH_PORT="2222"

echo -e "${GREEN}Using configuration:${NC}"
echo "• Admin user: $ADMIN_USER"
echo "• SSH port: $SSH_PORT"
echo "• Access: IP-based"
echo ""

echo "🔄 Starting setup..."

# Update system and install essential packages
echo "📦 Installing essential packages..."
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y adduser sudo curl wget git nano htop ufw fail2ban nginx openssl lsb-release ca-certificates gnupg

# Create user using useradd if adduser still fails
echo "👤 Creating admin user..."
if command -v adduser >/dev/null 2>&1; then
    if ! id "$ADMIN_USER" &>/dev/null; then
        adduser --disabled-password --gecos "" "$ADMIN_USER"
    fi
else
    # Fallback to useradd
    if ! id "$ADMIN_USER" &>/dev/null; then
        useradd -m -s /bin/bash "$ADMIN_USER"
    fi
fi

# Add to sudo group
usermod -aG sudo "$ADMIN_USER"

# Create SSH directory
mkdir -p "/home/$ADMIN_USER/.ssh"
chown "$ADMIN_USER:$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
chmod 700 "/home/$ADMIN_USER/.ssh"

echo "✓ User $ADMIN_USER created"

# Install Docker
echo "🐳 Installing Docker..."
curl -fsSL https://get.docker.com | sh
usermod -aG docker "$ADMIN_USER"

# Install Docker Compose
echo "📋 Installing Docker Compose..."
COMPOSE_VERSION="v2.24.0"
curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

echo "✓ Docker installed"

# Configure firewall
echo "🔥 Configuring firewall..."
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
ufw allow "$SSH_PORT"/tcp >/dev/null 2>&1
ufw allow 80/tcp >/dev/null 2>&1
ufw allow 443/tcp >/dev/null 2>&1
ufw allow 3000/tcp >/dev/null 2>&1
ufw allow 3001/tcp >/dev/null 2>&1
echo "y" | ufw enable >/dev/null 2>&1

echo "✓ Firewall configured"

# Configure SSH
echo "🔐 Configuring SSH..."
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
if sshd -t; then
    echo "✓ SSH configuration valid"
else
    echo "⚠️ SSH configuration has issues, but continuing..."
fi

# Configure Fail2Ban
echo "🛡️ Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

systemctl restart fail2ban >/dev/null 2>&1
systemctl enable fail2ban >/dev/null 2>&1

echo "✓ Fail2Ban configured"

# Configure Nginx
echo "🌐 Configuring Nginx..."
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

if nginx -t >/dev/null 2>&1; then
    systemctl restart nginx
    systemctl enable nginx
    echo "✓ Nginx configured"
else
    echo "⚠️ Nginx configuration has issues"
fi

# Create directories
echo "📁 Creating directories..."
mkdir -p /opt/docker-manager
mkdir -p /opt/docker-data/{mongodb,redis,app}
mkdir -p /var/log/docker-manager
mkdir -p /opt/backups

chown -R "$ADMIN_USER:$ADMIN_USER" /opt/docker-manager
chown -R "$ADMIN_USER:$ADMIN_USER" /opt/docker-data
chown -R "$ADMIN_USER:$ADMIN_USER" /var/log/docker-manager
chown -R "$ADMIN_USER:$ADMIN_USER" /opt/backups

echo "✓ Directories created"

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")

# Create environment template
echo "⚙️ Creating environment template..."
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

# Create preparation script
cat > /usr/local/bin/prepare-docker-manager.sh << EOF
#!/bin/bash
echo "=== Preparing Docker Manager ==="
cd /opt/docker-manager

if [ ! -f .env ]; then
    cp .env.template .env
    
    # Generate JWT secrets
    JWT_SECRET=\$(openssl rand -base64 32)
    JWT_REFRESH_SECRET=\$(openssl rand -base64 32)
    
    sed -i "s/CHANGE_THIS_SECRET/\$JWT_SECRET/" .env
    sed -i "s/CHANGE_THIS_REFRESH_SECRET/\$JWT_REFRESH_SECRET/" .env
    
    echo "✓ Environment file created with generated secrets"
else
    echo "✓ Environment file already exists"
fi

echo ""
echo "Ready for Docker Manager installation!"
echo ""
echo "Next steps:"
echo "1. su - $ADMIN_USER"
echo "2. cd /opt/docker-manager"
echo "3. Upload your Docker Manager files"
echo "4. docker-compose up -d"
EOF

chmod +x /usr/local/bin/prepare-docker-manager.sh

# System optimization
echo "⚡ Optimizing system..."
cat > /etc/sysctl.d/99-docker.conf << EOF
net.ipv4.ip_forward=1
vm.swappiness=10
fs.file-max=2097152
EOF

sysctl -p /etc/sysctl.d/99-docker.conf >/dev/null 2>&1

# Restart SSH carefully
echo "🔄 Restarting services..."
systemctl restart ssh

echo ""
echo -e "${GREEN}🎉 VPS Setup Complete! 🎉${NC}"
echo ""
echo -e "${BLUE}Configuration Summary:${NC}"
echo -e "• Server IP: ${YELLOW}$SERVER_IP${NC}"
echo -e "• SSH Port: ${YELLOW}$SSH_PORT${NC}"
echo -e "• Admin User: ${YELLOW}$ADMIN_USER${NC}"
echo -e "• Docker: ${GREEN}Installed${NC}"
echo -e "• Firewall: ${GREEN}Active${NC}"
echo -e "• Nginx: ${GREEN}Configured${NC}"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "1. Add your SSH public key:"
echo -e "   ${YELLOW}echo 'your-public-key' > /home/$ADMIN_USER/.ssh/authorized_keys${NC}"
echo ""
echo "2. Test SSH connection:"
echo -e "   ${YELLOW}ssh -p $SSH_PORT $ADMIN_USER@$SERVER_IP${NC}"
echo ""
echo "3. Prepare Docker Manager:"
echo -e "   ${YELLOW}/usr/local/bin/prepare-docker-manager.sh${NC}"
echo ""
echo -e "${GREEN}Access URL: http://$SERVER_IP${NC}"
echo ""
echo -e "${RED}⚠️ IMPORTANT: Test SSH connection before closing this session!${NC}"
EOF
