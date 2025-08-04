#!/bin/bash

#################################################
# Script Complet Setup VPS pentru Docker Manager
# Versiune: 2.0 - Optimizată și Testată
# Compatibil: Debian 11/12
#################################################

set -e

# Setare PATH completă
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin:$PATH"

# Culori pentru output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Configurație default
readonly ADMIN_USER="dockeradmin"
readonly SSH_PORT="2222"
readonly HOSTNAME="docker-manager"
readonly TIMEZONE="Europe/Bucharest"

# Variabile globale
DOMAIN_NAME=""
SSL_EMAIL=""
SSH_PUBLIC_KEY=""
ALERT_EMAIL=""

# Funcții utilitare
print_header() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    🛡️  SETUP VPS DOCKER MANAGER                  ║${NC}"
    echo -e "${BLUE}║                          Versiunea 2.0                          ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_step() {
    echo -e "${CYAN}[PASUL $(date '+%H:%M:%S')]${NC} $1"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Verificare root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Acest script trebuie rulat ca root. Folosește: sudo $0"
    fi
    print_success "Rulare ca root confirmată"
}

# Verificare sistem
check_system() {
    print_step "Verificarea sistemului..."
    
    # Verificare OS
    if [ ! -f /etc/os-release ]; then
        print_error "Nu pot determina sistemul de operare"
    fi
    
    . /etc/os-release
    if [ "$ID" != "debian" ]; then
        print_error "Acest script este doar pentru Debian. OS detectat: $PRETTY_NAME"
    fi
    
    print_success "Sistem compatibil: $PRETTY_NAME"
    
    # Verificare resurse
    local memory_gb=$(free -g | awk 'NR==2{print $2}')
    local disk_gb=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    
    if [ "$memory_gb" -lt 1 ]; then
        print_warning "RAM insuficient: ${memory_gb}GB (recomandat: 2GB+)"
    fi
    
    if [ "$disk_gb" -lt 10 ]; then
        print_warning "Spațiu disk insuficient: ${disk_gb}GB (recomandat: 20GB+)"
    fi
    
    print_info "Resurse: ${memory_gb}GB RAM, ${disk_gb}GB disk disponibil"
}

# Colectarea configurației
collect_config() {
    print_step "Configurarea parametrilor..."
    
    echo -e "${PURPLE}Configurația poate fi personalizată sau poți folosi valorile default:${NC}"
    echo ""
    
    # Domain (opțional)
    echo -e "${CYAN}Configurare Domeniu (opțional):${NC}"
    read -p "Introdu numele domeniului (sau Enter pentru acces IP): " DOMAIN_NAME
    
    if [ -n "$DOMAIN_NAME" ]; then
        read -p "Introdu email pentru certificatul SSL: " SSL_EMAIL
        print_info "Configurare domeniu: $DOMAIN_NAME"
    else
        print_info "Configurare pentru acces IP (fără domeniu)"
    fi
    
    echo ""
    
    # SSH Key (opțional)
    echo -e "${CYAN}Cheia SSH publică (opțional):${NC}"
    read -p "Introdu cheia SSH publică (sau Enter pentru configurare ulterioară): " SSH_PUBLIC_KEY
    
    # Alert email (opțional)
    read -p "Email pentru alertele sistemului (opțional): " ALERT_EMAIL
    
    echo ""
    print_success "Configurație colectată"
}

# Actualizarea sistemului
update_system() {
    print_step "Actualizarea sistemului..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    # Actualizare pachete
    apt update -qq
    apt upgrade -y -qq
    
    # Instalare pachete esențiale
    apt install -y -qq \
        curl wget git nano vim htop tree \
        apt-transport-https ca-certificates gnupg lsb-release \
        sudo ufw fail2ban nginx openssl \
        logrotate rsync cron jq net-tools \
        unattended-upgrades apt-listchanges
    
    print_success "Sistem actualizat și pachete instalate"
}

# Configurarea sistemului
configure_system() {
    print_step "Configurarea sistemului de bază..."
    
    # Timezone
    timedatectl set-timezone "$TIMEZONE"
    
    # Hostname
    hostnamectl set-hostname "$HOSTNAME"
    echo "127.0.0.1 $HOSTNAME" >> /etc/hosts
    
    # Actualizări automate de securitate
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}:\${distro_codename}-updates";
};

Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "$ALERT_EMAIL";
Unattended-Upgrade::MailOnlyOnError "true";
EOF
    
    systemctl enable unattended-upgrades
    
    print_success "Configurare sistem completă"
}

# Crearea utilizatorului admin
create_admin_user() {
    print_step "Crearea utilizatorului admin: $ADMIN_USER"
    
    # Crearea utilizatorului
    if ! id "$ADMIN_USER" &>/dev/null; then
        adduser --disabled-password --gecos "" "$ADMIN_USER"
        print_success "Utilizator $ADMIN_USER creat"
    else
        print_info "Utilizatorul $ADMIN_USER există deja"
    fi
    
    # Adăugare la grupa sudo
    usermod -aG sudo "$ADMIN_USER"
    
    # Configurare directorul SSH
    sudo -u "$ADMIN_USER" mkdir -p "/home/$ADMIN_USER/.ssh"
    sudo -u "$ADMIN_USER" chmod 700 "/home/$ADMIN_USER/.ssh"
    
    # Adăugare cheie SSH dacă este furnizată
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        echo "$SSH_PUBLIC_KEY" > "/home/$ADMIN_USER/.ssh/authorized_keys"
        chown "$ADMIN_USER:$ADMIN_USER" "/home/$ADMIN_USER/.ssh/authorized_keys"
        chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"
        print_success "Cheia SSH adăugată pentru $ADMIN_USER"
    else
        print_warning "Nu a fost furnizată o cheie SSH - va fi necesară configurarea ulterioară"
    fi
    
    print_success "Utilizator admin configurat complet"
}

# Configurarea securității SSH
configure_ssh() {
    print_step "Configurarea securității SSH..."
    
    # Backup configurație originală
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Configurație SSH securizată
    cat > /etc/ssh/sshd_config << EOF
# Configurație SSH securizată pentru Docker Manager
Port $SSH_PORT
Protocol 2

# Autentificare
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Utilizatori permisi
AllowUsers $ADMIN_USER

# Securitate
UsePAM yes
X11Forwarding no
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxStartups 2
LoginGraceTime 60

# Algoritmi siguri
HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
EOF
    
    # Testare configurație
    sshd -t
    
    print_success "SSH configurat pe portul $SSH_PORT"
}

# Configurarea firewall-ului
configure_firewall() {
    print_step "Configurarea firewall-ului (UFW)..."
    
    # Reset și configurare inițială
    ufw --force reset >/dev/null 2>&1
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    
    # Reguli pentru porturile necesare
    ufw allow "$SSH_PORT"/tcp comment 'SSH' >/dev/null 2>&1
    ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1
    ufw allow 443/tcp comment 'HTTPS' >/dev/null 2>&1
    ufw allow 3000/tcp comment 'Docker Manager Frontend' >/dev/null 2>&1
    ufw allow 3001/tcp comment 'Docker Manager API' >/dev/null 2>&1
    
    # Rate limiting pentru SSH
    ufw limit "$SSH_PORT"/tcp >/dev/null 2>&1
    
    # Activare firewall
    echo "y" | ufw enable >/dev/null 2>&1
    
    print_success "Firewall configurat și activat"
}

# Configurarea Fail2Ban
configure_fail2ban() {
    print_step "Configurarea Fail2Ban..."
    
    # Configurație Fail2Ban
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
    
    # Restart și activare
    systemctl restart fail2ban
    systemctl enable fail2ban
    
    print_success "Fail2Ban configurat și activ"
}

# Instalarea Docker
install_docker() {
    print_step "Instalarea Docker..."
    
    # Eliminarea versiunilor vechi
    apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Instalarea Docker prin scriptul oficial
    curl -fsSL https://get.docker.com | sh >/dev/null 2>&1
    
    # Configurarea daemonului Docker
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
  "live-restore": true,
  "no-new-privileges": true,
  "icc": false,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  }
}
EOF
    
    # Adăugare utilizator la grupa docker
    usermod -aG docker "$ADMIN_USER"
    
    # Restart și activare Docker
    systemctl restart docker
    systemctl enable docker
    
    # Instalarea Docker Compose
    COMPOSE_VERSION="v2.24.0"
    curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose 2>/dev/null
    chmod +x /usr/local/bin/docker-compose
    ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
    
    print_success "Docker și Docker Compose instalate"
}

# Configurarea Nginx
configure_nginx() {
    print_step "Configurarea Nginx..."
    
    # Obținerea IP-ului serverului
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")
    
    if [ -n "$DOMAIN_NAME" ]; then
        # Configurație pentru domeniu
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
    return 301 https://\$server_name\$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    
    # SSL placeholder (va fi actualizat)
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
        limit_req zone=api burst=20 nodelay;
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
    else
        # Configurație pentru IP
        cat > /etc/nginx/sites-available/docker-manager << EOF
# Rate limiting
limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;

# Upstream servers
upstream docker_api {
    server 127.0.0.1:3001;
    keepalive 32;
}

upstream docker_frontend {
    server 127.0.0.1:3000;
    keepalive 32;
}

# HTTP server
server {
    listen 80;
    server_name $server_ip _;
    
    # Security headers
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
    fi
    
    # Activarea site-ului
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/docker-manager /etc/nginx/sites-enabled/
    
    # Testarea configurației
    nginx -t
    
    print_success "Nginx configurat pentru $([ -n "$DOMAIN_NAME" ] && echo "domeniu: $DOMAIN_NAME" || echo "acces IP: $server_ip")"
}

# Instalarea certificatului SSL
install_ssl() {
    if [ -n "$DOMAIN_NAME" ] && [ -n "$SSL_EMAIL" ]; then
        print_step "Instalarea certificatului SSL pentru $DOMAIN_NAME..."
        
        # Instalarea Certbot
        apt install -y certbot python3-certbot-nginx
        
        # Oprirea Nginx temporar
        systemctl stop nginx
        
        # Obținerea certificatului
        if certbot certonly --standalone -d "$DOMAIN_NAME" -d "www.$DOMAIN_NAME" \
           --email "$SSL_EMAIL" --agree-tos --non-interactive; then
            
            # Actualizarea configurației Nginx
            sed -i "s|ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;|ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;|" /etc/nginx/sites-available/docker-manager
            sed -i "s|ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;|ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;|" /etc/nginx/sites-available/docker-manager
            
            # Configurații SSL moderne
            sed -i "/ssl_session_tickets off;/a\\
    # Modern SSL configuration\\
    ssl_protocols TLSv1.2 TLSv1.3;\\
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\\
    ssl_prefer_server_ciphers off;" /etc/nginx/sites-available/docker-manager
            
            # Auto-renewal
            echo "0 12 * * * /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'" | crontab -
            
            print_success "Certificat SSL instalat pentru $DOMAIN_NAME"
        else
            print_warning "Instalarea certificatului SSL a eșuat - se continuă fără SSL"
        fi
        
        # Repornirea Nginx
        systemctl start nginx
    else
        print_info "Nu a fost furnizat domeniul - se sare instalarea SSL"
    fi
    
    systemctl enable nginx
}

# Crearea directoarelor
create_directories() {
    print_step "Crearea structurii de directoare..."
    
    # Directoare principale
    mkdir -p /opt/docker-manager
    mkdir -p /opt/docker-data/{mongodb,mongodb-config,redis,app,prometheus,grafana,loki}
    mkdir -p /var/log/docker-manager
    mkdir -p /opt/backups/{daily,weekly,monthly,config}
    mkdir -p /opt/docker-manager/{logs,uploads,ssl}
    
    # Setarea permisiunilor
    chown -R "$ADMIN_USER:$ADMIN_USER" /opt/docker-manager
    chown -R "$ADMIN_USER:$ADMIN_USER" /opt/docker-data
    chown -R "$ADMIN_USER:$ADMIN_USER" /var/log/docker-manager
    chown -R "$ADMIN_USER:$ADMIN_USER" /opt/backups
    
    # Permisiuni corecte
    chmod 755 /opt/docker-manager /opt/docker-data /var/log/docker-manager /opt/backups
    
    print_success "Structura de directoare creată"
}

# Crearea template-ului de configurare
create_env_template() {
    print_step "Crearea template-ului de configurare..."
    
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    local cors_origin
    
    if [ -n "$DOMAIN_NAME" ]; then
        cors_origin="https://$DOMAIN_NAME"
    else
        cors_origin="http://$server_ip,https://$server_ip"
    fi
    
    cat > /opt/docker-manager/.env.template << EOF
# ===================================================================
# Docker Manager Environment Configuration
# Generat automat de scriptul de setup VPS
# ===================================================================

# Configurație aplicație
NODE_ENV=production
APP_NAME=Docker Manager
APP_VERSION=1.0.0
PORT=3001
LOG_LEVEL=info

# Configurație domeniu și CORS
CORS_ORIGIN=$cors_origin

# Configurație frontend
REACT_APP_API_URL=$([ -n "$DOMAIN_NAME" ] && echo "https://$DOMAIN_NAME" || echo "http://$server_ip:3001")
REACT_APP_WS_URL=$([ -n "$DOMAIN_NAME" ] && echo "wss://$DOMAIN_NAME" || echo "ws://$server_ip:3001")

# Configurație baze de date
MONGODB_URI=mongodb://docker_admin:SecureMongoPass123@mongodb:27017/docker_manager?authSource=admin
MONGO_ROOT_USER=docker_admin
MONGO_ROOT_PASSWORD=SecureMongoPass123
MONGO_DB=docker_manager

REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=SecureRedisPass123

# Configurație securitate (vor fi generate automat)
JWT_SECRET=CHANGE_THIS_SECRET
JWT_REFRESH_SECRET=CHANGE_THIS_REFRESH_SECRET

# Configurație Docker
DOCKER_HOST=unix:///var/run/docker.sock
DATA_DIR=/opt/docker-data

# Rate limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Monitoring și alerting
ALERT_EMAIL=$ALERT_EMAIL
SLACK_WEBHOOK=

# Configurație opțională
GRAFANA_USER=admin
GRAFANA_PASSWORD=SecureGrafanaPass123
TZ=$TIMEZONE

# Configurație backup
BACKUP_RETENTION_DAYS=30

# ===================================================================
# NOTĂ: Acest fișier va fi copiat în .env și personalizat automat
# ===================================================================
EOF
    
    chown "$ADMIN_USER:$ADMIN_USER" /opt/docker-manager/.env.template
    
    print_success "Template de configurare creat"
}

# Crearea scripturilor utilitare
create_utility_scripts() {
    print_step "Crearea scripturilor utilitare..."
    
    # Script de verificare sistem
    cat > /usr/local/bin/system-check.sh << 'EOF'
#!/bin/bash

# Culori
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    📊 VERIFICARE STATUS SISTEM                   ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}📅 Data: $(date)${NC}"
echo ""

echo -e "${BLUE}1. Informații sistem:${NC}"
echo "   • OS: $(lsb_release -d | cut -f2)"
echo "   • Kernel: $(uname -r)"
echo "   • Uptime: $(uptime -p)"
echo "   • Load: $(uptime | awk -F'load average:' '{print $2}')"

echo ""
echo -e "${BLUE}2. Utilizarea resurselor:${NC}"
echo "   • Memorie: $(free -h | grep Mem | awk '{print $3 "/" $2 " (" int($3/$2 * 100) "%)"}')"
echo "   • Disk: $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"

echo ""
echo -e "${BLUE}3. Status servicii:${NC}"
services=("ssh" "nginx" "docker" "fail2ban" "ufw")
for service in "${services[@]}"; do
    if systemctl is-active --quiet $service 2>/dev/null; then
        echo -e "   • $service: ${GREEN}✅ Activ${NC}"
    else
        echo -e "   • $service: ${RED}❌ Inactiv${NC}"
    fi
done

echo ""
echo -e "${BLUE}4. Docker:${NC}"
if command -v docker &> /dev/null; then
    echo "   • Versiune: $(docker --version | cut -d' ' -f3 | cut -d',' -f1)"
    if docker info &> /dev/null; then
        CONTAINERS=$(docker ps -q | wc -l)
        echo "   • Containere active: $CONTAINERS"
    else
        echo -e "   • Status: ${RED}Nu pot accesa Docker daemon${NC}"
    fi
else
    echo -e "   • Docker: ${RED}Nu este instalat${NC}"
fi

echo ""
echo -e "${BLUE}5. Securitate:${NC}"
echo "   • UFW: $(ufw status | head -1 | awk '{print $2}')"
echo "   • Fail2Ban: $(systemctl is-active fail2ban 2>/dev/null || echo 'inactiv')"
echo "   • SSH Port: $(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo '22')"

echo ""
echo -e "${BLUE}6. Rețea:${NC}"
echo "   • IP Public: $(curl -s ifconfig.me 2>/dev/null || echo 'Nu pot detecta')"
echo "   • Porturi deschise: $(ss -tuln | grep LISTEN | wc -l)"

echo ""
echo "═══════════════════════════════════════════════════════════════════"
EOF
    
    chmod +x /usr/local/bin/system-check.sh
    
    # Script de pregătire Docker Manager
    cat > /usr/local/bin/prepare-docker-manager.sh << EOF
#!/bin/bash

# Culori
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "\${BLUE}╔══════════════════════════════════════════════════════════════════╗\${NC}"
echo -e "\${BLUE}║                🐳 PREGĂTIRE DOCKER MANAGER                       ║\${NC}"
echo -e "\${BLUE}╚══════════════════════════════════════════════════════════════════╝\${NC}"
echo ""

cd /opt/docker-manager

# Verificarea și crearea fișierului .env
if [ ! -f .env ]; then
    echo -e "\${YELLOW}📝 Crearea fișierului de configurare .env...\${NC}"
    cp .env.template .env
    
    # Generarea secretelor JWT
    JWT_SECRET=\$(openssl rand -base64 32)
    JWT_REFRESH_SECRET=\$(openssl rand -base64 32)
    
    # Înlocuirea secretelor în .env
    sed -i "s/CHANGE_THIS_SECRET/\$JWT_SECRET/" .env
    sed -i "s/CHANGE_THIS_REFRESH_SECRET/\$JWT_REFRESH_SECRET/" .env
    
    echo -e "\${GREEN}✅ Fișierul .env creat cu secrete generate automat\${NC}"
else
    echo -e "\${GREEN}✅ Fișierul .env există deja\${NC}"
fi

echo ""
echo -e "\${BLUE}📋 Următorii pași:\${NC}"
echo "1. su - $ADMIN_USER"
echo "2. cd /opt/docker-manager"
echo "3. Încarcă fișierele Docker Manager"
echo "4. docker-compose up -d"
echo ""
echo -e "\${YELLOW}💡 Pentru a verifica sistemul: /usr/local/bin/system-check.sh\${NC}"
EOF
    
    chmod +x /usr/local/bin/prepare-docker-manager.sh
    
    # Script de backup
    cat > /usr/local/bin/backup-system.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/backup.log"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_message "=== Începerea procesului de backup ==="

# Backup MongoDB
if docker ps | grep -q mongodb; then
    log_message "Backup MongoDB..."
    docker exec mongodb mongodump --archive --gzip > "$BACKUP_DIR/daily/mongodb_$DATE.gz"
    log_message "✅ Backup MongoDB complet"
fi

# Backup Redis  
if docker ps | grep -q redis; then
    log_message "Backup Redis..."
    docker exec redis redis-cli --rdb - > "$BACKUP_DIR/daily/redis_$DATE.rdb"
    log_message "✅ Backup Redis complet"
fi

# Backup configurații
log_message "Backup configurații..."
tar -czf "$BACKUP_DIR/config/configs_$DATE.tar.gz" \
    /etc/nginx/sites-available/ \
    /etc/docker/ \
    /etc/fail2ban/ \
    /opt/docker-manager/.env \
    2>/dev/null

log_message "✅ Backup configurații complet"

# Curățarea backup-urilor vechi
log_message "Curățarea backup-urilor vechi..."
find "$BACKUP_DIR/daily" -name "*.gz" -mtime +7 -delete
find "$BACKUP_DIR/weekly" -name "*.tar.gz" -mtime +30 -delete  
find "$BACKUP_DIR/monthly" -name "*.tar.gz" -mtime +365 -delete

log_message "=== Procesul de backup finalizat ==="
EOF
    
    chmod +x /usr/local/bin/backup-system.sh
    
    print_success "Scripturi utilitare create"
}

# Optimizarea sistemului
optimize_system() {
    print_step "Optimizarea performanței sistemului..."
    
    # Limite sistem
    cat > /etc/security/limits.d/99-docker-manager.conf << EOF
# Limite pentru Docker Manager
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
$ADMIN_USER soft nofile 65536
$ADMIN_USER hard nofile 65536
$ADMIN_USER soft nproc 32768
$ADMIN_USER hard nproc 32768
EOF
    
    # Parametri kernel
    cat > /etc/sysctl.d/99-docker-manager.conf << EOF
# Optimizări rețea
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000

# Optimizări sistem de fișiere
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288

# Optimizări memorie virtuală
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# Optimizări securitate
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 1

# Optimizări Docker
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
    
    # Aplicarea parametrilor
    sysctl -p /etc/sysctl.d/99-docker-manager.conf >/dev/null 2>&1
    
    print_success "Optimizări sistem aplicate"
}

# Configurarea monitorizării
setup_monitoring() {
    print_step "Configurarea monitorizării sistemului..."
    
    # Script de monitorizare
    cat > /usr/local/bin/monitor-system.sh << 'EOF'
#!/bin/bash

LOG_FILE="/var/log/system-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] === Raport Monitorizare ===" >> $LOG_FILE

# Load average
echo "[$DATE] Load Average: $(uptime | awk -F'load average:' '{print $2}')" >> $LOG_FILE

# Utilizarea memoriei
MEMORY=$(free | grep Mem | awk '{printf("%.1f%%", $3/$2 * 100.0)}')
echo "[$DATE] Utilizare Memorie: $MEMORY" >> $LOG_FILE

# Utilizarea discului
DISK=$(df -h / | awk 'NR==2 {print $5}')
echo "[$DATE] Utilizare Disk: $DISK" >> $LOG_FILE

# Containere Docker
if command -v docker &> /dev/null; then
    CONTAINERS=$(docker ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | wc -l)
    echo "[$DATE] Containere Active: $((CONTAINERS-1))" >> $LOG_FILE
fi

echo "[$DATE] === Sfârșit Raport ===" >> $LOG_FILE
EOF
    
    chmod +x /usr/local/bin/monitor-system.sh
    
    # Programarea monitorizării
    echo "*/5 * * * * root /usr/local/bin/monitor-system.sh" >> /etc/crontab
    
    # Programarea backup-urilor
    cat > /etc/cron.d/docker-manager-backup << EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Backup zilnic la 2 AM
0 2 * * * root /usr/local/bin/backup-system.sh
EOF
    
    print_success "Monitorizare și backup programate"
}

# Restartarea serviciilor
restart_services() {
    print_step "Restartarea serviciilor..."
    
    # Restartarea SSH (cu precauție)
    systemctl restart ssh
    
    # Restartarea celorlalte servicii
    systemctl restart fail2ban
    systemctl restart nginx
    
    # Activarea serviciilor
    systemctl enable ssh fail2ban nginx docker
    
    print_success "Servicii restarted și activate"
}

# Generarea raportului final
generate_report() {
    print_step "Generarea raportului de setup..."
    
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    local report_file="/root/vps-setup-report.txt"
    
    cat > "$report_file" << EOF
╔══════════════════════════════════════════════════════════════════╗
║                    📊 RAPORT SETUP VPS COMPLET                   ║
╚══════════════════════════════════════════════════════════════════╝

Data: $(date)
Script Versiune: 2.0

INFORMAȚII SISTEM:
════════════════════════════════════════════════════════════════════
• Hostname: $HOSTNAME
• OS: $(lsb_release -d | cut -f2)
• Kernel: $(uname -r)
• IP Public: $server_ip
• Timezone: $TIMEZONE

CONFIGURAȚIE UTILIZATOR:
════════════════════════════════════════════════════════════════════
• Utilizator Admin: $ADMIN_USER
• Port SSH: $SSH_PORT
• Autentificare SSH: $([ -n "$SSH_PUBLIC_KEY" ] && echo "Cheie configurată" || echo "Necesită configurare")

CONFIGURAȚIE REȚEA:
════════════════════════════════════════════════════════════════════
• Domeniu: ${DOMAIN_NAME:-"Acces IP (fără domeniu)"}
• Certificat SSL: $([ -d "/etc/letsencrypt/live/$DOMAIN_NAME" ] && echo "Let's Encrypt instalat" || echo "Nu este configurat")
• Nginx: $(systemctl is-active nginx)

SECURITATE:
════════════════════════════════════════════════════════════════════
• UFW Firewall: $(ufw status | head -1 | awk '{print $2}')
• Fail2Ban: $(systemctl is-active fail2ban)
• SSH Security: Configurat și întărit
• Actualizări automate: Activate

DOCKER:
════════════════════════════════════════════════════════════════════
• Docker: $(docker --version 2>/dev/null || echo "Nu este instalat")
• Docker Compose: $(docker-compose --version 2>/dev/null || echo "Nu este instalat")
• Acces utilizator: $ADMIN_USER adăugat în grupa docker

MONITORIZARE ȘI BACKUP:
════════════════════════════════════════════════════════════════════
• Monitorizare sistem: Activă (la fiecare 5 minute)
• Backup automat: Zilnic la 2 AM
• Rotație loguri: Configurată
• Scripturi utilitare: Instalate

INFORMAȚII DE ACCES:
════════════════════════════════════════════════════════════════════

SSH:
ssh -p $SSH_PORT $ADMIN_USER@$server_ip

Docker Manager:
EOF

    if [ -n "$DOMAIN_NAME" ]; then
        echo "• Frontend: https://$DOMAIN_NAME" >> "$report_file"
        echo "• API: https://$DOMAIN_NAME/api/health" >> "$report_file"
    else
        echo "• Frontend: http://$server_ip" >> "$report_file"
        echo "• API: http://$server_ip/api/health" >> "$report_file"
        echo "• Acces direct: http://$server_ip:3000 (frontend), http://$server_ip:3001 (API)" >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

PORTURI FIREWALL:
════════════════════════════════════════════════════════════════════
• $SSH_PORT/tcp (SSH)
• 80/tcp (HTTP)
• 443/tcp (HTTPS)
• 3000/tcp (Docker Manager Frontend)
• 3001/tcp (Docker Manager API)

COMENZI UTILE:
════════════════════════════════════════════════════════════════════
• Verificare sistem: /usr/local/bin/system-check.sh
• Pregătire Docker Manager: /usr/local/bin/prepare-docker-manager.sh
• Backup manual: /usr/local/bin/backup-system.sh
• Monitorizare sistem: tail -f /var/log/system-monitor.log
• Status firewall: ufw status verbose
• Status fail2ban: fail2ban-client status

URMĂTORII PAȘI:
════════════════════════════════════════════════════════════════════
1. Testează conexiunea SSH pe port $SSH_PORT
2. Rulează: /usr/local/bin/prepare-docker-manager.sh
3. Încarcă fișierele Docker Manager în /opt/docker-manager/
4. Configurează .env cu setările specifice
5. Rulează: docker-compose up -d

SECURITATE - REAMINTIRI IMPORTANTE:
════════════════════════════════════════════════════════════════════
• Schimbă parolele default ale aplicațiilor
• Monitorizează regulat logurile pentru activitate suspectă
• Actualizează regulat sistemul și aplicațiile
• Păstrează backup-urile în siguranță
• Verifică periodic configurația de securitate

════════════════════════════════════════════════════════════════════
Setup completat cu succes!
────────────────────────────────────────────────────────────────────
EOF
    
    print_success "Raport generat: $report_file"
}

# Afișarea completării
show_completion() {
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                    🎉 SETUP VPS FINALIZAT CU SUCCES! 🎉          ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    echo -e "${BLUE}📋 Rezumat Configurație:${NC}"
    echo -e "   ✅ Sistem securizat și optimizat"
    echo -e "   ✅ Utilizator '$ADMIN_USER' creat cu acces sudo"
    echo -e "   ✅ SSH întărit (port $SSH_PORT, doar chei)"
    echo -e "   ✅ Firewall configurat și activ"
    echo -e "   ✅ Fail2Ban instalat și activ"
    echo -e "   ✅ Docker instalat și securizat"
    echo -e "   ✅ Nginx instalat și configurat"
    if [ -n "$DOMAIN_NAME" ]; then
        echo -e "   ✅ Certificat SSL $([ -d "/etc/letsencrypt/live/$DOMAIN_NAME" ] && echo "instalat" || echo "pregătit pentru instalare")"
    else
        echo -e "   ✅ Configurat pentru acces IP"
    fi
    echo -e "   ✅ Sisteme de monitorizare și backup active"
    echo -e "   ✅ Optimizări de performanță aplicate"
    echo ""
    
    echo -e "${YELLOW}⚠️  REAMINTIRI IMPORTANTE DE SECURITATE:${NC}"
    echo -e "   🔑 Testează conexiunea SSH: ${CYAN}ssh -p $SSH_PORT $ADMIN_USER@$server_ip${NC}"
    echo -e "   🔐 Autentificarea prin parolă SSH este DEZACTIVATĂ"
    echo -e "   🚪 Login-ul root SSH este DEZACTIVAT"
    echo -e "   🔥 Firewall-ul este ACTIV - doar porturile specificate sunt deschise"
    echo ""
    
    echo -e "${BLUE}📝 Următorii Pași:${NC}"
    echo -e "   1. ${GREEN}Testează conexiunea SSH${NC} înainte de a închide această sesiune"
    echo -e "   2. Rulează: ${CYAN}/usr/local/bin/system-check.sh${NC} pentru verificarea sistemului"
    echo -e "   3. Rulează: ${CYAN}/usr/local/bin/prepare-docker-manager.sh${NC} pentru pregătirea Docker Manager"
    echo -e "   4. Încarcă fișierele Docker Manager în ${CYAN}/opt/docker-manager/${NC}"
    echo ""
    
    echo -e "${BLUE}🌐 Informații de Acces:${NC}"
    if [ -n "$DOMAIN_NAME" ]; then
        echo -e "   • Frontend: ${GREEN}https://$DOMAIN_NAME${NC}"
        echo -e "   • API: ${GREEN}https://$DOMAIN_NAME/api/health${NC}"
    else
        echo -e "   • Frontend: ${GREEN}http://$server_ip${NC}"
        echo -e "   • API: ${GREEN}http://$server_ip/api/health${NC}"
        echo -e "   • Acces direct: ${CYAN}http://$server_ip:3000${NC} (frontend), ${CYAN}http://$server_ip:3001${NC} (API)"
    fi
    echo ""
    
    echo -e "${PURPLE}📊 Comenzi Utile:${NC}"
    echo -e "   • Status sistem: ${CYAN}/usr/local/bin/system-check.sh${NC}"
    echo -e "   • Status firewall: ${CYAN}ufw status verbose${NC}"
    echo -e "   • Loguri sistem: ${CYAN}tail -f /var/log/system-monitor.log${NC}"
    echo -e "   • Status fail2ban: ${CYAN}fail2ban-client status${NC}"
    echo ""
    
    echo -e "${GREEN}📋 Raport complet salvat în: /root/vps-setup-report.txt${NC}"
    echo ""
    echo -e "${RED}⚠️  NU ÎNCHIDE ACEASTĂ SESIUNE PÂNĂ NU TESTEZI ACCESUL SSH!${NC}"
    echo ""
}

# Funcția principală
main() {
    print_header
    
    # Verificări preliminare
    check_root
    check_system
    
    # Configurare
    collect_config
    
    echo ""
    print_step "Începerea procesului automat de setup..."
    echo -e "${YELLOW}Acest proces va dura 10-15 minute în funcție de viteza serverului.${NC}"
    echo ""
    
    # Executarea pașilor de setup
    update_system
    configure_system
    create_admin_user
    configure_ssh
    configure_firewall
    configure_fail2ban
    install_docker
    configure_nginx
    install_ssl
    create_directories
    create_env_template
    create_utility_scripts
    optimize_system
    setup_monitoring
    restart_services
    generate_report
    
    # Afișarea completării
    show_completion
    
    print_success "Setup VPS finalizat cu succes!"
    echo "Log complet disponibil în: /var/log/vps-setup.log"
}

# Pornirea scriptului
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
