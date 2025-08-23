#!/bin/bash

#################################################
# Script Complet Setup VPS pentru Docker Manager
# Versiune: 3.0 - Revizuit și Îmbunătățit
# Compatibil: Debian 11/12
# Autor: Docker Manager Setup
# Data: 2025
#################################################

# Oprește scriptul la orice eroare neprinsă
set -e

# Setează un PATH de bază pentru a asigura disponibilitatea comenzilor esențiale
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin:$PATH"

# --- Variabile Globale și Constante ---

# Culori pentru output-ul in consolă, pentru o lizibilitate mai bună
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Constante de configurare pentru mediul de bază
readonly ADMIN_USER="dockeradmin"
readonly SSH_PORT="2222"
readonly HOSTNAME="docker-manager"
readonly TIMEZONE="Europe/Bucharest"
readonly LOG_FILE="/var/log/vps-setup.log"

# Variabile ce vor fi populate de utilizator în timpul execuției
DOMAIN_NAME=""
SSL_EMAIL=""
SSH_PUBLIC_KEY=""
ALERT_EMAIL=""
ADMIN_PASSWORD=""

# --- Funcții Utilitare pentru Logging și Output ---

#
# Afișează un header principal pentru script.
#
print_header() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              🛡️  SETUP VPS DOCKER MANAGER v3.0                   ║${NC}"
    echo -e "${BLUE}║                Instalare Completă și Securizată                  ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

#
# Afișează și înregistrează în log un mesaj ce indică un nou pas de instalare.
# Argumente:
#   $1 - Mesajul de afișat.
#
print_step() {
    local message="[PASUL $(date '+%H:%M:%S')] $1"
    echo -e "${CYAN}${message}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${message}" >> "$LOG_FILE"
}

#
# Afișează și înregistrează în log un mesaj de succes.
# Argumente:
#   $1 - Mesajul de succes.
#
print_success() {
    local message="✅ $1"
    echo -e "${GREEN}${message}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - SUCCESS: $1" >> "$LOG_FILE"
}

#
# Afișează și înregistrează în log un mesaj de avertisment.
# Argumente:
#   $1 - Mesajul de avertisment.
#
print_warning() {
    local message="⚠️  $1"
    echo -e "${YELLOW}${message}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - WARNING: $1" >> "$LOG_FILE"
}

#
# Afișează și înregistrează în log un mesaj de eroare, apoi oprește scriptul.
# Argumente:
#   $1 - Mesajul de eroare.
#
print_error() {
    local message="❌ $1"
    echo -e "${RED}${message}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $1" >> "$LOG_FILE"
    exit 1
}

#
# Afișează și înregistrează în log un mesaj informativ.
# Argumente:
#   $1 - Mesajul informativ.
#
print_info() {
    local message="ℹ️  $1"
    echo -e "${BLUE}${message}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO: $1" >> "$LOG_FILE"
}

#
# Generează o parolă aleatorie, sigură.
# Utilizează OpenSSL pentru a genera date aleatorii, apoi le filtrează
# pentru a elimina caracterele ce pot cauza probleme în fișiere de configurare.
#
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# --- Funcții de Verificare Inițială ---

#
# Verifică dacă scriptul este rulat cu privilegii de root (UID 0).
# Oprește execuția dacă nu este root.
#
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Acest script trebuie rulat ca root. Folosește: sudo $0"
    fi
    print_success "Rulare ca root confirmată"
}

#
# Verifică compatibilitatea sistemului de operare și resursele hardware.
# Se asigură că rulează pe Debian 11+ și avertizează dacă resursele sunt scăzute.
#
check_system() {
    print_step "Verificarea sistemului..."
    if [ ! -f /etc/os-release ]; then
        print_error "Nu pot determina sistemul de operare"
    fi

    # Încarcă variabilele din /etc/os-release (ex: ID, PRETTY_NAME)
    . /etc/os-release

    if [ "$ID" != "debian" ]; then
        print_error "Acest script este doar pentru Debian. OS detectat: $PRETTY_NAME"
    fi
    print_success "Sistem compatibil: $PRETTY_NAME"

    local debian_version=$(cat /etc/debian_version | cut -d. -f1)
    if [ "$debian_version" -lt 11 ]; then
        print_error "Versiune Debian prea veche. Minim necesar: Debian 11"
    fi

    # Verifică resursele sistemului (RAM și Disk)
    local memory_mb=$(free -m | awk 'NR==2{print $2}')
    local disk_gb=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')

    if [ "$memory_mb" -lt 1024 ]; then
        print_warning "RAM insuficient: ${memory_mb}MB (recomandat: 2GB+)"
    fi
    if [ "$disk_gb" -lt 10 ]; then
        print_warning "Spațiu disk insuficient: ${disk_gb}GB (recomandat: 20GB+)"
    fi
    print_info "Resurse: ${memory_mb}MB RAM, ${disk_gb}GB disk disponibil"
}

# --- Colectare Date de la Utilizator ---

#
# Colectează interactiv datele de configurare de la utilizator.
# Parolă, cheie SSH, domeniu, email, etc.
# Setează variabilele globale corespunzătoare.
#
collect_config() {
    print_step "Configurarea parametrilor..."
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                      CONFIGURARE INIȚIALĂ                        ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Colectează parola pentru utilizatorul admin
    while true; do
        echo -e "${CYAN}1. Parolă pentru utilizatorul $ADMIN_USER:${NC}"
        echo -e "${YELLOW}   ⚠️  IMPORTANT: Salvează această parolă într-un loc sigur!${NC}"
        read -s -p "   Introdu o parolă puternică: " ADMIN_PASSWORD
        echo
        read -s -p "   Confirmă parola: " ADMIN_PASSWORD_CONFIRM
        echo
        if [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ]; then
            if [ ${#ADMIN_PASSWORD} -ge 8 ]; then
                print_success "Parolă setată"
                break
            else
                print_warning "Parola trebuie să aibă minim 8 caractere"
            fi
        else
            print_warning "Parolele nu se potrivesc"
        fi
    done

    echo ""
    echo -e "${CYAN}2. Cheia SSH publică (foarte recomandat pentru securitate):${NC}"
    echo -e "${YELLOW}   Exemplu: ssh-rsa AAAAB3NzaC1... user@computer${NC}"
    read -p "   Introdu cheia SSH publică (sau Enter pentru a sări): " SSH_PUBLIC_KEY
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        print_success "Cheie SSH salvată"
    else
        print_warning "Nu ai furnizat o cheie SSH - vei folosi doar parola pentru autentificare"
    fi

    echo ""
    echo -e "${CYAN}3. Configurare Domeniu (opțional):${NC}"
    read -p "   Numele domeniului (ex: docker.example.com sau Enter pentru IP): " DOMAIN_NAME
    if [ -n "$DOMAIN_NAME" ]; then
        # Validare simplă a formatului domeniului
        if [[ "$DOMAIN_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
            read -p "   Email pentru certificatul SSL: " SSL_EMAIL
            # Validare simplă a formatului email-ului
            if [[ "$SSL_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                print_success "Domeniu configurat: $DOMAIN_NAME"
            else
                print_warning "Email invalid - SSL nu va fi configurat automat"
                SSL_EMAIL=""
            fi
        else
            print_warning "Format domeniu invalid - se va folosi acces prin IP"
            DOMAIN_NAME=""
        fi
    else
        print_info "Se va configura pentru acces prin IP"
    fi

    echo ""
    echo -e "${CYAN}4. Email pentru alerte sistem (opțional):${NC}"
    read -p "   Email pentru notificări: " ALERT_EMAIL
    if [ -n "$ALERT_EMAIL" ]; then
        print_success "Email alerte: $ALERT_EMAIL"
    fi

    echo ""
    print_success "Configurație completă!"
    echo ""

    # Afișează un sumar al configurării și cere confirmarea finală
    echo -e "${YELLOW}Verifică configurația:${NC}"
    echo "• Utilizator admin: $ADMIN_USER"
    echo "• Port SSH: $SSH_PORT"
    echo "• Autentificare SSH: $([ -n "$SSH_PUBLIC_KEY" ] && echo "Cheie + Parolă" || echo "Doar parolă")"
    echo "• Domeniu: ${DOMAIN_NAME:-"Acces prin IP"}"
    echo "• SSL: $([ -n "$SSL_EMAIL" ] && echo "Let's Encrypt" || echo "Nu")"
    echo ""
    read -p "Continuăm cu instalarea? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_error "Instalare anulată"
    fi
}

# --- Funcții de Configurare a Sistemului ---

#
# Actualizează pachetele sistemului și instalează dependențele necesare.
# Se ocupă de deblocarea managerului de pachete apt și instalează o listă
# predefinită de pachete esențiale și utilitare.
#
update_system() {
    print_step "Actualizarea sistemului..."
    # Înlătură posibile lock-uri apt care pot bloca instalarea
    rm -f /var/lib/apt/lists/lock
    rm -f /var/cache/apt/archives/lock
    rm -f /var/lib/dpkg/lock*
    dpkg --configure -a

    # Rulează apt update, cu o reîncercare în caz de eșec
    apt update -qq || {
        print_warning "Prima încercare de update a eșuat, reîncerc..."
        sleep 2
        apt update
    }
    apt upgrade -y -qq

    # Lista de pachete necesare pentru server
    local packages=(
        curl wget git nano vim htop tree
        apt-transport-https ca-certificates gnupg lsb-release
        ufw fail2ban nginx openssl
        logrotate rsync cron jq net-tools dnsutils
        unattended-upgrades apt-listchanges mailutils
        software-properties-common iptables-persistent
    )
    local critical_packages=("ufw" "fail2ban" "nginx")

    # Instalează fiecare pachet, cu tratare specială pentru cele critice
    for package in "${packages[@]}"; do
        print_info "Instalare $package..."
        if ! apt install -y -qq "$package"; then
            if [[ " ${critical_packages[*]} " =~ " ${package} " ]]; then
                print_error "Nu am putut instala pachetul critic: $package. Verifică logurile apt."
            else
                print_warning "Nu am putut instala pachetul: $package"
            fi
        fi
    done
    print_success "Sistem actualizat și pachete instalate"
}

#
# Configurează setările de bază ale sistemului.
# Include timezone, hostname, fișier swap și actualizări automate (unattended-upgrades).
#
configure_system() {
    print_step "Configurarea sistemului de bază..."

    # Setează fusul orar
    timedatectl set-timezone "$TIMEZONE"
    print_success "Timezone setat: $TIMEZONE"

    # Setează hostname-ul sistemului
    hostnamectl set-hostname "$HOSTNAME"
    grep -q "$HOSTNAME" /etc/hosts || echo "127.0.0.1 $HOSTNAME" >> /etc/hosts
    print_success "Hostname setat: $HOSTNAME"

    # Creează și activează un fișier swap dacă nu există
    if [ ! -f /swapfile ]; then
        print_info "Creez fișier swap de 2G..."
        fallocate -l 2G /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        print_success "Swap creat și activat"
    fi

    # Configurează actualizările automate de securitate
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}:\${distro_codename}-updates";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "${ALERT_EMAIL:-root}";
Unattended-Upgrade::MailOnlyOnError "true";
EOF
    echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades
    systemctl enable unattended-upgrades
    print_success "Actualizări automate configurate"
}

#
# Creează și configurează utilizatorul de administrare.
# Setează parola, adaugă utilizatorul la grupul sudo, configurează accesul sudo fără parolă
# și adaugă cheia SSH publică (dacă a fost furnizată).
#
create_admin_user() {
    print_step "Crearea utilizatorului admin: $ADMIN_USER"

    # Creează utilizatorul dacă nu există, altfel se asigură că este în grupul sudo
    if ! id "$ADMIN_USER" &>/dev/null; then
        useradd -m -s /bin/bash -G sudo "$ADMIN_USER"
        print_success "Utilizator $ADMIN_USER creat"
    else
        print_info "Utilizatorul $ADMIN_USER există deja"
        usermod -aG sudo "$ADMIN_USER"
    fi

    # Setează parola pentru utilizator
    echo "$ADMIN_USER:$ADMIN_PASSWORD" | chpasswd
    print_success "Parolă setată pentru $ADMIN_USER"

    # Configurează acces sudo fără parolă pentru acest utilizator
    echo "$ADMIN_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$ADMIN_USER
    chmod 0440 /etc/sudoers.d/$ADMIN_USER
    print_success "Acces sudo configurat"

    # Creează directorul .ssh și adaugă cheia publică
    local ssh_dir="/home/$ADMIN_USER/.ssh"
    runuser -u "$ADMIN_USER" -- mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        echo "$SSH_PUBLIC_KEY" > "$ssh_dir/authorized_keys"
        chown "$ADMIN_USER:$ADMIN_USER" "$ssh_dir/authorized_keys"
        chmod 600 "$ssh_dir/authorized_keys"
        print_success "Cheia SSH adăugată pentru $ADMIN_USER"
    fi

    # Creează un director de lucru pentru utilizator
    runuser -u "$ADMIN_USER" -- mkdir -p "/home/$ADMIN_USER/docker-manager"
    print_success "Utilizator admin configurat complet"
}
# ==================== CONFIGURARE SSH ======================
#
# Aplică o configurație SSH securizată.
# Schimbă portul, dezactivează login-ul ca root, permite doar anumiți utilizatori,
# și impune algoritmi criptografici moderni.
#
configure_ssh() {
    print_step "Configurarea securității SSH..."
    # Creează un backup al configurației SSH originale
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

    # Generează o nouă configurație sshd_config securizată
    cat > /etc/ssh/sshd_config << EOF
# Port custom pentru a reduce atacurile automate
Port $SSH_PORT
Protocol 2
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# Chei host
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Logging
SyslogFacility AUTH
LogLevel INFO

# Autentificare
LoginGraceTime 60
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 10
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes # Menținută ca backup
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Restricționare acces
AllowUsers $ADMIN_USER

# Dezactivare funcționalități periculoase
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitUserEnvironment no

# Mesaje și keep-alive
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2
MaxStartups 10:30:60
Banner none

# SFTP
Subsystem sftp /usr/lib/openssh/sftp-server

# Algoritmi moderni și siguri
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
EOF

    # Testează validitatea noii configurații înainte de a o aplica
    if sshd -t; then
        print_success "Configurație SSH validă"
    else
        print_error "Configurație SSH invalidă - verifică logurile"
    fi

    # Regenerează cheile host ale serverului pentru securitate sporită
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
    ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N ""
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    print_success "SSH configurat pe portul $SSH_PORT"
}

# ================== FIREWALL (UFW) ===========================
#
# Configurează firewall-ul UFW (Uncomplicated Firewall).
# Resetează regulile, setează politici default (deny incoming), și permite
# traficul doar pe porturile necesare (SSH, HTTP, HTTPS, și porturile aplicației).
#
configure_firewall() {
    print_step "Configurarea firewall-ului (UFW)..."
    ufw --force disable >/dev/null 2>&1
    echo "y" | ufw --force reset >/dev/null 2>&1

    # Setează politicile de bază: blochează tot ce intră, permite tot ce iese
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    ufw default deny routed >/dev/null 2>&1

    # Permite traficul pe porturile esențiale
    ufw allow "$SSH_PORT"/tcp comment 'SSH' >/dev/null 2>&1
    ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1
    ufw allow 443/tcp comment 'HTTPS' >/dev/null 2>&1
    ufw allow 3000/tcp comment 'Docker Manager Frontend' >/dev/null 2>&1
    ufw allow 3001/tcp comment 'Docker Manager API' >/dev/null 2>&1

    # Limitează numărul de încercări de conectare SSH pentru a preveni atacurile brute-force
    ufw limit "$SSH_PORT"/tcp comment 'SSH rate limit' >/dev/null 2>&1

    ufw logging on >/dev/null 2>&1
    echo "y" | ufw enable >/dev/null 2>&1

    if ufw status | grep -q "Status: active"; then
        print_success "Firewall UFW configurat și activat"
    else
        print_error "Firewall UFW nu a putut fi activat"
    fi
}

# ================== FAIL2BAN ===========================
#
# Configurează Fail2Ban pentru a bloca adresele IP care încearcă atacuri.
# Creează o configurație locală (jail.local) cu reguli pentru SSH, Nginx,
# și definește filtre custom pentru a detecta activități malițioase (scanări, bad bots).
#
configure_fail2ban() {
    print_step "Configurarea Fail2Ban..."
    # Creează fișierul de configurare local pentru a suprascrie setările default
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = ${ALERT_EMAIL:-root@localhost}
sendername = Fail2Ban
mta = sendmail
action = %(action_mwl)s
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
bantime = 600
findtime = 60

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 5
bantime = 600

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2
bantime = 3600
EOF

    # Filtru pentru a bloca tentativele de a accesa scripturi vulnerabile (ex: .php)
    cat > /etc/fail2ban/filter.d/nginx-noscript.conf << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*\.(php|asp|exe|pl|cgi|scgi)
ignoreregex =
EOF

    # Filtru pentru a bloca boți cunoscuți ca fiind malițioși sau nedoriți
    cat > /etc/fail2ban/filter.d/nginx-badbots.conf << 'EOF'
[Definition]
badbots = Googlebot|bingbot|Baiduspider|yandexbot|facebookexternalhit|twitterbot|rogerbot|linkedinbot|embedly|quora link preview|showyoubot|outbrain|pinterest|slackbot|vkShare|W3C_Validator|whatsapp|Mediatoolkitbot|ahrefsbot|semrushbot|dotbot|mj12bot|seznambot|blexbot|ezooms|majestic12|spbot|seokicks|smtbot|scrapbot|g00g1e|addthis|blekkobot|magpie-crawler|grapeshotcrawler|livelapbot|trendictionbot|baiduspider|dataprovider|mixrankbot|simplecrawler|cliqzbot
failregex = ^<HOST> -.*"(GET|POST|HEAD).*HTTP.*".*(?:%(badbots)s).*"$
ignoreregex =
EOF

    systemctl stop fail2ban >/dev/null 2>&1
    systemctl start fail2ban
    systemctl enable fail2ban

    if systemctl is-active --quiet fail2ban; then
        print_success "Fail2Ban configurat și activ"
        print_info "Jails active: $(fail2ban-client status | grep "Jail list" | cut -d: -f2)"
    else
        print_error "Fail2Ban nu a pornit corect"
    fi
}

# ============= DOCKER & GRUPUL DOCKER ADMIN ===============
#
# Instalează și configurează Docker și Docker Compose.
# Adaugă repository-ul oficial Docker, instalează pachetele, și configurează
# daemon-ul Docker cu setări de logging, stocare și securitate.
#
install_docker() {
    print_step "Instalarea Docker..."
    # Curăță versiuni vechi de Docker, dacă există
    for pkg in docker docker-engine docker.io containerd runc; do
        apt remove -y $pkg 2>/dev/null || true
    done

    # Adaugă cheia GPG și repository-ul oficial Docker
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    # Creează fișierul de configurare pentru daemon-ul Docker
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "default-address-pools": [
    {
      "base": "172.17.0.0/16",
      "size": 24
    }
  ],
  "userland-proxy": false,
  "live-restore": true,
  "no-new-privileges": true,
  "experimental": false,
  "icc": false,
  "selinux-enabled": false,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  }
}
EOF

    # Adaugă utilizatorul admin la grupul docker pentru a-i permite să ruleze comenzi docker
    usermod -aG docker "$ADMIN_USER"
    systemctl restart docker
    systemctl enable docker

    if docker --version >/dev/null 2>&1; then
        print_success "Docker instalat: $(docker --version)"
    else
        print_error "Docker nu a fost instalat corect"
    fi
    if docker compose version >/dev/null 2>&1; then
        print_success "Docker Compose instalat: $(docker compose version)"
    else
        print_warning "Docker Compose nu este disponibil"
    fi
}
# ===================== NGINX ============================
#
# Configurează Nginx ca reverse proxy pentru aplicația Docker Manager.
# Generează o configurație principală (nginx.conf) și o configurație de site
# specifică, adaptată pentru acces prin domeniu (HTTPS) sau direct prin IP (HTTP).
#
configure_nginx() {
    print_step "Configurarea Nginx..."
    # Detectează IP-ul public al serverului
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")

    # Creează o configurație Nginx globală, optimizată și securizată
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;

events {
    worker_connections 1024;
    multi_accept on;
    use epoll;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off; # Nu afișa versiunea Nginx
    client_max_body_size 100M;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Setări SSL/TLS
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    access_log /var/log/nginx/access.log;

    # Compresie Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml application/atom+xml image/svg+xml;

    # Headers de securitate
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Zone pentru rate limiting
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=3r/s;
    limit_conn_zone $binary_remote_addr zone=addr:10m;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    # Generează configurația de site în funcție de prezența unui domeniu
    if [ -n "$DOMAIN_NAME" ]; then
        # Configurație pentru domeniu, cu redirect de la HTTP la HTTPS
        cat > /etc/nginx/sites-available/docker-manager << EOF
# Upstreams pentru serviciile backend și frontend
upstream docker_api {
    server 127.0.0.1:3001 max_fails=3 fail_timeout=30s;
    keepalive 32;
}
upstream docker_frontend {
    server 127.0.0.1:3000 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

# Server block pentru HTTP, redirecționează către HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    # Locație pentru validarea Certbot
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# Server block pentru HTTPS
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;

    # Certificat SSL (inițial self-signed, apoi înlocuit de Certbot)
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;

    # Optimizări SSL
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Headers de securitate pentru HTTPS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

    access_log /var/log/nginx/docker-manager.access.log;
    error_log /var/log/nginx/docker-manager.error.log;

    # Aplică rate limiting
    limit_req zone=general burst=20 nodelay;
    limit_conn addr 10;

    # Reverse proxy pentru frontend
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
        proxy_read_timeout 90s;
    }

    # Reverse proxy pentru API
    location /api/ {
        limit_req zone=api burst=50 nodelay;
        proxy_pass http://docker_api;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300;
        # Setări CORS
        add_header Access-Control-Allow-Origin \$http_origin always;
        add_header Access-Control-Allow-Methods 'GET, POST, PUT, DELETE, OPTIONS' always;
        add_header Access-Control-Allow-Headers 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        add_header Access-Control-Expose-Headers 'Content-Length,Content-Range' always;
    }

    # Reverse proxy pentru WebSockets
    location /ws {
        proxy_pass http://docker_api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400; # Timeout lung pentru conexiuni persistente
    }

    # Endpoint pentru health checks
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF
    else
        # Configurație Nginx pentru acces direct prin IP (doar HTTP)
        cat > /etc/nginx/sites-available/docker-manager << EOF
upstream docker_api {
    server 127.0.0.1:3001 max_fails=3 fail_timeout=30s;
    keepalive 32;
}
upstream docker_frontend {
    server 127.0.0.1:3000 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $server_ip _;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    access_log /var/log/nginx/docker-manager.access.log;
    error_log /var/log/nginx/docker-manager.error.log;

    limit_req zone=general burst=20 nodelay;
    limit_conn addr 10;

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
        proxy_read_timeout 90s;
    }

    location /api/ {
        limit_req zone=api burst=50 nodelay;
        proxy_pass http://docker_api;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300;
    }

    location /ws {
        proxy_pass http://docker_api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }

    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF
    fi

    # Generează un certificat self-signed temporar dacă s-a configurat un domeniu.
    # Acest certificat va fi folosit de Nginx până când Certbot îl înlocuiește.
    if [ -n "$DOMAIN_NAME" ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/nginx-selfsigned.key \
            -out /etc/ssl/certs/nginx-selfsigned.crt \
            -subj "/C=RO/ST=Romania/L=Bucharest/O=Docker Manager/CN=$DOMAIN_NAME" \
            2>/dev/null
    fi

    # Activează noul site și dezactivează site-ul default
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/docker-manager /etc/nginx/sites-enabled/

    # Creează directorul pentru validarea Certbot
    mkdir -p /var/www/certbot
    chown www-data:www-data /var/www/certbot

    # Verifică sintaxa configurației Nginx
    if nginx -t 2>/dev/null; then
        print_success "Nginx configurat corect"
    else
        print_error "Eroare în configurația Nginx"
        nginx -t
    fi
}

# ============= SSL Let's Encrypt (Certbot) ==================
#
# Instalează un certificat SSL gratuit de la Let's Encrypt folosind Certbot.
# Se execută doar dacă un domeniu și un email au fost furnizate.
# Configurează reînnoirea automată a certificatului.
#
install_ssl() {
    if [ -n "$DOMAIN_NAME" ] && [ -n "$SSL_EMAIL" ]; then
        print_step "Instalarea certificatului SSL Let's Encrypt..."
        apt install -y certbot python3-certbot-nginx || print_error "Instalarea Certbot a eșuat. Verifică logurile apt."
        systemctl start nginx

        # Obține certificatul de la Let's Encrypt
        certbot certonly --nginx \
            -d "$DOMAIN_NAME" \
            -d "www.$DOMAIN_NAME" \
            --email "$SSL_EMAIL" \
            --agree-tos \
            --non-interactive \
            --redirect \
            --staple-ocsp \
            --must-staple

        # Dacă certificatul a fost obținut cu succes, actualizează configurația Nginx
        if [ -d "/etc/letsencrypt/live/$DOMAIN_NAME" ]; then
            sed -i "s|ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;|ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;|" \
                /etc/nginx/sites-available/docker-manager
            sed -i "s|ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;|ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;|" \
                /etc/nginx/sites-available/docker-manager

            # Generează parametrii Diffie-Hellman pentru o securitate sporită
            openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048 2>/dev/null

            # Adaugă un cron job pentru reînnoirea automată a certificatului
            echo "0 0,12 * * * root certbot renew --quiet --post-hook 'systemctl reload nginx'" >> /etc/crontab
            print_success "Certificat SSL instalat pentru $DOMAIN_NAME"
        else
            print_warning "Nu s-a putut obține certificatul SSL - continuăm cu self-signed"
        fi
    else
        print_info "SSL nu este configurat - folosim HTTP"
    fi
    systemctl restart nginx
    systemctl enable nginx
}

# ============= DIRECTOARE APLICAȚIE =============
#
# Creează structura de directoare necesară pentru aplicație, date și backup-uri.
# Asigură permisiunile corecte pentru utilizatorul admin.
#
create_directories() {
    print_step "Crearea structurii de directoare..."
    local dirs=(
        "/opt/docker-manager"
        "/opt/docker-manager/data"
        "/opt/docker-manager/logs"
        "/opt/docker-manager/backups"
        "/opt/docker-manager/configs"
        "/opt/docker-manager/ssl"
        "/opt/docker-data/mongodb"
        "/opt/docker-data/mongodb-config"
        "/opt/docker-data/redis"
        "/opt/docker-data/prometheus"
        "/opt/docker-data/grafana"
        "/opt/docker-data/loki"
        "/var/log/docker-manager"
        "/opt/backups/daily"
        "/opt/backups/weekly"
        "/opt/backups/monthly"
    )
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        chown "$ADMIN_USER:$ADMIN_USER" "$dir"
    done
    # Creează un link simbolic pentru acces facil din home-ul utilizatorului
    ln -sf /opt/docker-manager "/home/$ADMIN_USER/docker-manager"
    print_success "Structura de directoare creată"
}
# ================== CONFIG FILES & DOCKER-COMPOSE ======================
#
# Creează fișierele de configurare inițiale pentru Docker Manager.
# Generează docker-compose.yml, un .env.template cu valori pre-completate,
# și un script init.sh pentru a facilita pornirea aplicației.
#
create_config_files() {
    print_step "Crearea fișierelor de configurare..."
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")

    # Generează fișierul docker-compose.yml
    cat > /opt/docker-manager/docker-compose.yml << EOF
version: '3.8'

services:
  mongodb:
    image: mongo:7.0
    container_name: docker_manager_mongodb
    restart: unless-stopped
    environment:
      MONGO_INITDB_ROOT_USERNAME: \${MONGO_ROOT_USER}
      MONGO_INITDB_ROOT_PASSWORD: \${MONGO_ROOT_PASSWORD}
      MONGO_INITDB_DATABASE: \${MONGO_DB}
    volumes:
      - /opt/docker-data/mongodb:/data/db
      - /opt/docker-data/mongodb-config:/data/configdb
    networks:
      - docker_manager_network
    healthcheck:
      test: ["CMD", "mongosh", "--eval", "db.adminCommand('ping')"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    container_name: docker_manager_redis
    restart: unless-stopped
    command: redis-server --requirepass \${REDIS_PASSWORD}
    volumes:
      - /opt/docker-data/redis:/data
    networks:
      - docker_manager_network
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  backend:
    image: docker-manager-backend:latest # Se așteaptă ca această imagine să fie construită manual
    container_name: docker_manager_backend
    restart: unless-stopped
    ports:
      - "3001:3001"
    environment:
      - NODE_ENV=production
      - PORT=3001
      - MONGODB_URI=\${MONGODB_URI}
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - REDIS_PASSWORD=\${REDIS_PASSWORD}
      - JWT_SECRET=\${JWT_SECRET}
      - JWT_REFRESH_SECRET=\${JWT_REFRESH_SECRET}
      - CORS_ORIGIN=\${CORS_ORIGIN}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro # Acces la Docker socket
      - /opt/docker-manager/logs:/app/logs
      - /opt/docker-manager/uploads:/app/uploads
    networks:
      - docker_manager_network
    depends_on:
      - mongodb
      - redis
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:3001/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  frontend:
    image: docker-manager-frontend:latest # Se așteaptă ca această imagine să fie construită manual
    container_name: docker_manager_frontend
    restart: unless-stopped
    ports:
      - "3000:80"
    environment:
      - REACT_APP_API_URL=\${REACT_APP_API_URL}
      - REACT_APP_WS_URL=\${REACT_APP_WS_URL}
    networks:
      - docker_manager_network
    depends_on:
      - backend
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:80"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  docker_manager_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
EOF

    # Generează un template pentru fișierul .env
    cat > /opt/docker-manager/.env.template << EOF
# --- Environment variables for Docker Manager ---

# General
NODE_ENV=production
APP_NAME=Docker Manager
APP_VERSION=1.0.0
PORT=3001
LOG_LEVEL=info
TZ=$TIMEZONE

# API & Frontend URLs
CORS_ORIGIN=$([ -n "$DOMAIN_NAME" ] && echo "https://$DOMAIN_NAME,https://www.$DOMAIN_NAME" || echo "http://$server_ip")
REACT_APP_API_URL=$([ -n "$DOMAIN_NAME" ] && echo "https://$DOMAIN_NAME/api" || echo "http://$server_ip/api")
REACT_APP_WS_URL=$([ -n "$DOMAIN_NAME" ] && echo "wss://$DOMAIN_NAME/ws" || echo "ws://$server_ip/ws")

# Database (MongoDB)
MONGO_ROOT_USER=docker_admin
MONGO_ROOT_PASSWORD=$(generate_password)
MONGO_DB=docker_manager
MONGODB_URI=mongodb://\${MONGO_ROOT_USER}:\${MONGO_ROOT_PASSWORD}@mongodb:27017/\${MONGO_DB}?authSource=admin

# Cache (Redis)
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=$(generate_password)

# Security (JWT)
JWT_SECRET=$(generate_password)
JWT_REFRESH_SECRET=$(generate_password)

# Docker
DOCKER_HOST=unix:///var/run/docker.sock
DATA_DIR=/opt/docker-data

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Notifications
ALERT_EMAIL=${ALERT_EMAIL:-root@localhost}
SLACK_WEBHOOK=
EOF

    # Creează un script de inițializare pentru utilizator
    cat > /opt/docker-manager/init.sh << 'EOF'
#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    🐳 DOCKER MANAGER SETUP                       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creez fișierul .env din template...${NC}"
    cp .env.template .env
    echo -e "${GREEN}✅ Fișier .env creat. Editează-l dacă este necesar.${NC}"
else
    echo -e "${GREEN}✅ Fișier .env există${NC}"
fi
echo ""
echo -e "${BLUE}Pași următori:${NC}"
echo "1. Încarcă codul sursă al aplicației (backend, frontend)"
echo "2. Construiește imaginile: docker compose build"
echo "3. Pornește serviciile: docker compose up -d"
echo "4. Verifică status: docker compose ps"
echo ""
EOF

    chmod +x /opt/docker-manager/init.sh
    chown -R "$ADMIN_USER:$ADMIN_USER" /opt/docker-manager
    print_success "Fișiere de configurare create"
}

# ========== SCRIPTURI MANAGEMENT/UTILITARE (backup, restore, monitor etc.) =============
#
# Creează o serie de scripturi utilitare în /usr/local/bin pentru a facilita
# administrarea serverului: system-check, docker-backup, docker-restore, etc.
#
create_management_scripts() {
    print_step "Crearea scripturilor de management..."

    # Script pentru o verificare rapidă a stării sistemului
    cat > /usr/local/bin/system-check << 'EOF'
#!/bin/bash
#
# system-check: Afișează un raport sumar despre starea sistemului.
#
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
echo "   • Hostname: $(hostname)"
echo "   • OS: $(lsb_release -d | cut -f2)"
echo "   • Kernel: $(uname -r)"
echo "   • Uptime: $(uptime -p)"
echo "   • Load: $(uptime | awk -F'load average:' '{print $2}')"
echo ""
echo -e "${BLUE}2. Utilizarea resurselor:${NC}"
echo "   • CPU: $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}')"
echo "   • Memorie: $(free -h | grep Mem | awk '{print $3 "/" $2 " (" int($3/$2 * 100) "%)"}')"
echo "   • Swap: $(free -h | grep Swap | awk '{print $3 "/" $2}')"
echo "   • Disk /: $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"
echo "   • Disk /opt: $(df -h /opt 2>/dev/null | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}' || echo 'N/A')"
echo ""
echo -e "${BLUE}3. Status servicii critice:${NC}"
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
    if docker info &> /dev/null 2>&1; then
        CONTAINERS_RUNNING=$(docker ps -q | wc -l)
        CONTAINERS_TOTAL=$(docker ps -aq | wc -l)
        IMAGES=$(docker images -q | wc -l)
        echo "   • Containere: $CONTAINERS_RUNNING active din $CONTAINERS_TOTAL total"
        echo "   • Imagini: $IMAGES"
        if docker ps | grep -q docker_manager; then
            echo -e "   • Docker Manager: ${GREEN}✅ Activ${NC}"
        else
            echo -e "   • Docker Manager: ${YELLOW}⚠️  Nu rulează${NC}"
        fi
    else
        echo -e "   • Status: ${RED}Docker daemon nu este accesibil${NC}"
    fi
else
    echo -e "   • Docker: ${RED}Nu este instalat${NC}"
fi
echo ""
echo -e "${BLUE}5. Securitate:${NC}"
if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
    echo -e "   • UFW Firewall: ${GREEN}✅ Activ${NC}"
    RULES=$(sudo ufw status numbered | grep -c "^\[" || echo "0")
    echo "     └─ Reguli active: $RULES"
else
    echo -e "   • UFW Firewall: ${RED}❌ Inactiv${NC}"
fi
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    echo -e "   • Fail2Ban: ${GREEN}✅ Activ${NC}"
    if command -v fail2ban-client &> /dev/null; then
        JAILS=$(sudo fail2ban-client status | grep "Jail list" | cut -d: -f2 | tr -d ' \t' | tr ',' ' ' | wc -w || echo "0")
        echo "     └─ Jails active: $JAILS"
    fi
else
    echo -e "   • Fail2Ban: ${RED}❌ Inactiv${NC}"
fi
SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
echo "   • SSH Port: $SSH_PORT"
echo "   • SSH Root Login: $(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}' || echo "yes")"
echo ""
echo -e "${BLUE}6. Rețea:${NC}"
echo "   • IP Public: $(curl -s ifconfig.me 2>/dev/null || echo 'Nu pot detecta')"
echo "   • Hostname: $(hostname -f)"
echo "   • DNS: $(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}')"
echo "   • Porturi ascultate:"
sudo ss -tlnp | grep LISTEN | awk '{print "     └─ " $4}' | head -10
echo ""
echo -e "${BLUE}7. Actualizări sistem:${NC}"
if command -v apt &> /dev/null; then
    UPDATES=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")
    echo "   • Pachete de actualizat: $UPDATES"
fi
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo -e "${GREEN}Verificare completă!${NC}"
echo ""
echo -e "${YELLOW}Comenzi utile:${NC}"
echo "• Logs sistem: journalctl -xe"
echo "• Logs Docker: docker logs <container>"
echo "• Monitorizare live: htop"
echo "• Verificare porturi: sudo ss -tlnp"
echo ""
EOF
    chmod +x /usr/local/bin/system-check

    # Script pentru backup-ul aplicației (bază de date și volume)
    cat > /usr/local/bin/docker-backup << 'EOF'
#!/bin/bash
set -eo pipefail
#
# docker-backup: Creează un backup complet al aplicației Docker Manager.
# Include dump-ul bazei de date MongoDB și arhivarea volumelor de date și a fișierelor de configurare.
#
# --- Configurare ---
APP_DIR="/opt/docker-manager"
BACKUP_BASE_DIR="/opt/backups/daily"
RETENTION_DAYS=7
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
BACKUP_NAME="docker-manager-backup-${TIMESTAMP}"
BACKUP_DIR="${BACKUP_BASE_DIR}/${BACKUP_NAME}"
FINAL_ARCHIVE_PATH="${BACKUP_BASE_DIR}/${BACKUP_NAME}.tar.gz"
LOG_FILE="/var/log/docker-backup.log"

# --- Funcții ---
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }

cleanup_on_error() {
    log "❌ A apărut o eroare. Anulez operațiunea."
    [ -d "$BACKUP_DIR" ] && rm -rf "$BACKUP_DIR" && log "🗑️  Director temporar șters."
    cd "$APP_DIR" && docker compose start >/dev/null 2>&1
    log "🚀 Serviciile (posibil oprite) au fost repornite."
    exit 1
}
trap cleanup_on_error ERR

log "--- 🚀 Început backup Docker Manager ---"

# Verificări
if [ "$EUID" -ne 0 ]; then log "❌ Root necesar."; exit 1; fi
if ! command -v docker &>/dev/null || ! docker compose version &>/dev/null; then log "❌ Docker/Compose lipsește."; exit 1; fi
if [ ! -d "$APP_DIR" ]; then log "❌ $APP_DIR nu există."; exit 1; fi
if [ ! -f "$APP_DIR/.env" ]; then log "❌ $APP_DIR/.env lipsește."; exit 1; fi
export $(grep -v '^#' "$APP_DIR/.env" | xargs)

mkdir -p "$BACKUP_DIR"
log "📂 Creat director de backup: $BACKUP_DIR"
cd "$APP_DIR"

MONGO_CONTAINER=$(docker compose ps -q mongodb)
[ -z "$MONGO_CONTAINER" ] && log "❌ Container MongoDB nu a fost găsit." && exit 1

log "🛑 Opresc serviciile dependente de DB pentru a asigura consistența datelor..."
docker compose stop backend frontend

log "📦 Fac backup la baza de date MongoDB..."
docker exec "$MONGO_CONTAINER" mongodump --archive --gzip --db=docker_manager --username="${MONGO_ROOT_USER}" --password="${MONGO_ROOT_PASSWORD}" --authenticationDatabase=admin > "${BACKUP_DIR}/mongodb_dump.gz"

log "🚀 Repornesc serviciile oprite..."
docker compose start backend frontend

log "📦 Arhivez volumele de date (/opt/docker-data)..."
tar -czf "${BACKUP_DIR}/docker-data.tar.gz" -C /opt/docker-data .

log "📦 Arhivez fișierele de configurare (.env, docker-compose.yml)..."
tar -czf "${BACKUP_DIR}/config-files.tar.gz" -C "$APP_DIR" .env docker-compose.yml

log "💯 Arhivă finală creată: ${FINAL_ARCHIVE_PATH}"
tar -czf "${FINAL_ARCHIVE_PATH}" -C "${BACKUP_DIR}" .

rm -rf "${BACKUP_DIR}" # Păstrăm doar arhiva finală

log "🧹 Curăț backup-urile mai vechi de $RETENTION_DAYS zile..."
find "$BACKUP_BASE_DIR" -type f -name "*.tar.gz" -mtime +$RETENTION_DAYS -exec log "🗑️  Șterg: {}" \; -exec rm -f {} \;
log "✅ Curățare finalizată."

log "--- 🎉 Backup Docker Manager finalizat cu succes ---"
exit 0
EOF
    chmod +x /usr/local/bin/docker-backup

    # Script pentru restaurarea unui backup
    cat > /usr/local/bin/docker-restore << 'EOF'
#!/bin/bash
set -eo pipefail
#
# docker-restore: Restaurează aplicația dintr-un fișier de backup.
# ATENȚIE: Această operațiune este distructivă și va suprascrie datele curente.
# Utilizare: docker-restore /cale/catre/backup.tar.gz
#
# --- Configurare ---
APP_DIR="/opt/docker-manager"
DATA_DIR="/opt/docker-data"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"; }

if [ "$EUID" -ne 0 ]; then log "❌ Root necesar."; exit 1; fi
if [ -z "$1" ]; then log "❌ Utilizare: $0 /cale/catre/backup.tar.gz"; exit 1; fi
BACKUP_FILE="$1"
if [ ! -f "$BACKUP_FILE" ]; then log "❌ Fișierul $BACKUP_FILE nu există."; exit 1; fi

log "⚠️  ATENȚIE! Această operațiune va suprascrie datele și configurațiile curente."
read -p "Ești sigur că vrei să continui? (y/n): " -n 1 -r; echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then log "🚫 Operațiune anulată."; exit 0; fi

cd "$APP_DIR"
log "🛑 Opresc toate serviciile..."
docker compose down --remove-orphans

log "🧹 Șterg datele vechi..."
rm -rf "${DATA_DIR}"/*
mkdir -p "$DATA_DIR"

TEMP_DIR=$(mktemp -d)
log "📦 Extrag backup-ul în: $TEMP_DIR"
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"

if [ -f "${TEMP_DIR}/config-files.tar.gz" ]; then
    log "📦 Restaurez fișierele de configurare..."
    tar -xzf "${TEMP_DIR}/config-files.tar.gz" -C "$APP_DIR"
else
    log "⚠️  Nu am găsit arhiva de configurare în backup."
fi

export $(grep -v '^#' "$APP_DIR/.env" | xargs)

if [ -f "${TEMP_DIR}/docker-data.tar.gz" ]; then
    log "📦 Restaurez volumele de date..."
    tar -xzf "${TEMP_DIR}/docker-data.tar.gz" -C "$DATA_DIR"
else
    log "❌ Nu am găsit arhiva cu volumele de date."; rm -rf "$TEMP_DIR"; exit 1
fi

log "🚀 Pornesc baza de date pentru restaurare..."
docker compose up -d mongodb redis
MONGO_CONTAINER=$(docker compose ps -q mongodb)
log "ℹ️  Aștept ca MongoDB să fie gata (15s)..."
sleep 15

if [ -f "${TEMP_DIR}/mongodb_dump.gz" ]; then
    log "📦 Restaurez baza de date MongoDB..."
    cat "${TEMP_DIR}/mongodb_dump.gz" | docker exec -i "$MONGO_CONTAINER" mongorestore --archive --gzip --username="${MONGO_ROOT_USER}" --password="${MONGO_ROOT_PASSWORD}" --authenticationDatabase=admin --drop
else
    log "❌ Nu am găsit dump-ul bazei de date."; rm -rf "$TEMP_DIR"; exit 1
fi

log "🚀 Pornesc toate serviciile..."
docker compose up -d

log "🧹 Curăț fișierele temporare..."
rm -rf "$TEMP_DIR"

log "--- 🎉 Restaurare finalizată cu succes! ---"
exit 0
EOF
    chmod +x /usr/local/bin/docker-restore

    # Script pentru monitorizarea live a containerelor Docker
    cat > /usr/local/bin/docker-monitor << 'EOF'
#!/bin/bash
#
# docker-monitor: Wrapper pentru 'docker stats' pentru a afișa un monitor live
# al containerelor din proiectul Docker Manager.
#
APP_DIR="/opt/docker-manager"
if [ ! -d "$APP_DIR" ]; then echo "❌ $APP_DIR nu există."; exit 1; fi
cd "$APP_DIR"
PROJECT_NAME=$(docker compose ls --format '{{.Name}}' | head -n 1)
if [ -z "$PROJECT_NAME" ]; then echo "❌ Nu am putut găsi proiectul Docker Compose."; exit 1; fi
echo "📊 Monitorizare live pentru proiectul '$PROJECT_NAME' (Ctrl+C pentru a ieși)..."
docker stats $(docker ps --filter "label=com.docker.compose.project=${PROJECT_NAME}" -q)
EOF
    chmod +x /usr/local/bin/docker-monitor

    # Script pentru a trimite notificări pe email
    cat > /usr/local/bin/notify-admin << 'EOF'
#!/bin/bash
#
# notify-admin: Trimite o notificare pe email-ul de admin.
# Utilizare: notify-admin "Subiect" "Corp mesaj"
#
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"; }
if [ "$#" -ne 2 ]; then echo "Utilizare: $0 \"Subiect\" \"Corp mesaj\""; exit 1; fi
SUBJECT="$1"
BODY="$2"
ENV_FILE="/opt/docker-manager/.env"
ADMIN_EMAIL="root@localhost"
if [ -f "$ENV_FILE" ]; then
    ADMIN_EMAIL_TMP=$(grep "^ALERT_EMAIL=" "$ENV_FILE" | cut -d'=' -f2)
    if [ -n "$ADMIN_EMAIL_TMP" ]; then
      ADMIN_EMAIL="$ADMIN_EMAIL_TMP"
    fi
fi
echo "$BODY" | mail -s "$SUBJECT" "$ADMIN_EMAIL"
log "📧 Notificare trimisă către $ADMIN_EMAIL"
EOF
    chmod +x /usr/local/bin/notify-admin

    print_success "Scripturi de management create"
}

# ============= CRON & OPTIMIZARE ==================
#
# Configurează task-uri programate (cron jobs) pentru mentenanță automată.
# Include backup-uri zilnice, monitorizare și curățare de log-uri.
#
setup_cron_jobs() {
    print_step "Configurarea task-urilor programate..."

    # Cron job pentru backup zilnic
    cat > /etc/cron.d/docker-manager-backup << EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# Backup zilnic la 2 AM
0 2 * * * root /usr/local/bin/docker-backup >> /var/log/docker-backup.log 2>&1
EOF

    # Cron job pentru monitorizare (exemplu, poate fi dezactivat/modificat)
    cat > /etc/cron.d/system-monitor << EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# Verificare sistem la fiecare 5 minute (pentru logging, poate fi zgomotos)
*/5 * * * * root /usr/local/bin/system-check --silent >> /var/log/system-monitor.log 2>&1
EOF

    # Cron job pentru curățarea log-urilor vechi
    cat > /etc/cron.d/log-cleanup << EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# Curățare loguri vechi zilnic la 3 AM
0 3 * * * root find /var/log -name "*.log" -mtime +30 -exec gzip {} \; 2>/dev/null
0 3 * * * root find /var/log -name "*.gz" -mtime +90 -delete 2>/dev/null
0 3 * * * root find /opt/docker-manager/logs -name "*.log" -mtime +7 -delete 2>/dev/null
EOF
    chmod 0644 /etc/cron.d/*
    print_success "Task-uri programate configurate"
}

# ========== OPTIMIZĂRI SISTEM ==================
#
# Aplică o serie de optimizări la nivel de kernel (sysctl) și limite de sistem
# pentru a îmbunătăți performanța rețelei și a gestionării fișierelor,
# esențiale pentru un server cu trafic ridicat.
#
optimize_system() {
    print_step "Optimizarea performanței sistemului..."

    # Aplică setări sysctl pentru performanța rețelei și a sistemului
    cat > /etc/sysctl.d/99-docker-manager.conf << EOF
# Optimizări TCP/IP
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_slow_start_after_idle = 0

# Optimizări sistem de fișiere și memorie virtuală
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 512
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1

# Întăriri de securitate
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Necesare pentru Docker
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
    sysctl -p /etc/sysctl.d/99-docker-manager.conf >/dev/null 2>&1

    # Mărește limitele pentru descriptori de fișiere (file descriptors)
    cat > /etc/security/limits.d/99-docker-manager.conf << EOF
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 65536
* hard nproc 65536
* soft memlock unlimited
* hard memlock unlimited
$ADMIN_USER soft nofile 1048576
$ADMIN_USER hard nofile 1048576
$ADMIN_USER soft nproc 65536
$ADMIN_USER hard nproc 65536
EOF

    # Configurează rotația și limitele pentru log-urile systemd
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/99-docker-manager.conf << EOF
[Journal]
SystemMaxUse=1G
SystemKeepFree=2G
SystemMaxFileSize=100M
MaxRetentionSec=1month
MaxFileSec=1week
ForwardToSyslog=no
Compress=yes
EOF
    systemctl restart systemd-journald
    print_success "Optimizări de performanță aplicate"
}
# ====================== CLEANUP LA EROARE =========================
#
# Funcție de cleanup care este apelată în caz de eroare.
# Afișează un mesaj de eroare și locația fișierului de log.
#
cleanup_on_error() {
    print_error "A apărut o eroare în timpul instalării!"
    print_info "Verifică logurile în: $LOG_FILE"
    exit 1
}

# Setare trap pentru orice EROARE neinterceptată:
trap cleanup_on_error ERR

# ================ RESTART SERVICII ȘI VERIFICARE FINALĂ ====================
#
# Repornește serviciile critice la finalul instalării și verifică
# dacă toate sunt active și funcționale.
#
restart_all_services() {
    print_step "Restart servicii și verificare finală..."
    # Restart servicii în ordinea corectă
    systemctl restart ssh
    sleep 2
    systemctl restart fail2ban
    systemctl restart nginx
    systemctl restart docker

    # Verificare că toate serviciile sunt active
    local all_good=true
    for service in ssh fail2ban nginx docker; do
        if ! systemctl is-active --quiet $service; then
            print_warning "Serviciul $service nu este activ!"
            all_good=false
        fi
    done

    if [ "$all_good" = true ]; then
        print_success "Toate serviciile sunt active și funcționale"
    else
        print_warning "Unele servicii necesită atenție - verifică cu: system-check"
    fi
}

# ================== GENERARE RAPORT FINAL DE INSTALARE =====================
#
# Generează un raport detaliat al instalării, salvat în /root.
# Acest raport conține toate informațiile esențiale despre configurarea serverului
# și pașii următori pentru utilizator.
#
generate_final_report() {
    print_step "Generarea raportului final de instalare..."

    local server_ip=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    local report_file="/root/docker-manager-setup-report.txt"

    cat > "$report_file" << EOF
╔══════════════════════════════════════════════════════════════════╗
║            📊 RAPORT INSTALARE DOCKER MANAGER v3.0               ║
╚══════════════════════════════════════════════════════════════════╝

Data instalării: $(date)
Versiune script: 3.0

=====================================
🖥️  INFORMAȚII SISTEM
=====================================
• Hostname: $HOSTNAME
• OS: $(lsb_release -d | cut -f2)
• Kernel: $(uname -r)
• IP Public: $server_ip
• Timezone: $TIMEZONE
• CPU: $(nproc) cores
• RAM: $(free -h | grep Mem | awk '{print $2}')
• Disk: $(df -h / | awk 'NR==2 {print $2}')

=====================================
👤 CONFIGURAȚIE UTILIZATOR
=====================================
• Utilizator Admin: $ADMIN_USER
• Home Directory: /home/$ADMIN_USER
• Acces sudo: Configurat (NOPASSWD)
• Membru în grupuri: sudo, docker
• SSH Key: $([ -n "$SSH_PUBLIC_KEY" ] && echo "✓ Configurată" || echo "✗ Doar parolă")

=====================================
🔐 SECURITATE
=====================================
• SSH Port: $SSH_PORT
• SSH Root Login: Dezactivat
• Password Authentication: $([ -n "$SSH_PUBLIC_KEY" ] && echo "Activă (backup)" || echo "Activă")
• Firewall (UFW): Activ
  └─ Porturi deschise: $SSH_PORT, 80, 443, 3000, 3001
• Fail2Ban: Activ
  └─ Jails: sshd, nginx-*
• Actualizări automate: Configurate

=====================================
🌐 CONFIGURAȚIE REȚEA
=====================================
• Domeniu: ${DOMAIN_NAME:-"Doar acces IP"}
• SSL: $([ -n "$DOMAIN_NAME" ] && echo "Let's Encrypt" || echo "Nu este configurat")
• Nginx: Configurat ca reverse proxy
• Rate limiting: Activ

=====================================
🐳 DOCKER & APLICAȚII
=====================================
• Docker CE: $(docker --version 2>/dev/null | cut -d' ' -f3 || echo "N/A")
• Docker Compose: v2 (plugin)
• Docker Manager: Pregătit pentru instalare
  └─ Backend port: 3001
  └─ Frontend port: 3000
• MongoDB: Pregătit (port intern)
• Redis: Pregătit (port intern)

=====================================
📁 STRUCTURA DIRECTOARE
=====================================
• Aplicație: /opt/docker-manager
• Date Docker: /opt/docker-data
• Backup-uri: /opt/backups
• Loguri: /var/log/docker-manager
• Configurări: /opt/docker-manager/.env

=====================================
🛠️  SCRIPTURI UTILITARE
=====================================
• system-check - Verificare completă sistem
• docker-backup - Backup manual
• docker-restore <file> - Restaurare din backup
• docker-monitor - Monitorizare live
• notify-admin - Trimite notificări

=====================================
⏰ TASK-URI AUTOMATE
=====================================
• Backup automat: Zilnic la 2:00 AM
• Monitorizare sistem: La fiecare 5 minute
• Verificare servicii: La fiecare 10 minute
• Curățare loguri: Zilnic la 3:00 AM
• Actualizări securitate: Automat

=====================================
📊 ACCES APLICAȚIE
=====================================
EOF

    if [ -n "$DOMAIN_NAME" ]; then
        cat >> "$report_file" << EOF
• Frontend: https://$DOMAIN_NAME
• API: https://$DOMAIN_NAME/api
• Health check: https://$DOMAIN_NAME/api/health
EOF
    else
        cat >> "$report_file" << EOF
• Frontend: http://$server_ip
• API: http://$server_ip/api
• Health check: http://$server_ip/api/health
• Acces direct: http://$server_ip:3000 (frontend)
                http://$server_ip:3001 (API)
EOF
    fi

    cat >> "$report_file" << EOF

=====================================
🚀 PAȘI URMĂTORI
=====================================
1. Testează conexiunea SSH:
   ssh -p $SSH_PORT $ADMIN_USER@$server_ip

2. Conectează-te ca $ADMIN_USER și navighează:
   cd /opt/docker-manager

3. Copiază fișierele aplicației:
   - Backend în: /opt/docker-manager/backend/
   - Frontend în: /opt/docker-manager/frontend/

4. Configurează aplicația:
   cp .env.template .env
   nano .env  # Verifică/modifică setările

5. Construiește și pornește:
   docker compose build
   docker compose up -d

6. Verifică status:
   docker compose ps
   docker compose logs

=====================================
⚠️  RECOMANDĂRI IMPORTANTE
=====================================
• SALVEAZĂ parola pentru $ADMIN_USER într-un loc sigur
• SALVEAZĂ acest raport pentru referință
• TESTEAZĂ conexiunea SSH înainte de a închide sesiunea curentă
• CONFIGUREAZĂ backup-uri externe pentru date critice
• MONITORIZEAZĂ regulat cu: system-check
• ACTUALIZEAZĂ periodic cu: apt update && apt upgrade

=====================================
📞 SUPORT & DEPANARE
=====================================
• Logs SSH: /var/log/auth.log
• Logs Nginx: /var/log/nginx/
• Logs Docker: docker logs <container>
• Logs sistem: journalctl -xe
• Status servicii: systemctl status <service>

====================================
✅ INSTALARE COMPLETĂ CU SUCCES!
====================================
EOF

    # Creează un fișier separat cu credențiale, cu permisiuni restrictive
    cat > "/root/.docker-manager-credentials" << EOF
# Docker Manager Credentials
# PĂSTREAZĂ ACEST FIȘIER ÎN SIGURANȚĂ!
# Generated: $(date)

Admin User: $ADMIN_USER
Admin Password: [cea pe care ai setat-o]
SSH Port: $SSH_PORT

MongoDB Root User: Vezi în /opt/docker-manager/.env
MongoDB Root Password: Vezi în /opt/docker-manager/.env
Redis Password: Vezi în /opt/docker-manager/.env

JWT Secret: Vezi în /opt/docker-manager/.env
JWT Refresh Secret: Vezi în /opt/docker-manager/.env
EOF

    chmod 600 "/root/.docker-manager-credentials"
    print_success "Raport generat în: $report_file"
}

# ================== BANNER FINAL / INSTRUCȚIUNI CLI ====================
#
# Afișează un mesaj final în consolă cu un rezumat al informațiilor
# critice și instrucțiuni clare pentru pașii următori.
#
show_completion_message() {
    clear
    echo -e "${GREEN}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║        🎉 FELICITĂRI! INSTALARE COMPLETĂ CU SUCCES! 🎉          ║
    ║                                                                  ║
    ║                    Docker Manager VPS Setup v3.0                 ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"

    local server_ip=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")

    echo -e "${BLUE}📋 REZUMAT RAPID:${NC}"
    echo ""
    echo -e "${GREEN}✅ Sistem securizat și optimizat${NC}"
    echo -e "${GREEN}✅ Utilizator admin: ${YELLOW}$ADMIN_USER${NC}"
    echo -e "${GREEN}✅ SSH port: ${YELLOW}$SSH_PORT${NC}"
    echo -e "${GREEN}✅ Firewall și Fail2Ban active${NC}"
    echo -e "${GREEN}✅ Docker și Docker Compose instalate${NC}"
    echo -e "${GREEN}✅ Nginx configurat ca reverse proxy${NC}"

    if [ -n "$DOMAIN_NAME" ]; then
        echo -e "${GREEN}✅ Domeniu configurat: ${YELLOW}$DOMAIN_NAME${NC}"
    else
        echo -e "${GREEN}✅ Acces prin IP: ${YELLOW}$server_ip${NC}"
    fi

    echo ""
    echo -e "${RED}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}⚠️  IMPORTANT - CITEȘTE CU ATENȚIE:${NC}"
    echo -e "${RED}════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}1. TESTEAZĂ IMEDIAT conexiunea SSH într-o fereastră nouă:${NC}"
    echo -e "   ${CYAN}ssh -p $SSH_PORT $ADMIN_USER@$server_ip${NC}"
    echo ""
    echo -e "${YELLOW}2. NU ÎNCHIDE această sesiune până nu confirmi că poți conecta!${NC}"
    echo ""
    echo -e "${YELLOW}3. Raport complet salvat în:${NC}"
    echo -e "   ${CYAN}/root/docker-manager-setup-report.txt${NC}"
    echo ""
    echo -e "${YELLOW}4. Pentru a începe cu Docker Manager:${NC}"
    echo -e "   ${CYAN}su - $ADMIN_USER${NC}"
    echo -e "   ${CYAN}cd /opt/docker-manager${NC}"
    echo -e "   ${CYAN}./init.sh${NC}"
    echo ""

    echo -e "${BLUE}🛠️  Comenzi utile:${NC}"
    echo -e "• Verificare sistem: ${CYAN}system-check${NC}"
    echo -e "• Monitorizare live: ${CYAN}docker-monitor${NC}"
    echo -e "• Backup manual: ${CYAN}docker-backup${NC}"
    echo ""

    echo -e "${GREEN}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Instalare completă! Mult succes cu Docker Manager! 🚀${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ======================= FUNCȚIA PRINCIPALĂ ========================
#
# Orchestrează întregul proces de instalare, apelând funcțiile
# definite mai sus în ordinea corectă.
#
main() {
    # Inițializare
    print_header
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    echo "=== Docker Manager VPS Setup v3.0 - Started at $(date) ===" > "$LOG_FILE"

    # Etapele instalării
    check_root
    check_system
    collect_config

    echo ""
    print_info "Instalarea va dura aproximativ 10-15 minute..."
    echo ""

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
    create_config_files
    create_management_scripts
    setup_cron_jobs
    optimize_system

    # Finalizare
    generate_final_report
    restart_all_services

    show_completion_message
    echo "=== Setup completed successfully at $(date) ===" >> "$LOG_FILE"
}

# ===== PORNIRE SCRIPT DOAR DACĂ E EXECUTAT DIRECT (nu la import) =====
# Asigură că funcția `main` este apelată doar când scriptul este executat,
# nu și când este inclus (sourced) în alt script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
