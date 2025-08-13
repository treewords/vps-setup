# Docker Manager Dashboard

This project is a web-based management interface for Docker, designed to be deployed on a server provisioned with the included `vps-setup.sh` script. It provides a modern, responsive UI for managing Docker containers.

## Features

- **List Containers**: View all containers (running, stopped, etc.) with their status and key information.
- **Container Actions**: Start, stop, and restart containers directly from the UI.
- **Inspect Container**: View detailed information about a container in a clean, formatted view.
- **Real-time Logs**: Stream container logs in real-time and view historical logs.

## Technology Stack

- **Backend**: Node.js with Express.js, using `dockerode` to interact with the Docker API.
- **Frontend**: React with Material-UI for a modern and responsive design.
- **Real-time Communication**: WebSockets (`ws` library) for live log streaming.
- **Containerization**: Docker and Docker Compose.

## Local Development

To run the application in a local development environment, you need Docker and Docker Compose installed.

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

2.  **Start the application:**
    ```bash
    docker-compose up --build
    ```
    This command will build the Docker images for the frontend and backend and start the services.

3.  **Access the application:**
    -   The frontend will be available at [http://localhost:3000](http://localhost:3000).
    -   The backend API will be available at [http://localhost:3001](http://localhost:3001).

The development server supports hot-reloading. Any changes you make to the source code in `app/backend` or `app/frontend` will be reflected automatically.

---

# Production Deployment with VPS Setup Script

This script automates the setup and hardening of a Debian 11/12 server, preparing it to host a web application called "Docker Manager". It configures a secure, production-ready environment with Docker, Nginx as a reverse proxy, SSL, and various management utilities.

**Note:** The script's interactive prompts and console output are in **Romanian**.

## Features

-   **System Hardening**: Secures SSH, sets up a firewall (UFW), and installs Fail2Ban to prevent brute-force attacks.
-   **Automated Dependency Installation**: Installs Nginx, Docker, Docker Compose, Certbot, and other essential utilities.
-   **User & Permissions Setup**: Creates a dedicated admin user with `sudo` privileges and appropriate permissions for managing Docker.
-   **Nginx Reverse Proxy**: Configures Nginx as a reverse proxy, ready to serve the application.
-   **Automatic SSL**: Installs and configures a free Let's Encrypt SSL certificate if a domain name is provided.
-   **Application Scaffolding**: Creates the necessary directory structure and configuration templates (`docker-compose.yml`, `.env.template`) for the Docker Manager application.
-   **System Optimization**: Applies kernel-level optimizations for better performance.
-   **Management & Backup Scripts**: Installs utility scripts for system monitoring (`system-check`), backups (`docker-backup`), and restoration (`docker-restore`).
-   **Automated Maintenance**: Sets up cron jobs for daily backups and log rotation.
-   **Detailed Reporting**: Generates a comprehensive report with all setup details and credentials upon completion.

## Prerequisites

-   A server running **Debian 11 or Debian 12**.
-   **Root access** to the server.

## Usage

1.  Connect to your server as the `root` user.
2.  Download the script:
    ```bash
    curl -o vps-setup.sh https://raw.githubusercontent.com/your-repo/your-project/main/vps-setup.sh # Replace with the actual raw URL
    ```
3.  Make the script executable:
    ```bash
    chmod +x vps-setup.sh
    ```
4.  Run the script:
    ```bash
    ./vps-setup.sh
    ```

## Configuration

The script will guide you through an interactive configuration process. You will be asked to provide:

-   **Admin User Password**: A strong password for the new `dockeradmin` user.
-   **Public SSH Key**: Your public SSH key for secure, passwordless login (highly recommended).
-   **Domain Name**: The domain you want to use (e.g., `docker.example.com`). If you don't provide one, the server will be configured for access via its IP address.
-   **SSL Email**: An email address for Let's Encrypt notifications if you provide a domain.
-   **Alert Email**: An email address for system notifications (e.g., from Fail2Ban or unattended upgrades).

## What It Does in Detail

1.  **System Check**: Verifies OS compatibility and system resources.
2.  **Package Management**: Updates the system and installs all necessary packages.
3.  **User Creation**: Creates a non-root user `dockeradmin` and gives it `sudo` rights.
4.  **SSH Security**:
    -   Changes the default SSH port to `2222`.
    -   Disables root login via SSH.
    -   Configures modern, secure cryptographic algorithms.
5.  **Firewall (UFW)**:
    -   Sets up UFW to deny all incoming traffic by default.
    -   Allows traffic on necessary ports: SSH (`2222`), HTTP (`80`), HTTPS (`443`), and application ports (`3000`, `3001`).
6.  **Fail2Ban**: Configures jails to monitor SSH and Nginx logs, automatically banning malicious IPs.
7.  **Docker & Docker Compose**: Installs the latest versions from the official Docker repository and adds the `dockeradmin` user to the `docker` group.
8.  **Nginx**:
    -   Sets up Nginx as a reverse proxy.
    -   If a domain is provided, it configures it to handle HTTPS and redirect HTTP traffic.
    -   If no domain is provided, it configures it for HTTP access via the server's IP.
9.  **SSL (Let's Encrypt)**:
    -   If a domain is provided, it uses Certbot to obtain and install an SSL certificate.
    -   Sets up a cron job for automatic certificate renewal.
10. **Application Environment**:
    -   Creates directories (`/opt/docker-manager`, `/opt/docker-data`, `/opt/backups`).
    -   Generates a `docker-compose.yml` file for the application stack (backend, frontend, MongoDB, Redis).
    -   Generates a `.env.template` with pre-filled values and secure, randomly generated passwords.
11. **Utility Scripts**: Creates several helpful scripts in `/usr/local/bin`:
    -   `system-check`: Displays a summary of the system status.
    -   `docker-backup`: Creates a compressed backup of the application data and configuration.
    -   `docker-restore`: Restores the application from a backup.
    -   `docker-monitor`: A wrapper for `docker stats` to monitor running containers.
    -   `notify-admin`: A simple script to send email notifications.

## Post-Installation

After the script finishes, **it is crucial to perform the following steps**:

1.  **Test the new SSH connection in a new terminal window before closing your root session**:
    ```bash
    ssh -p 2222 dockeradmin@YOUR_SERVER_IP
    ```
2.  Once you have successfully logged in as `dockeradmin`, you can deploy your application:
    ```bash
    # Navigate to the application directory
    cd /opt/docker-manager

    # (Optional) Review and customize the environment variables
    cp .env.template .env
    nano .env

    # Place your application's source code or Dockerfiles in the correct directories
    # ...

    # Build and start the containers
    docker compose build
    docker compose up -d
    ```

3.  A detailed installation report is saved at `/root/docker-manager-setup-report.txt`. **Save this report**, as it contains important configuration details.

---

### **Disclaimer**

This script performs extensive modifications to your system and installs software with root privileges. Always review scripts from the internet before executing them on your server. The author is not responsible for any damage or data loss.
