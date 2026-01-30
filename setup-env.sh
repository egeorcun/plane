#!/bin/bash
# =============================================================================
# PLANE ENVIRONMENT SETUP SCRIPT
# =============================================================================
# This script generates secure environment variables for Plane deployment.
# It creates a .env file with auto-generated passwords and sensible defaults.
#
# Usage:
#   ./setup-env.sh                    # Interactive mode
#   ./setup-env.sh --non-interactive  # Use defaults for optional fields
#
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Output file
ENV_FILE=".env"
ENV_EXAMPLE=".env.production.example"

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

print_header() {
    echo ""
    echo -e "${BLUE}=============================================================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}=============================================================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Generate a random string
generate_random() {
    local length=${1:-32}
    openssl rand -base64 $length 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c $length
}

# Generate a random hex string
generate_hex() {
    local length=${1:-16}
    openssl rand -hex $length 2>/dev/null | head -c $length
}

# Generate a URL-safe random string (for SECRET_KEY)
generate_secret_key() {
    openssl rand -base64 64 2>/dev/null | tr -dc 'a-zA-Z0-9_-' | head -c 64
}

# Prompt for input with default value
prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    
    if [[ "$NON_INTERACTIVE" == "true" && -n "$default" ]]; then
        eval "$var_name=\"$default\""
        return
    fi
    
    if [[ -n "$default" ]]; then
        read -p "$prompt [$default]: " input
        eval "$var_name=\"${input:-$default}\""
    else
        read -p "$prompt: " input
        eval "$var_name=\"$input\""
    fi
}

# =============================================================================
# CHECK PREREQUISITES
# =============================================================================

check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check for openssl
    if ! command -v openssl &> /dev/null; then
        print_error "openssl is required but not installed."
        exit 1
    fi
    print_success "openssl found"
    
    # Check for docker
    if ! command -v docker &> /dev/null; then
        print_warning "docker not found - you'll need it to run Plane"
    else
        print_success "docker found"
    fi
    
    # Check if .env already exists
    if [[ -f "$ENV_FILE" ]]; then
        print_warning ".env file already exists"
        if [[ "$NON_INTERACTIVE" != "true" ]]; then
            read -p "Overwrite? (y/N): " overwrite
            if [[ "$overwrite" != "y" && "$overwrite" != "Y" ]]; then
                print_error "Aborted. Backup your .env file and try again."
                exit 1
            fi
        fi
    fi
}

# =============================================================================
# GENERATE SECURE CREDENTIALS
# =============================================================================

generate_credentials() {
    print_header "Generating Secure Credentials"
    
    # Django Secret Key (64 characters)
    SECRET_KEY=$(generate_secret_key)
    print_success "Generated SECRET_KEY (64 chars)"
    
    # PostgreSQL
    POSTGRES_USER="plane"
    POSTGRES_PASSWORD=$(generate_random 32)
    POSTGRES_DB="plane"
    print_success "Generated PostgreSQL credentials"
    
    # RabbitMQ
    RABBITMQ_USER="plane"
    RABBITMQ_PASSWORD=$(generate_random 32)
    RABBITMQ_VHOST="plane"
    print_success "Generated RabbitMQ credentials"
    
    # MinIO / S3
    AWS_ACCESS_KEY_ID=$(generate_hex 20)
    AWS_SECRET_ACCESS_KEY=$(generate_random 40)
    print_success "Generated MinIO/S3 credentials"
}

# =============================================================================
# GET USER INPUT FOR REQUIRED FIELDS
# =============================================================================

get_user_input() {
    print_header "Configuration"
    
    echo "Please provide the following required information:"
    echo ""
    
    # Domain/URL
    prompt_with_default "Your domain (e.g., plane.example.com)" "localhost" "DOMAIN"
    
    # Determine protocol
    if [[ "$DOMAIN" == "localhost" || "$DOMAIN" == "127.0.0.1" ]]; then
        PROTOCOL="http"
        print_warning "Using HTTP for localhost (no SSL)"
    else
        prompt_with_default "Use HTTPS?" "yes" "USE_HTTPS"
        if [[ "$USE_HTTPS" == "yes" || "$USE_HTTPS" == "y" ]]; then
            PROTOCOL="https"
        else
            PROTOCOL="http"
        fi
    fi
    
    WEB_URL="${PROTOCOL}://${DOMAIN}"
    ALLOWED_HOSTS="$DOMAIN"
    CORS_ALLOWED_ORIGINS="$WEB_URL"
    
    # Ports (only ask if not using standard ports)
    if [[ "$NON_INTERACTIVE" != "true" ]]; then
        prompt_with_default "HTTP port" "80" "LISTEN_HTTP_PORT"
        prompt_with_default "HTTPS port" "443" "LISTEN_HTTPS_PORT"
    else
        LISTEN_HTTP_PORT="80"
        LISTEN_HTTPS_PORT="443"
    fi
    
    # SSL Certificate email (optional)
    if [[ "$PROTOCOL" == "https" && "$NON_INTERACTIVE" != "true" ]]; then
        prompt_with_default "Email for SSL certificates (optional)" "" "CERT_EMAIL"
    else
        CERT_EMAIL=""
    fi
    
    # Gunicorn workers
    CPU_CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)
    GUNICORN_WORKERS=$((CPU_CORES * 2 + 1))
    if [[ $GUNICORN_WORKERS -gt 9 ]]; then
        GUNICORN_WORKERS=9
    fi
    print_success "Auto-configured $GUNICORN_WORKERS Gunicorn workers based on CPU cores"
}

# =============================================================================
# WRITE ENV FILE
# =============================================================================

write_env_file() {
    print_header "Writing Configuration"
    
    cat > "$ENV_FILE" << EOF
# =============================================================================
# PLANE PRODUCTION ENVIRONMENT
# =============================================================================
# Generated by setup-env.sh on $(date)
# =============================================================================

# =============================================================================
# SECURITY SETTINGS (Auto-generated - DO NOT SHARE)
# =============================================================================

# Django Secret Key
SECRET_KEY=${SECRET_KEY}

# Allowed hosts and CORS
ALLOWED_HOSTS=${ALLOWED_HOSTS}
CORS_ALLOWED_ORIGINS=${CORS_ALLOWED_ORIGINS}

# Debug mode (0 = production, 1 = development)
DEBUG=0

# =============================================================================
# DATABASE (PostgreSQL)
# =============================================================================

POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=${POSTGRES_DB}

# =============================================================================
# MESSAGE QUEUE (RabbitMQ)
# =============================================================================

RABBITMQ_USER=${RABBITMQ_USER}
RABBITMQ_PASSWORD=${RABBITMQ_PASSWORD}
RABBITMQ_VHOST=${RABBITMQ_VHOST}
RABBITMQ_PORT=5672

# =============================================================================
# OBJECT STORAGE (MinIO)
# =============================================================================

AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
AWS_REGION=
AWS_S3_ENDPOINT_URL=http://plane-minio:9000
AWS_S3_BUCKET_NAME=uploads
USE_MINIO=1
MINIO_ENDPOINT_SSL=0

# =============================================================================
# APPLICATION SETTINGS
# =============================================================================

# Your Plane URL
WEB_URL=${WEB_URL}

# Application version
APP_RELEASE=v1.0.0

# Worker configuration
GUNICORN_WORKERS=${GUNICORN_WORKERS}

# File upload limit (bytes) - default 5MB
FILE_SIZE_LIMIT=5242880

# Rate limiting
API_KEY_RATE_LIMIT=60/minute

# =============================================================================
# NETWORK SETTINGS
# =============================================================================

LISTEN_HTTP_PORT=${LISTEN_HTTP_PORT}
LISTEN_HTTPS_PORT=${LISTEN_HTTPS_PORT}

# Redis (internal)
REDIS_HOST=plane-redis
REDIS_PORT=6379
REDIS_URL=redis://plane-redis:6379/

# =============================================================================
# SSL/TLS SETTINGS
# =============================================================================

CERT_EMAIL=${CERT_EMAIL}
CERT_ACME_CA=https://acme-v02.api.letsencrypt.org/directory
TRUSTED_PROXIES=0.0.0.0/0

EOF

    print_success "Created $ENV_FILE"
}

# =============================================================================
# PRINT SUMMARY
# =============================================================================

print_summary() {
    print_header "Setup Complete!"
    
    echo "Your Plane instance is configured with:"
    echo ""
    echo -e "  URL:              ${GREEN}${WEB_URL}${NC}"
    echo -e "  HTTP Port:        ${LISTEN_HTTP_PORT}"
    echo -e "  HTTPS Port:       ${LISTEN_HTTPS_PORT}"
    echo -e "  Workers:          ${GUNICORN_WORKERS}"
    echo ""
    echo "Credentials have been auto-generated and saved to .env"
    echo ""
    echo -e "${YELLOW}IMPORTANT: Keep your .env file secure and never commit it to git!${NC}"
    echo ""
    echo "To deploy Plane, run:"
    echo ""
    echo -e "  ${GREEN}docker compose -f docker-compose.production.yml up -d --build${NC}"
    echo ""
    echo "First build may take 10-20 minutes depending on your server."
    echo ""
    
    if [[ "$PROTOCOL" == "https" && -z "$CERT_EMAIL" ]]; then
        print_warning "No SSL email configured. You may need to set up SSL manually or via reverse proxy."
    fi
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    print_header "Plane Environment Setup"
    
    # Check for non-interactive mode
    NON_INTERACTIVE="false"
    if [[ "$1" == "--non-interactive" || "$1" == "-n" ]]; then
        NON_INTERACTIVE="true"
        print_warning "Running in non-interactive mode"
    fi
    
    check_prerequisites
    generate_credentials
    get_user_input
    write_env_file
    print_summary
}

# Run main function
main "$@"
