# Installation Guide

This guide will walk you through installing and setting up the Rust OAuth2 Server on your local machine or production environment.

## Prerequisites

Before installing the OAuth2 server, ensure you have the following prerequisites installed:

### Required

- **Rust** (1.70 or higher)
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
  
- **SQLite** (for development) or **PostgreSQL** (for production)
  ```bash
  # Ubuntu/Debian
  sudo apt-get install sqlite3 libsqlite3-dev
  
  # macOS
  brew install sqlite
  
  # For PostgreSQL
  sudo apt-get install postgresql postgresql-contrib
  ```

### Optional

- **Docker** (for containerized deployment)
  ```bash
  # Install Docker
  curl -fsSL https://get.docker.com -o get-docker.sh
  sudo sh get-docker.sh
  ```

- **Docker Compose** (for multi-container setup)
  ```bash
  sudo apt-get install docker-compose
  ```

- **Flyway** (for manual database migrations)
  ```bash
  # Download from https://flywaydb.org/download/
  # Or use Docker version (recommended)
  ```

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/ianlintner/rust_oauth2.git
cd rust_oauth2
```

### 2. Install Rust Dependencies

The project uses Cargo to manage dependencies. Install all required dependencies:

```bash
cargo build
```

This will download and compile all dependencies specified in `Cargo.toml`.

### 3. Database Setup

#### Using SQLite (Development)

Create the SQLite database file:

```bash
touch oauth2.db
```

#### Using PostgreSQL (Production)

Create a PostgreSQL database:

```bash
# Login to PostgreSQL
sudo -u postgres psql

# Create database and user
CREATE DATABASE oauth2_db;
CREATE USER oauth2_user WITH ENCRYPTED PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE oauth2_db TO oauth2_user;
\q
```

### 4. Run Database Migrations

The project uses Flyway for database schema management. You have several options:

#### Option A: Using the Migration Script (Recommended)

```bash
./scripts/migrate.sh
```

This script automatically detects if Flyway is installed locally or uses Docker.

#### Option B: Using Docker Directly

```bash
docker run --rm \
  -v "$(pwd)/migrations/sql:/flyway/sql" \
  -v "$(pwd)/flyway.conf:/flyway/conf/flyway.conf" \
  flyway/flyway:10-alpine migrate
```

#### Option C: Using Flyway Command Line

If you have Flyway installed locally:

```bash
flyway -configFiles=flyway.conf migrate
```

### 5. Configure Environment Variables

Create a `.env` file in the project root (this file is gitignored):

```bash
# Server Configuration
OAUTH2_SERVER_HOST=127.0.0.1
OAUTH2_SERVER_PORT=8080

# Database Configuration
OAUTH2_DATABASE_URL=sqlite:oauth2.db
# For PostgreSQL:
# OAUTH2_DATABASE_URL=postgresql://oauth2_user:your_password@localhost/oauth2_db

# JWT Configuration
OAUTH2_JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters-long

# Session Configuration
OAUTH2_SESSION_KEY=your-session-key-must-be-at-least-64-characters-for-security

# Token Expiration (in seconds)
OAUTH2_ACCESS_TOKEN_EXPIRATION=3600
OAUTH2_REFRESH_TOKEN_EXPIRATION=2592000

# OpenTelemetry Configuration
OAUTH2_OTLP_ENDPOINT=http://localhost:4317

# Social Login Providers (Optional)
# See social-login-setup.md for detailed setup
# OAUTH2_GOOGLE_CLIENT_ID=your-google-client-id
# OAUTH2_GOOGLE_CLIENT_SECRET=your-google-client-secret
```

!!! warning "Security Notice"
    Never commit the `.env` file or any files containing secrets to version control. The `.gitignore` file is already configured to exclude it.

### 6. Build the Project

#### Development Build

```bash
cargo build
```

#### Release Build (Production)

```bash
cargo build --release
```

The release build is optimized for performance and produces a smaller binary.

### 7. Verify Installation

Run the server to verify everything is set up correctly:

```bash
cargo run
```

You should see output similar to:

```
[INFO] Starting OAuth2 Server...
[INFO] Configuration loaded
[INFO] Social login configuration loaded
[INFO] Metrics initialized
[INFO] Database initialized
[INFO] Starting HTTP server at http://127.0.0.1:8080
```

### 8. Test the Installation

Open your browser and navigate to:

- **Server Root**: http://localhost:8080
- **Health Check**: http://localhost:8080/health
- **API Documentation**: http://localhost:8080/swagger-ui
- **Admin Dashboard**: http://localhost:8080/admin
- **Metrics**: http://localhost:8080/metrics

## Docker Installation

For a containerized setup, use Docker Compose:

### 1. Build and Run

```bash
docker-compose up -d
```

This will:
- Build the OAuth2 server image
- Run database migrations
- Start the server on port 8080

### 2. View Logs

```bash
docker-compose logs -f oauth2_server
```

### 3. Stop the Server

```bash
docker-compose down
```

## Troubleshooting

### Database Connection Issues

**Problem**: "Failed to connect to database"

**Solution**:
```bash
# Check database URL format
# SQLite: sqlite:path/to/database.db
# PostgreSQL: postgresql://user:password@host/database

# Verify database file exists (SQLite)
ls -la oauth2.db

# Verify PostgreSQL is running
sudo systemctl status postgresql
```

### Migration Errors

**Problem**: "Migration failed"

**Solution**:
```bash
# Check migration files exist
ls -la migrations/sql/

# Verify Flyway configuration
cat flyway.conf

# Try running migrations manually
./scripts/migrate.sh
```

### Port Already in Use

**Problem**: "Address already in use"

**Solution**:
```bash
# Find process using port 8080
lsof -i :8080
# Or
netstat -tulpn | grep 8080

# Kill the process or change the port
export OAUTH2_SERVER_PORT=8081
```

### Rust Compilation Errors

**Problem**: "Could not compile..."

**Solution**:
```bash
# Update Rust to latest stable
rustup update stable

# Clean build artifacts
cargo clean

# Rebuild
cargo build
```

## Next Steps

After successful installation:

1. Read the [Quick Start Guide](quickstart.md) to create your first OAuth2 client
2. Review [Configuration Options](configuration.md) for detailed settings
3. Set up [Social Login Providers](social-login-setup.md) if needed
4. Explore the [API Documentation](../api/endpoints.md)

## System Requirements

### Minimum Requirements

- **CPU**: 1 core (2 cores recommended)
- **RAM**: 512 MB (1 GB recommended)
- **Disk**: 100 MB for application + space for database
- **OS**: Linux, macOS, or Windows

### Recommended Production Requirements

- **CPU**: 2+ cores
- **RAM**: 2+ GB
- **Disk**: 10+ GB SSD
- **OS**: Linux (Ubuntu 20.04+ or similar)
- **Database**: PostgreSQL with separate server

## Support

If you encounter any issues during installation:

1. Check the [Troubleshooting](#troubleshooting) section above
2. Review the [GitHub Issues](https://github.com/ianlintner/rust_oauth2/issues)
3. Consult the [Configuration Guide](configuration.md)
4. Open a new issue with detailed error information
