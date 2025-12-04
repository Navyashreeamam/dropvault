# DropVault 🔐

Secure file storage with encryption, sharing, and trash recovery.

## Features
- 🔐 End-to-end file encryption
- 📤 Secure file sharing via email/link
- 🗑️ Trash with 30-day retention
- 🔄 File recovery from trash
- 📧 Email verification
- 🐳 Docker support

## Quick Start

### Using Docker

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/dropvault.git
cd dropvault

# Create .env file with your settings
cp .env.example .env

# Build and run with Docker
docker-compose up -d

# Access at http://localhost:8000
