# PPEM-Final Deployment Guide

## Table of Contents
1. [Quick Start](#quick-start)
2. [Production Deployment](#production-deployment)
3. [Cloud Deployment](#cloud-deployment)
4. [Monitoring & Maintenance](#monitoring--maintenance)
5. [Troubleshooting](#troubleshooting)

## Quick Start

### Local Development
```bash
# 1. Install dependencies
./scripts/install_dependencies.sh

# 2. Setup project
./scripts/setup.sh

# 3. Run
./ppem
```

### Docker Deployment
```bash
# Build and run with Docker
docker-compose up -d
```

## Production Deployment

### Prerequisites Checklist

- [ ] Ubuntu 22.04 LTS or similar
- [ ] 32GB RAM minimum
- [ ] 100GB available disk space
- [ ] Git with LFS support
- [ ] Docker & Docker Compose (optional)

### Step-by-Step Production Setup

#### 1. System Preparation
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
./scripts/install_dependencies.sh

# Configure system limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf
```

#### 2. Clone and Setup
```bash
# Clone with LFS
git lfs install
git clone https://github.com/yourusername/PPEM-Final.git
cd PPEM-Final

# Checkout specific version for production
git checkout tags/v1.0.0

# Run setup
./scripts/setup.sh --non-interactive
```

#### 3. Configuration
```bash
# Generate production config
./scripts/generate_config.sh

# Edit for production paths
vim ppem.config.json

# Validate configuration
./ppem --validate-config
```

#### 4. Build for Production
```bash
# Build with optimizations
CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o ppem ./cmd/ppem

# Build RISC Zero with release mode
cd risc0
cargo build --release
cd ..
```

#### 5. Proving Key Setup
```bash
# Option A: Download pre-generated (faster)
export PPEM_PROVING_KEY_URL="https://your-cdn.com/stark_verify_final.zkey"
export PPEM_PROVING_KEY_SHA256="your_sha256_hash_here"
./scripts/download_proving_key.sh

# Option B: Generate new (more secure)
./scripts/generate_proving_key.sh
```

## Cloud Deployment

### AWS EC2

#### Instance Requirements
- Type: `r5.8xlarge` or larger
- Storage: 200GB gp3 SSD
- Network: Enhanced networking enabled

#### Deployment Script
```bash
#!/bin/bash
# deploy_aws.sh

# Install AWS CLI dependencies
sudo apt install -y awscli

# Pull from S3
aws s3 cp s3://your-bucket/ppem-release.tar.gz .
tar -xzf ppem-release.tar.gz

# Start service
sudo systemctl start ppem
```

### Kubernetes

```yaml
# ppem-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ppem
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ppem
  template:
    metadata:
      labels:
        app: ppem
    spec:
      containers:
      - name: ppem
        image: yourdockerhub/ppem-final:latest
        resources:
          requests:
            memory: "16Gi"
            cpu: "4"
          limits:
            memory: "32Gi"
            cpu: "8"
        volumeMounts:
        - name: proving-key
          mountPath: /app/circom
          readOnly: true
      volumes:
      - name: proving-key
        persistentVolumeClaim:
          claimName: ppem-proving-key-pvc
```

### Docker Swarm

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml ppem-stack

# Scale service
docker service scale ppem-stack_ppem=5
```

## Environment Variables

```bash
# Core Configuration
export PPEM_CONFIG=/etc/ppem/config.json
export PPEM_LOG_LEVEL=info
export PPEM_DATA_DIR=/var/lib/ppem

# Tool Paths (override defaults)
export PPEM_CARGO_PATH=/usr/local/bin/cargo
export PPEM_STARK_VERIFY_PATH=/opt/ppem/bin/stark_verify
export PPEM_PROVER_PATH=/opt/ppem/bin/prover

# Performance Tuning
export RUST_BACKTRACE=1
export RAYON_NUM_THREADS=16
export GOMAXPROCS=16
```

## Systemd Service

```ini
# /etc/systemd/system/ppem.service
[Unit]
Description=PPEM Privacy-Preserving Energy Market
After=network.target

[Service]
Type=simple
User=ppem
Group=ppem
WorkingDirectory=/opt/ppem
ExecStart=/opt/ppem/ppem
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ppem

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ppem

# Resource Limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryLimit=32G

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ppem
sudo systemctl start ppem
sudo systemctl status ppem
```

## Monitoring & Maintenance

### Health Checks

```bash
# Check service status
curl http://localhost:8080/health

# Verify setup
./scripts/verify_setup.sh

# Check logs
journalctl -u ppem -f
```

### Prometheus Metrics

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'ppem'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
```

### Backup Strategy

```bash
#!/bin/bash
# backup.sh

# Backup configuration
tar -czf ppem-config-$(date +%Y%m%d).tar.gz \
  ppem.config.json \
  circom/vkey.json

# Backup data
rsync -av /var/lib/ppem/ /backup/ppem/

# Backup to S3
aws s3 sync /backup/ppem/ s3://your-backup-bucket/ppem/
```

## Troubleshooting

### Common Issues

#### "stark_verify: cannot execute binary file"
**Cause**: Architecture mismatch
**Solution**: Rebuild for your architecture
```bash
./scripts/build_stark_verify.sh
```

#### "Out of memory"
**Cause**: Insufficient RAM for proof generation
**Solution**: Increase system RAM or use swap
```bash
sudo fallocate -l 32G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

#### "Tool not found"
**Cause**: Incorrect PATH configuration
**Solution**: Regenerate config
```bash
./scripts/generate_config.sh
./ppem --validate-config
```

#### "Proving key not found"
**Cause**: Missing stark_verify_final.zkey
**Solution**: Download or generate
```bash
./scripts/download_proving_key.sh
# OR
./scripts/generate_proving_key.sh
```

### Debug Mode

```bash
# Enable debug logging
export PPEM_LOG_LEVEL=debug

# Run with verbose output
./ppem --debug --verbose

# Trace execution
strace -f ./ppem 2> trace.log
```

### Performance Tuning

```bash
# CPU Governor
sudo cpupower frequency-set -g performance

# Disable swap for performance
sudo swapoff -a

# Increase file descriptors
ulimit -n 65536

# Memory settings
echo 1 | sudo tee /proc/sys/vm/overcommit_memory
echo 90 | sudo tee /proc/sys/vm/dirty_ratio
```

## Security Considerations

1. **Firewall Configuration**
```bash
sudo ufw allow 22/tcp  # SSH
sudo ufw allow 8080/tcp  # PPEM API
sudo ufw enable
```

2. **File Permissions**
```bash
chmod 700 /opt/ppem
chmod 600 ppem.config.json
chmod 400 circom/stark_verify_final.zkey
```

3. **Secrets Management**
- Use environment variables for sensitive data
- Consider using HashiCorp Vault or AWS Secrets Manager
- Never commit proving keys to Git

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/PPEM-Final/issues)
- **Documentation**: [docs/](./docs/)
- **Community**: [Discord/Slack]

---
*Last updated: September 2024*