# Auto-Incident Resolution Testing Environment — Architecture

## Overview

This document describes the full infrastructure architecture provisioned by the Ansible playbook. The environment runs on a single AWS EC2 instance and provides a complete monitoring stack for auto-incident resolution testing.

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          AWS EC2 Instance (Ubuntu 22.04)                     │
│                                                                              │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐  │
│  │   Nginx     │   │  Prometheus  │   │   Grafana    │   │  Load Test   │  │
│  │   :80/:443  │   │    :9090     │   │    :3000     │   │  (wrk + ab)  │  │
│  └──────┬──────┘   └──────┬───────┘   └──────────────┘   └──────────────┘  │
│         │                 │                                                  │
│         │  /nginx_status  │  scrape targets                                  │
│         │                 │                                                  │
│  ┌──────┴──────┐   ┌─────┴────────┐                                        │
│  │   Nginx     │   │    Node      │                                        │
│  │  Exporter   │   │   Exporter   │                                        │
│  │   :9113     │   │    :9100     │                                        │
│  └─────────────┘   └──────────────┘                                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. EC2 Instance Provisioning

| Parameter | Value |
|-----------|-------|
| OS | Ubuntu 22.04 LTS (Jammy) |
| AMI Resolution | SSM Parameter Store → ec2_ami_info fallback |
| Instance Type | Configurable (`aws_instance_type`) |
| Key Pair | Configurable (`aws_key_name`) |
| SSH User | `ubuntu` |
| SSH Key | `demo.pem` |

**Security Group Ports:**

| Port | Protocol | Purpose | CIDR |
|------|----------|---------|------|
| 22 | TCP | SSH | `ssh_allowed_cidr` (configurable) |
| 80 | TCP | Nginx HTTP | `0.0.0.0/0` |
| 443 | TCP | Nginx HTTPS | `0.0.0.0/0` |
| 9090 | TCP | Prometheus | `0.0.0.0/0` |
| 3000 | TCP | Grafana | `0.0.0.0/0` |
| 9100 | TCP | Node Exporter | `0.0.0.0/0` |
| 9113 | TCP | Nginx Exporter | `0.0.0.0/0` |

### 2. Nginx

**Source:** Cloned from `https://github.com/mgm152002/nginx_configs.git`

```
nginx_configs/
├── nginx/
│   ├── nginx.conf
│   ├── conf.d/
│   │   └── default.conf
│   ├── sites-available/
│   │   └── default
│   └── sites-enabled/
│       └── default -> ../sites-available/default
└── www/
    └── html/
        └── index.html
```

**Deployment flow:**
1. Install `nginx`, `git`, `curl`, `wget`, `gnupg2`, `ca-certificates`, `lsb-release`
2. Clone configs to `/tmp/nginx_configs`
3. Copy `nginx/` → `/etc/nginx/`
4. Copy `www/` → `/var/www/html/`
5. Remove default site configs
6. Validate with `nginx -t`
7. Create `/nginx_status` stub_status endpoint (from template)
8. Enable site via symlink in `sites-enabled/`
9. Start and restart nginx

**Status endpoint:** `http://localhost/nginx_status` — restricted to `127.0.0.1`

### 3. Prometheus (v3.8.1)

| Property | Value |
|----------|-------|
| Binary | `/usr/local/bin/prometheus` (symlink) |
| Config | `/etc/prometheus/prometheus.yml` |
| Data Dir | `/var/lib/prometheus` |
| Listen | `0.0.0.0:9090` |
| User | `prometheus` (system) |

**Scrape targets:**

| Job | Target | Metrics Path |
|-----|--------|-------------|
| `prometheus` | `localhost:9090` | `/metrics` (default) |
| `node_exporter` | `localhost:9100` | `/metrics` (default) |
| `nginx` | `localhost:9113` | `/metrics` (default) |
| `nginx_server` | `localhost:80` | `/nginx_status` |

**Scrape interval:** 15s

### 4. Node Exporter (v1.10.2)

| Property | Value |
|----------|-------|
| Binary | `/usr/local/bin/node_exporter` (symlink) |
| Listen | `0.0.0.0:9100` |
| User | `node_exporter` (system) |

**Collectors enabled:** `systemd`, `processes`, `cpu`, `meminfo`, `diskstats`

### 5. Nginx Exporter (v1.5.1)

| Property | Value |
|----------|-------|
| Binary | `/usr/local/bin/nginx_exporter` (symlink) |
| Listen | `0.0.0.0:9113` |
| Scrape URI | `http://localhost/nginx_status` |
| User | `nginx_exporter` (system) |

**Exported metrics:**
- `nginx_http_requests_total`
- `nginx_http_request_duration_seconds`
- `nginx_http_connections` (active, reading, writing, waiting)
- `nginx_connections_accepted`
- `nginx_connections_handled`

### 6. Grafana

| Property | Value |
|----------|-------|
| Install | APT (`apt.grafana.com` repository) |
| Config | `/etc/grafana/grafana.ini` |
| Data Dir | `/var/lib/grafana` |
| Listen | `0.0.0.0:3000` |
| DB | SQLite3 |
| Admin User | `admin` |
| Admin Password | `admin` |

**Provisioned resources:**
- **Datasource:** Prometheus at `http://localhost:9090` (default)
- **Dashboard:** `Auto-Incident Resolution Test Dashboard` with 4 panels:
  1. CPU Usage (`node_cpu_seconds_total`)
  2. Memory Usage (`node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes`)
  3. Nginx Requests/sec (`rate(nginx_http_requests_total[5m])`)
  4. Nginx Request Duration (`nginx_http_request_duration_seconds_sum / nginx_http_requests_total`)

### 7. Load Testing

**Tools installed:** `apache2-utils` (ab), `wrk`, `htop`, `curl`

**Script:** `/usr/local/bin/load_test.sh`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `TARGET_HOST` | `localhost` | Target hostname |
| `TARGET_PORT` | `80` | Target port |
| `DURATION` | `300` | Test duration in seconds |
| `THREADS` | `4` | wrk thread count |
| `CONNECTIONS` | `50` | Concurrent connections |

**Behavior:**
- Runs `wrk` continuously for the specified duration
- Runs `ab` (Apache Bench) 5 times with 1000 requests each at 50 concurrency, spaced 60s apart
- Exposed as a systemd oneshot service (`load-test.service`)

## Playbook Execution Order

```
1. Provision EC2 Instance for Auto-Incident Testing (localhost)
   ├─ Validate AWS credentials
   ├─ Create security group (ports 22, 80, 443, 9090, 3000, 9100, 9113)
   ├─ Resolve AMI (SSM → ec2_ami_info)
   ├─ Provision EC2 instance
   └─ Add host to inventory as "nginx-server"

2. Setup Nginx with GitHub Configs (nginx-server)
   ├─ Install packages
   ├─ Clone and deploy nginx configs
   ├─ Create /nginx_status endpoint
   └─ Start nginx

3. Setup Prometheus (nginx-server)
   ├─ Create user and directories
   ├─ Download and extract binary
   ├─ Write config with scrape targets
   └─ Start systemd service

4. Setup Node Exporter (nginx-server)
   ├─ Create user
   ├─ Download and extract binary
   └─ Start systemd service

5. Setup Nginx Exporter (nginx-server)
   ├─ Create user and directories
   ├─ Download and extract binary
   └─ Start systemd service

6. Setup Grafana (nginx-server)
   ├─ Install via APT
   ├─ Configure grafana.ini
   ├─ Provision datasource (Prometheus)
   ├─ Provision dashboard JSON
   └─ Start grafana-server

7. Display URLs Before Load Test (localhost)
   └─ Print service URLs and credentials

8. Setup Load Testing (nginx-server)
   ├─ Install wrk, ab, htop, curl
   ├─ Create load_test.sh script
   └─ Start load-test systemd service
```

## Service URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| Nginx HTTP | `http://<PUBLIC_IP>:80` | — |
| Prometheus | `http://<PUBLIC_IP>:9090` | — |
| Grafana | `http://<PUBLIC_IP>:3000` | `admin` / `admin` |
| Node Exporter | `http://<PUBLIC_IP>:9100` | — |
| Nginx Exporter | `http://<PUBLIC_IP>:9113` | — |

## Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `aws_region` | — | AWS region |
| `aws_instance_type` | — | EC2 instance type |
| `aws_key_name` | — | EC2 key pair name |
| `aws_security_group_name` | — | Security group name |
| `ssh_allowed_cidr` | — | CIDR for SSH access |
| `ssh_key_path` | `demo.pem` | Local SSH key path |
| `aws_ami_ssm_param` | — | SSM parameter for AMI |
| `ec2_tags` | — | EC2 instance tags |
| `nginx_repo_url` | `https://github.com/mgm152002/nginx_configs.git` | Nginx config repo |
| `prometheus_version` | `3.8.1` | Prometheus version |
| `node_exporter_version` | `1.10.2` | Node Exporter version |
| `nginx_exporter_version` | `1.5.1` | Nginx Exporter version |
