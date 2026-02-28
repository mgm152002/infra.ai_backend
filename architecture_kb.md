 # Nginx Configuration Architecture 
 ## Overview 
 This document describes the nginx configuration architecture used for the 
 auto-incident resolution testing environment. 
 ## Configuration Source 
 ### GitHub Repository 
 -  **Repository URL**  :  `https://github.com/mgm152002/nginx_configs` 
 -  **Config Path**  :  `https://github.com/mgm152002/nginx_configs/tree/main/nginx` 
 -  **Clone Location**  :  `/tmp/nginx_configs`  on the  EC2 instance 
 -  **Config Subdirectory**  :  `nginx/`  (where all configs  are stored) 
 ## New Repository Structure 
 The nginx_configs repository now has the following structure: 
 ``` 
 nginx_configs/ 
 ├── README.md                    # Documentation 
 ├── nginx/ 
 │   ├── nginx.conf               # Global settings (workers, gzip, logging, etc.) 
 │   ├── conf.d/ 
 │   │   └── default.conf         # Catch-all default server block 
 │   ├── sites-available/ 
 │   │   └── default              # Virtual host config for example.com 
 │   └── sites-enabled/ 
 │       └── default -> ../sites-available/default  # Symlink 
 └── www/ 
 └── html/ 
 └── index.html           # Dummy dark-themed landing page 
 ``` 
 ## Configuration Flow 
 ``` 
 GitHub Repository                    EC2 Instance 
 ┌─────────────────────┐              ┌─────────────────────┐ 
 │ nginx_configs/      │   git clone  │ /tmp/nginx_configs/ │ 
 │  ├── nginx/         │ ──────────>  │  ├── nginx/        │ 
 │  │   ├── nginx.conf│              │  │   ├── nginx.conf │ 
 │  │   ├── conf.d/   │              │  │   ├── conf.d/    │ 
 │  │   └── sites-*  │              │  │   └── sites-*    │ 
 │  └── www/          │              │  └── www/          │ 
 │      └── html/     │              │      └── html/     │ 
 └─────────────────────┘              └──────────┬──────────┘ 
 │ 
 ┌──────────────────┼──────────────────┐ 
 │                  │                  │ 
 ▼                  ▼                  ▼ 
 /etc/nginx/       /var/www/html/    /etc/nginx/sites-* 
 ``` 
 ## Ansible Tasks 
 The provisioning playbook performs the following: 
 1.  **Install Nginx** 
 ```yaml 
 apt  : 
 name  :  nginx 
 ``` 
 2.  **Clone GitHub Repository** 
 ```yaml 
 git  : 
 repo  :  https://github.com/mgm152002/nginx_configs.git 
 dest  :  /tmp/nginx_configs 
 ``` 
 3.  **Copy Nginx Configuration Files** 
 ```yaml 
 copy  : 
 src  :  /tmp/nginx_configs/nginx/ 
 dest  :  /etc/nginx/ 
 ``` 
 4.  **Copy Web Content (www/html/)** 
 ```yaml 
 copy  : 
 src  :  /tmp/nginx_configs/www/ 
 dest  :  /var/www/ 
 ``` 
 5.  **Ensure sites-enabled Symlinks Exist** 
 ```yaml 
 file  : 
 etc/nginx/sites-available/default     src: / 
 dest: /etc/nginx/sites-enabled/default 
 state: link 
 ``` 
 6. **Create Status Endpoint** 
 ```yaml 
 # /etc/nginx/sites-available/nginx_status 
 location /nginx_status { 
 stub_status on; 
 allow 127.0.0.1; 
 deny all; 
 } 
 ``` 
 ## Configuration Files 
 ### Main Configuration 
 -  `/etc/nginx/nginx.conf`  - Main nginx configuration  (worker processes, gzip, 
 logging) 
 ### Include Directories 
 -  `/etc/nginx/conf.d/`  - Additional configuration  snippets 
 -  `/etc/nginx/sites-available/`  - Available site configs 
 -  `/etc/nginx/sites-enabled/`  - Enabled site configs  (symlinks) 
 ### Web Content 
 -  `/var/www/html/`  - Web root directory (from www/html/) 
 -  Default document:  `index.html`  (dark-themed landing  page) 
 ### Status Endpoint 
 -  **URL**  :  `http://localhost/nginx_status` 
 -  **Purpose**  : Stub status for nginx exporter 
 ## Nginx Status Metrics 
 The  `/nginx_status`  endpoint provides: 
 | Metric | Description | 
 |--------|-------------| 
 |  `Active connections`  | Current active connections  | 
 |  `accepts`  | Total accepted connections | 
 |  `handled`  | Total handled connections | 
 |  `requests`  | Total requests | 
 |  `Reading`  | Connections in reading state | 
 |  `Writing`  | Connections in writing state | 
 |  `Waiting`  | Connections in waiting state | 
 ## Nginx Exporter Integration 
 ### Scrape URL 
 ``` 
 http://localhost/nginx_status 
 ``` 
 ### Exporter Configuration 
 ```yaml 
 nginx_exporter  : 
 -scrape-uri  :  http://localhost/nginx_status 
 listen-address  :  :9113 
 ``` 
 ### Prometheus Metrics 
 -  `nginx_http_requests_total`  - Total HTTP requests 
 -  `nginx_http_connections`  - Connection states 
 -  `nginx_connections_accepted`  - Accepted connections 
 -  `nginx_connections_handled`  - Handled connections 
 ## Port Configuration 
 | Port | Service | 
 |------|---------| 
 | 80 | HTTP | 
 | 443 | HTTPS | 
 | 8080 | Alternative HTTP | 
 ## Security 
 ### Allowed Access 
 -  `127.0.0.1`  - Localhost only for /nginx_status 
 -  `0.0.0.0/0`  - HTTP/HTTPS for web traffic 
 ### Status Endpoint Protection 
 ``` 
 location /nginx_status { 
 stub_status on; 
 access_log off; 
 allow 127.0.0.1; 
 allow ::1; 
 deny all; 
 } 
 ``` 
 ## Deployment Process 
 1.  Ansible clones configs from GitHub 
 2.  Nginx configs copied to  `/etc/nginx/` 
 3.  Web content copied to  `/var/www/` 
 4.  Sites-enabled symlinks verified/created 
 5.  Nginx configuration validated:  `nginx -t` 
 6.  Nginx restarted/reloaded 
 7.  Status endpoint available at  `/nginx_status` 
 8.  Prometheus scrapes metrics from exporter 
 ## Variables 
 | Variable | Value | Description | 
 |----------|-------|-------------| 
 |  `nginx_repo_url`  |  `https://github.com/mgm152002/nginx_configs.git`  | GitHub 
 repository | 
 |  `nginx_repo_path`  |  `nginx/`  | Subdirectory containing  configs | 
 |  `nginx_clone_dir`  |  `/tmp/nginx_configs`  | Local  clone location | 
 |  `nginx_config_path`  |  `/etc/nginx`  | System config  path | 
 |  `nginx_web_root`  |  `/var/www/html`  | Web content  root | 
 |  `nginx_status_port`  |  `80`  | HTTP port | 
 |  `nginx_status_path`  |  `/nginx_status`  | Status endpoint  | 
 ## Integration Points 
 ### Prometheus 
 -  Scrapes nginx exporter at  `:9113` 
 -  Stores metrics in time-series database 
 ### Grafana 
 -  Dashboard displays nginx metrics 
 -  Visualizes request rates, latency, errors 
 ### Monitoring Alerts 
 -  High 5xx error rate 
 -  Connection exhaustion 
 -  Request latency spikes 
 ## Configuration Details 
 ### nginx.conf (Main Configuration) 
 The main configuration file includes: 
 -  Worker process configuration 
 -  Gzip compression settings 
 -  Access and error log paths 
 -  Include directives for conf.d/ and sites-enabled/ 
 ### conf.d/default.conf 
 Catch-all default server block handling: 
 -  Default virtual host settings 
 -  Error pages 
 -  Location directives 
 ### sites-available/default 
 Virtual host configuration for example.com: 
 -  Server name: example.com 
 -  Document root: /var/www/html 
 -  Access logging 
 -  Index files 
 ### www/html/index.html 
 Dark-themed landing page served at the root URL. 