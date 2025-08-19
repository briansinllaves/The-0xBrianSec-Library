

 Additional OPSEC Notes
    • Log Segregation: push logs off-site to SIEM or storage account
    
    • Time-based Blocks: only allow connections during engagement hours
    • Port Knocking: require pre-knock sequence before port 22 opens
    
    • User-Agent Randomization: rotate UA per beacon

    • Certificate Pinning: pin your own CA on clients to prevent MitM
    
    Keep this as your living OPSEC playbook—update with new decoys, rotate domains, and refine your profiles as needed.
    

# Deploy Decoy Web Content

Making the Site Look Legit (Avoiding Detection)
Here’s how to reduce the chance of your domain being flagged as malicious:
1. Choose a Clean Domain & Subdomains
    • Use a clean domain name from reputable registrars (not expired/abused domains).
    • Avoid sketchy words in names (hack, malware, etc.).
    • Use legit-looking terms: telemetry, cdn, assets, tasks, mail.
2. Deploy Decoy Web Content
Use legit-looking content to make each subdomain appear “normal” if browsed:
Subdomain	Example Decoy Content
telemetry.*	JSON telemetry page or auto-refreshing dashboard
cdn.*	Host CSS/JS/images, common assets like fonts or fake PDFs
assets.*	Public file repository layout, or mimic SharePoint/Dropbox
tasks.*	Swagger UI or health-check API interface (/api/health)

You can use:
    • Static templates (/var/www/html/index.html)
    • Fake pages with open-source HTML templates
    • JavaScript-based dashboards
    • WordPress if you want to go full decoy
3. Avoid Flagging by Reputational Engines
    • Don’t use IPs previously flagged by VirusTotal, Talos, etc.
    • Avoid uploading malware from known IPs/domains.
    • Don’t register the domain, then immediately do C2 — warm it up (wait ~48hrs).
    • Add basic SEO metadata and SSL certs via Let’s Encrypt.
4. Add Robots.txt and sitemap.xml

bash
Copy code
# /var/www/html/robots.txt
User-agent: *
Disallow: /admin/

xml
Copy code
<!-- /var/www/html/sitemap.xml -->
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://cdn.trustedsecuritysolution.com/</loc>
    <changefreq>weekly</changefreq>
  </url>
</urlset>

# note

• Log Segregation: push logs off-site to SIEM or storage account
• Time-based Blocks: only allow connections during engagement hours
• Port Knocking: require pre-knock sequence before port 22 opens
• User-Agent Randomization: rotate UA per beacon
• Certificate Pinning: pin your own CA on clients to prevent MitM

# IP Rotation & Anonymity

• swap-ip.sh every 6–12 hrs via cron
• VPS Pools: script create/destroy droplets on DO/Hetzner
• Azure CLI dynamic detach/attach public-IP
TOR Entry Nodes: Route select outbound tasks through Tor (hidden-service redirector)

# Automation: Let’s Encrypt

• AutoSSL with Let’s Encrypt on all public services
• Or purchase cheap wildcard certs (Namecheap)
• Terminate SSL at redirector or on each VM (Apache/Nginx + cert management)

# Install Certbot and Nginx plugin
sudo apt update
sudo apt install -y certbot python3-certbot-nginx

# Obtain & install cert for your domain
# (assumes nginx host blocks on 443)
sudo certbot --nginx \
  --agree-tos \
  --non-interactive \
  --email ops@yourdomain.com \
  -d redirector.yourdomain.com

# Auto-renewal (runs twice daily)
# Edit /etc/crontab and add:
# 0 0,12 * * * root certbot renew --quiet --deploy-hook "systemctl reload nginx"

# Dual Redirector Chaining

Yes—just drop a new file terraform/redirector2.tf alongside the others. Example:

hcl
Copy code
# Public IP for 2nd redirector
resource "azurerm_public_ip" "redirector2_ip" {
  name                = "redirector2-pip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
}
# NIC for 2nd redirector
resource "azurerm_network_interface" "redirector2_nic" {
  name                = "redirector2-nic"
  location            = var.location
  resource_group_name = var.resource_group_name
ip_configuration {
    name                          = "redirector2-ipcfg"
    subnet_id                     = azurerm_subnet.main.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.redirector2_ip.id
  }
}
# VM for 2nd redirector
resource "azurerm_linux_virtual_machine" "redirector2" {
  name                  = "redirector02"
  location              = var.location
  resource_group_name   = var.resource_group_name
  network_interface_ids = [azurerm_network_interface.redirector2_nic.id]
  size                  = "Standard_B1s"
  admin_username        = var.admin_username
  admin_password        = var.vm_password
os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "22_04-lts"
    version   = "latest"
  }
}
Then in terraform/firewalls.tf or a new redirector2-firewall.tf, allow 443 to redirector2_nic:

hcl
Copy code
# Allow HTTPS to 2nd redirector
resource "azurerm_network_security_rule" "allow_https_r2" {
  name                        = "Allow_HTTPS_R2"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["443"]
  source_address_prefix       = "*"
  destination_address_prefix  = azurerm_public_ip.redirector2_ip.ip_address
  network_security_group_name = azurerm_network_security_group.redirector_nsg.name
}
Finally, on redirector01, update your iptables to send all HTTPS to redirector2:

bash
Copy code
# On redirector01:
iptables -t nat -A PREROUTING -p tcp --dport 443 \
  -j DNAT --to-destination <redirector2_private_ip>:443
iptables -A FORWARD -p tcp -d <redirector2_private_ip> --dport 443 -j ACCEPT
Drop that file into the terraform/ folder, terraform init && terraform apply, and you’ll have dual redirector chaining.


# Hidden C2 Traffic Profiles


    • Custom URI: Use random-looking paths (e.g., /api/v2/update?ver=3.1.4)
    • User-Agent Spoofing: Mimic common browsers
    • Chunked Transfer: Hide payload in HTTP chunks
    • Example Havoc Listener Config

json

{
  "Profile": {
    "Name": "EdgeUpdate",
    "Headers": {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/90.0.0.0 Safari/537.36",
      "Accept": "*/*"
    },
    "URI": "/svc/update/v1/check"
  }
}


# Anti-Scanning & Decoy Redirects

    • nginx.conf snippet on redirector or per-VM

nginx

server {
  listen 443 ssl;
  server_name *.yourdomain.com;
# Legitimate locations
  location = /updates/   { proxy_pass http://taskmgr; }
  location = /portal/    { proxy_pass http://taskmgr; }
  location = /files/     { proxy_pass http://payload; }
# Any other path → honeypot

  location / {
    return 302 https://decoy.yourdomain.com$request_uri;
  }
}
    • Robots.txt: Disallow real paths, allow decoy.
    • Fail2Ban: Ban IPs with strange scan patterns.


# Tor Integration & Hidden Service


# /etc/tor/torrc
HiddenServiceDir /var/lib/tor/hs_c2/
HiddenServicePort 443 127.0.0.1:40056
    • HiddenServiceDir → Tor writes onion address here
    • HiddenServicePort → map onion:443 → local C2 port

# start Tor
sudo systemctl enable tor
sudo systemctl start tor
# fetch onion address
sudo cat /var/lib/tor/hs_c2/hostname
    
    • SSH over Tor:
# on your local machine
tor &                             # ensure Tor client running
    • ssh -o "ProxyCommand nc -x localhost:9050 %h %p" \
  adminuser@<your_onion_address>




