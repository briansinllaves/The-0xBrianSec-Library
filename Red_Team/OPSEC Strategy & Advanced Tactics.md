# Red Team OPSEC Playbook

This playbook outlines operational security (OPSEC) techniques for building and maintaining resilient red team infrastructure. It combines **host-level**, **network-level**, and **infrastructure-level** evasion strategies while layering in deception. Treat this as a **living document**—update it with new decoys, rotate domains, and refine your profiles after each engagement.

---

## Additional OPSEC Notes

* **Log Segregation**
  Push logs off-site to a dedicated SIEM or cloud storage account. This ensures that if one redirector or C2 node is compromised, logs are still preserved. It also reduces forensic artifacts left on the server itself.

* **Time-Based Blocks**
  Configure services to only allow inbound connections during engagement hours. This reduces exposure time and can confuse automated scanners that attempt connections outside those windows.

* **Port Knocking**
  Require a pre-knock sequence before sensitive ports (like SSH on 22) are opened. This helps avoid mass-scanning detection and forces an attacker/analyst to know the secret sequence before access is possible.

* **User-Agent Randomization**
  Rotate User-Agent strings per beacon or request. Sticking with a static string makes your traffic easier to fingerprint, while rotation helps blend into normal browsing patterns.

* **Certificate Pinning**
  Pin your own Certificate Authority (CA) in clients to prevent SSL/TLS interception via enterprise middleboxes. This ensures that only your issued certs are trusted by the beacon, raising the bar against defenders running transparent proxies.

---

## Deploying Decoy Web Content

Defenders and reputation services will often browse your domain to determine whether it looks malicious. To avoid getting flagged, **make the site look legitimate**.

### 1. Choose a Clean Domain & Subdomains

* Always use a clean domain name from reputable registrars, not expired or recycled ones.
* Avoid suspicious keywords (`hack`, `exploit`, `test`).
* Use enterprise-friendly terms for subdomains:

  * `telemetry.*`
  * `cdn.*`
  * `assets.*`
  * `tasks.*`
  * `mail.*`

### 2. Deploy Decoy Web Content

Make each subdomain appear as if it serves a legitimate business purpose:

| Subdomain     | Example Decoy Content                            |
| ------------- | ------------------------------------------------ |
| `telemetry.*` | JSON telemetry page or auto-refreshing dashboard |
| `cdn.*`       | CSS/JS/images, fonts, or PDFs                    |
| `assets.*`    | Public file repo or fake SharePoint/Dropbox view |
| `tasks.*`     | Swagger UI or health-check API interface         |

Practical approaches:

* Place static templates in `/var/www/html/index.html`.
* Use open-source HTML themes for dashboards.
* Fake API endpoints with `Swagger` or `GraphQL` explorers.
* WordPress installs if you want to go “full decoy.”

### 3. Avoid Reputation Engine Flagging

* Don’t use IPs already flagged by VirusTotal, Talos, etc.
* Avoid uploading malware from the same IP/domain used for C2.
* Warm up new domains for 24–48 hours before use.
* Add SEO metadata and SSL certs via Let’s Encrypt to make domains blend.

### 4. Robots.txt and Sitemap

Adding `robots.txt` and `sitemap.xml` improves legitimacy:

**robots.txt**

```bash
# /var/www/html/robots.txt
User-agent: *
Disallow: /admin/
```

**sitemap.xml**

```xml
<!-- /var/www/html/sitemap.xml -->
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://cdn.trustedsecuritysolution.com/</loc>
    <changefreq>weekly</changefreq>
  </url>
</urlset>
```

---

## IP Rotation & Anonymity

* **Scheduled IP Swaps**
  Rotate redirector IPs every 6–12 hours with cron jobs (`swap-ip.sh`).

* **VPS Pools**
  Script the creation/destruction of droplets in providers like DO or Hetzner. Rapid churn prevents defenders from easily pinning infrastructure.

* **Dynamic Public IPs**
  With Azure CLI, detach and reattach public IPs for new “clean” addresses on demand.

* **Tor Integration**
  For select outbound tasks, route traffic through Tor entry nodes or deploy hidden-service redirectors. Adds an additional anonymity layer.

---

## Automation: SSL/TLS

* **Let’s Encrypt AutoSSL**
  Automate cert issuance and renewal with Certbot.
* **Wildcard Certificates**
  Purchase from registrars like Namecheap if you need persistent wildcard coverage.
* **Placement**
  Terminate SSL either at redirectors or per VM (Nginx/Apache with auto-renew).

**Install Certbot**

```bash
sudo apt update
sudo apt install -y certbot python3-certbot-nginx
```

**Obtain & Install Certificate**

```bash
sudo certbot --nginx \
  --agree-tos \
  --non-interactive \
  --email ops@yourdomain.com \
  -d redirector.yourdomain.com
```

**Auto-Renew (Crontab)**

```bash
0 0,12 * * * root certbot renew --quiet --deploy-hook "systemctl reload nginx"
```

---

## Dual Redirector Chaining

Chaining multiple redirectors improves resilience and complicates attribution.

**Terraform Example (Redirector2 VM)**

```hcl
resource "azurerm_public_ip" "redirector2_ip" {
  name                = "redirector2-pip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
}
...
resource "azurerm_linux_virtual_machine" "redirector2" {
  name                  = "redirector02"
  location              = var.location
  ...
  size                  = "Standard_B1s"
  admin_username        = var.admin_username
  admin_password        = var.vm_password
  ...
}
```

**Firewall Rule Example**

```hcl
resource "azurerm_network_security_rule" "allow_https_r2" {
  name                        = "Allow_HTTPS_R2"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  destination_port_ranges     = ["443"]
  source_address_prefix       = "*"
  destination_address_prefix  = azurerm_public_ip.redirector2_ip.ip_address
  network_security_group_name = azurerm_network_security_group.redirector_nsg.name
}
```

**iptables Forwarding**

```bash
iptables -t nat -A PREROUTING -p tcp --dport 443 \
  -j DNAT --to-destination <redirector2_private_ip>:443
iptables -A FORWARD -p tcp -d <redirector2_private_ip> --dport 443 -j ACCEPT
```

---

## Hidden C2 Traffic Profiles

C2 traffic must look ordinary to blend with enterprise traffic.

* **Custom URI Paths:** Use random but benign-looking paths (`/api/v2/update?ver=3.1.4`).
* **User-Agent Spoofing:** Match Chrome, Edge, or Firefox UAs.
* **Chunked Transfer Encoding:** Break payloads into HTTP chunks to evade static inspection.

**Havoc Listener Config Example**

```json
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
```

---

## Anti-Scanning & Decoy Redirects

* **nginx.conf Example**

```nginx
server {
  listen 443 ssl;
  server_name *.yourdomain.com;

  location = /updates/   { proxy_pass http://taskmgr; }
  location = /portal/    { proxy_pass http://taskmgr; }
  location = /files/     { proxy_pass http://payload; }

  # Default → decoy site
  location / {
    return 302 https://decoy.yourdomain.com$request_uri;
  }
}
```

* Add `robots.txt` to block real paths but allow decoy crawling.
* Use **Fail2Ban** to automatically block IPs with scanning patterns.

---

## Tor Integration & Hidden Service

Deploying hidden services provides resilient, anonymous C2 fallback.

**Torrc Example**

```conf
HiddenServiceDir /var/lib/tor/hs_c2/
HiddenServicePort 443 127.0.0.1:40056
```

* `HiddenServiceDir`: Tor stores onion hostname here.
* `HiddenServicePort`: Maps onion port → local C2 port.

**Enable Tor**

```bash
sudo systemctl enable tor
sudo systemctl start tor
sudo cat /var/lib/tor/hs_c2/hostname
```

**SSH over Tor**

```bash
ssh -o "ProxyCommand nc -x localhost:9050 %h %p" \
  adminuser@<your_onion_address>
```

---

# Closing Notes

* Keep OPSEC **layered**: network deception (domain aging, fronting), host evasion (port knocking, time-based access), and content camouflage (decoy sites).
* Treat every engagement as an opportunity to **rotate domains**, refresh certificates, and refine traffic profiles.
* Remember: **defenders evolve quickly**—static playbooks get burned. Keep this document alive.

---

