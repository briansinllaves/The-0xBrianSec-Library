#!/bin/bash
# Adding a user (equivalent to New-User in PowerShell)
sudo useradd newuser

# Listing all users
cut -d: -f1 /etc/passwd
