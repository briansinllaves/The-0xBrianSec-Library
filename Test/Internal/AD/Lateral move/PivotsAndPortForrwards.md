

### SSH Tunneling

Note: Target must have SSH running for there service

1. Create SSH Tunnel: `ssh -D localhost:<local port> -f -N user@localhost -p <Target Port>`
2. Setup ProxyChains. Edit the following config file (/etc/proxychains.conf)
3. Add the following line into the config: `Socks5 127.0.0.1 <Local Port>`
4. Run commands through the tunnel: `proxychains <command>`


netsh local port forwarding:
```
netsh interface portproxy add v4tov4 listenaddress=10.1.1.1 listenport:4444 connectaddress:10.1.1.1 connectport:3306
netsh advfirewall firewall add rule ne="4444_to_3306" protocol=TCP dir=in localip=127.0.0.1 localport=3306 action=allow
```


### netsh port forwarding
```
netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=9000 connectaddress=192.168.0.10 connectport=80
netsh interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport=9000
```

---

---

### Dymanic Port Forwarding

`ssh -N -D 127.0.0.1:1337 user@remotehost -p 22222`

- The `-D` means dynic. The `1337` is the port you proxy traffic through. With this you can setup a Socks proxy on your local machine to send traffic to port `1337`, thus said traffic will be sent through that port, and then through the remote host. `-N` is optional, it means do not execute a remote command. Specifying `127.0.0.1` is also optional. It'll default to `127.0.0.1`.


---

### Port Forwarding

**Local port forwarding**

`ssh -N -L 0.0.0.0:4455:10.1.1.1:445 user@remotehost`

or

`ssh -L 8080:localhost:8080 user@remotehost`

The -L stands for local. First 8080 is port of your machine, 2nd 8080 is port of remote machine (doesn't have to be the same port). After successful ssh connection, if you request localhost:8080 (like from your browser, if you're trying to access a localling listening web server on the remote machine) that request will be send through that ssh tunnel to that remote host and you will be able to connect to that remote service. 
In other words, what this tunnel does is whatever request you sent to your localhost it will be forwarded to remote localhost.

**Remote port forwarding**
- `ssh -N -R 10.10.1.1:4455:127.0.0.1:445 attacker@10.10.1.1`

**Socks5 with SSH**
- `ssh -N -D 127.0.0.1:8888 admin@10.1.1.1`

---
