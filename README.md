# digitalocean-dns-updater
Linux daemon for dynamically updating DigitalOcean DNS records

- For all the folks out there who own a domain and can't point the registrar
to a nameserver because of the impossibility of getting a static IP address from their ISP 🌍

- DigitalOcean offers free DNS services 💸 and also exposes a fairly simple to use API for editing the records

- The daemon watches for changes in the server's public IP address then updates the DNS records accordingly

## Install

- Clone repo
- Run `install.sh` as `root`
- Start service with `sudo service dodnsupdater start`