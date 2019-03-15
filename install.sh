#!/usr/bin/env bash

mkdir /etc/digitalocean-dns-updater
cp config.yml /etc/digitalocean-dns-updater
cp *.py /etc/digitalocean-dns-updater
cp dodnsupdater.service /lib/systemd/system
chmod 644 /lib/systemd/system/dodnsupdater.service
systemctl daemon-reload
systemctl enable dodnsupdater.service