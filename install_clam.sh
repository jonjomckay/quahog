#!/bin/sh
apt-get update -qq
apt-get install -qq clamav-daemon
echo TCPSocket 3310 >> /etc/clamav/clamd.conf
sed -i'' -e "s%/var/lib/clamav%${HOME}/clamav%" /etc/clamav/*
chmod -R a+rwx ${HOME}/clamav
freshclam
rsync -arv ${HOME}/clamav /var/lib/clamav
/etc/init.d/clamav-daemon start
chmod -R a+rwx ${HOME}/clamav
