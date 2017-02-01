#!/bin/sh
apt-get update -qq
apt-get install -qq clamav-daemon
echo TCPSocket 3310 >> /etc/clamav/clamd.conf
sed -i'' -e "s%/var/lib/clamav%${HOME}/clamav%" /etc/clamav/*
freshclam
/etc/init.d/clamav-daemon start
