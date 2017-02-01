#!/bin/sh
apt-get update -qq
apt-get install -qq clamav-daemon
echo TCPSocket 3310 >> /etc/clamav/clamd.conf
echo User travis >> /etc/clamav/clamd.conf
cat /etc/clamav/clamd.conf
freshclam
/etc/init.d/clamav-daemon start
