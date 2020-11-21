# rcirc

Tunnel that exposes RocketChat as an IRC server.

## Requirements

- json-c
- libwebsockets
- libuv
- openssl/libressl

OpenSUSE: `zypper install libjson-c-devel 'libwebsockets-devel>4'
libopenssl-devel libuv-devel`

## Building

    make

## Running

    ./rcirc -l <irc_port> <servername>

Then connect with IRC client, for example:

    irssi  -c localhost -p <irc_port> -w <RocketChat secret token>


