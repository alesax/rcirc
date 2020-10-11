# rcirc

Tunnel that exposes RocketChat as an IRC server.

## Requirements

json-c libwebsockets

## Building

make

## Running

./rcirc <servername>

Then connect with IRC client, for example:

irssi  -c localhost -p 6666 -w <RocketChat secret token>


