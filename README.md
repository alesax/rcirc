# rcirc

Tunnel that exposes RocketChat as an IRC server.

## Requirements

json-c libwebsockets

## Building

    make

## Running

    ./rcirc -p <irc_port> <servername>

Then connect with IRC client, for example:

    irssi  -c localhost -p <irc_port> -w <RocketChat secret token>


