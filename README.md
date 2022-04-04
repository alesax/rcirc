# rcirc

Tunnel that exposes RocketChat as an IRC server.

## Requirements

- json-c
- libwebsockets

OpenSUSE: `zypper install libjson-c-devel 'libwebsockets-devel>4' libopenssl-devel`

## Building

    make

## Running

    ./rcirc -l <irc_port> <servername>

Get a personal access token - in RocketChat web interface go to

Settings (your avatar in top left) -> My Account -> Personal Access Tokens

eg. https://open.rocket.chat/account/tokens

Then connect with IRC client, for example:

    irssi  -c localhost -p <irc_port> -w <RocketChat personal access token>

The user id generated together with the access token is not required.

Note: ircrc uses the PASS command which is part of the original irc protocol and rarely used today - as opposed to the modern SASL authentication which also has a usename.
