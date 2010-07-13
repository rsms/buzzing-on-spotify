#!/bin/bash
cd "$(dirname $0)"

# Your Google Buzz API key and secret
BUZZ_KEY='KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK'
BUZZ_SECRET='SSSSSSSSSSSSSSSSSSSSSSS'
# Your Spotify username and password (read from a file)
SPOTIFY_USER='username'
SPOTIFY_PASSWD_FILE=spotify-updater/password
# Name of (existing) playlist in your Spotify account to be updated
SPOTIFY_PLAYLIST_NAME='Buzzing'

for f in $(python buzz-collector/main.py -k "$BUZZ_KEY" -s "$BUZZ_SECRET"); do
  spotify-updater/push2playlist \
    "$SPOTIFY_USER" "$(cat $SPOTIFY_PASSWD_FILE)" "$SPOTIFY_PLAYLIST_NAME" $f || break
done
