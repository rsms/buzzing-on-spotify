# Buzzing on Spotify

Keeps a Spotify playlist up to date with the most recently Buzzed Spotify tracks (i.e. track links posted on Google Buzz by anyone in the world).

*This is a hack by Erik Hartwig and Rasmus Andersson during the Google Spotify Hackathon July 12, 2010.*

There is a live demo running and the resulting playlist can be found and subscribed to here: ["Buzzing" http://open.spotify.com/user/rasmus/playlist/2PAIqo345bENl0XSnZU8hC](http://open.spotify.com/user/rasmus/playlist/2PAIqo345bENl0XSnZU8hC)

## Building and running

> **Be adviced:** this is a *hack*, not a polished product. It might not work at all. This has been tested and is running on Debian Linux.

You will need the folling stuff:

- An API key (and secret) for the Google Buzz API. This will get you started: [http://code.google.com/apis/buzz/](http://code.google.com/apis/buzz/)

- A Spotify premium account and an application key for libspotify. You can create an application key by signing in here: [https://developer.spotify.com/en/libspotify/application-key/](https://developer.spotify.com/en/libspotify/application-key/)

Now, it's time to setup and start the machine.

1. Download the libspotify application key as "c-code" and replace the contents of `spotify-updater/appkey.c` with the "c-code".

2. Run `make` in the `spotify-updater` directory.

3. Open `run.sh` in your favourite text editor and update the `BUZZ_*` and `SPOTIFY_*` variables with the Buzz API key and secret, and Spotify username.

4. Open `spotify-updater/password` in your text editor and replace the contents with your Spotify password (for the `SPOTIFY_USER`). Save the file and `chmod 0400 spotify-updater/password` so no one can read it but you.

5. Run `./run.sh`

If everything works (yeah, right...) you should see new tracks popping up in the playlist (when observed in a Spotify client). Status and error messages will be printed to the terminal.

## MIT license

Copyright (c) 2010 Erik Hartwig & Rasmus Andersson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
