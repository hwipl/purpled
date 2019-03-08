# purpleD mirror/fork

This is a mirror/fork of the purpleD libpurple daemon:
https://sourceforge.net/projects/purpled/

Summary from sf.net:
"purpled is a libpurple daemon, aimed to provide instant-messaging services to
external applications."

Original project members:
* [XcinnaY](https://sourceforge.net/u/xcinnay/)
* [driedfruit](https://sourceforge.net/u/driedfruit/)

The original code mirrored from sf.net is tagged as
["mirrored"](https://github.com/hwipl/purpled/releases/tag/mirrored). See
README for original description and INSTALL for original building information.

Later commits contain the following changes:

## Changes:
* mirrored:
  * original code from sf.net
* v0.0.1:
  * A patch from [Leandro Britez](https://sourceforge.net/u/britinx/) to show
    the (online) buddies of an account with `account ID buddies [ONLINE]`
* v0.1:
  * Support for Unix Domain Sockets/AF\_UNIX sockets; use command line
    parameter `-i` for an AF\_INET socket and `-u` for an AF\_UNIX socket
  * Changes to the messages sent from purpleD to clients: they now contain the
    "message type" to make parsing easier
* ...
