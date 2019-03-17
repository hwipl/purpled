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

Later commits contain the changes described in the "Changes" section.

## Installation:

You can install purpled with the following steps:

* Download [purpled](https://github.com/hwipl/purpled)
* Build and install purpled with:
  * `meson builddir`
  * `ninja -C builddir install`

Note: these steps require the [meson](https://mesonbuild.com/) build system.
In case you want to use the old Makefiles etc., you can find them in the `orig`
directory.

## Changes:
* v0.2:
  * Switched to meson and made purpled installable with it. Old Makefiles etc.
    are in folder `orig`.
  * Message format updates: made `account list` reply easier to parse. Added
    more CR/LF message terminations. Introduced `info:` and `error:` message
    types.
  * Introduced command line parameter to specify working directory.
* v0.1:
  * Support for Unix Domain Sockets/AF\_UNIX sockets; use command line
    parameter `-i` for an AF\_INET socket and `-u` for an AF\_UNIX socket
  * Changes to the messages sent from purpleD to clients to make parsing
    easier: they now contain the "message type" and use CR/LF to mark the end
    of messages
  * A meson.build file
* v0.0.1:
  * A patch from [Leandro Britez](https://sourceforge.net/u/britinx/) to show
    the (online) buddies of an account with `account ID buddies [ONLINE]`
* mirrored:
  * original code from sf.net
