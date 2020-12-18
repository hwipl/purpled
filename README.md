# purpled

purpled is a network daemon that implements the nuqql interface and uses
[libpurple](https://developer.pidgin.im/) to connect to various
instant-messaging networks. It can be used as a backend for
[nuqql](https://github.com/hwipl/nuqql) or as a standalone chat client daemon.

## History:

purpled is a mirror/fork of the purpleD libpurple daemon:
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

* devel:
  * Add command line arguments and update argument parsing
    * Allow pushing accounts to the client
    * Allow disabling the message history
    * Add simple logging and logging level definition
  * Add welcome message and account adding help messages
  * Cleanups and fixes
* v0.5:
  * Add new commands:
    * `bye`: disconnect from purpled.
    * `quit`: quit purpled.
    * `help`: show list of commands and their description.
  * Add and use "chat msg" message format for group chat messages
  * Make "message" message format more similar to other nuqql backends.
  * Cleanups and fixes
* v0.4:
  * Add chat room messages:
    * List joined chat rooms: `account <id> chat list`
    * Join a chat room: `account <id> chat join <chat_room>`
    * Leave a chat room: `account <id> chat part <chat_room>`
    * List users in a chat room: `account <id> chat users <chat_room>`
    * Invite user to a chat room: `account <id> chat invite <chat_room> <user>`
    * Send a message to a chat room: `account <id> chat send <chat_room> <msg>`
* v0.3:
  * Add account status message
    * Set current status with: `account <id> status set <status>`
    * Get current status with: `account <id> status get`
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
