NCDM
====
NCurses Display Manager (NCDM) is, well, a display manager written in python. It also manages commandline sessions, so display or desktop probably is not the right word for the D part of the acronym. However, it is very much in an alpha state, so if you want to test it, put it on a computer where you're fine with it making mistakes.

Features:
* Disable root login if needed
* Allow select users to only log in once
* Allow customization of session list on a per user basis. See sys.cfg for more details.
* List CLI and GUI sessions in *.csv files with the format "Name","Command".
* Autodetect available GUI sessions based on what is in /usr/share/xsessions and /etc/X11/sessions.
* PAMless authentication.
* List active sessions and switch between them.
* Configure commands for hibernate, suspend, shutdown, and restart buttons
* Color scheme configuration
* Optional FBTerm and Consolekit support
* Custom banner to welcome users
* Always has an option for a login shell if cli.csv does not exist.
* Allow setting background image for NCDM if fbterm is told to be used
* Log program operation (useful for detecting bugs)

Dependencies:
* python-urwid
* Core python modules: crypt, spwd, pwd, grp, os, re, subprocess, platform, glob, csv
* xorg-xinit
* xorg-sessreg
* coreutils
* grep
* kbd (for opening a virtual terminal and launching the cli session on there using openvt)

Optional dependencies:
* python-dbus
* consolekit
* fbterm
* fbv

Todo:
* Port to python 3 once kinks are worked out.
* Register sessions programatically with python-utmp? So far the commented out code using python-utmp doesn't work (http://korpus.juls.savba.sk/~garabik/software/python-utmp/README.txt)
* Add custom markup support for banner
* Add more places for theming?
* Remote login support? Pretty iffy.
