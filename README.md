NCDM
====
NCurses Display Manager (NCDM) is, well, a display manager written in python. It also manages commandline sessions, so display or desktop probably is not the right word for the D part of the acronym. However, it is very much in an alpha state, so if you want to test it, put it on a computer where you're fine with it making mistakes.

Features:
* Allow customization of session list on a per user basis. See sys.cfg for more details.
* List CLI and GUI sessions in *.csv files with the format "Name","Command".
* Autodetect available GUI sessions based on what is in /usr/share/xsessions and /etc/X11/sessions.
* PAMless authentication.
* List active sessions and switch between them.
* Configure commands for hibernate, suspend, shutdown, and restart buttons
* Color scheme configuration

Dependencies:
* python2-urwid
* Core python modules: crypt, spwd, pwd, grp, os, re, subprocess, platform, glob
* xorg-xinit
* xorg-sessreg
* coreutils
* kbd (for opening a virtual terminal and launching the cli session on there using openvt)

Optional dependencies:
* python2-dbus
* consolekit

Todo:
* Add a default session to the CLI section that will always launch the user's login shell
* Port to python 3 once kinks are worked out
* Register sessions programatically with python-utmp? So far the commented out code using python-utmp doesn't work (http://korpus.juls.savba.sk/~garabik/software/python-utmp/README.txt)
* Add title support
* Add custom markup support for title
* Add more places for theming?
* Remote login support? Pretty iffy.
