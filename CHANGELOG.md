0.1.7 (06/24/2012)
====
* Decoupled UI more from login backend
0.1.6 (06/21/2012
====
* Added the ability to log normal operations
* Log failed login attempts for the shadow-only version
0.1.5 (06/19-20/2012)
====
* Add some dialog for the cases where authentication passes, but the account is already expired
* Well, add dialog code from WICD
* Override TERM variable to be fbterm if fbterm is enabled for session
* Port to Python3
* Change FBterm background image support for main screen a little
0.1.4 (06/17/2012)
====
* Slight fix regarding framebuffer and consolekit enabling
* Some code cleanup

0.1.3 (06/16/2012)
====
* Slight fix to fbterm support
* Allow setting TERM through the wrapper that goes in inittab
* Additional fix to that detection relations

0.1.2 (06/16/2012)
====
* Try to fix detecting relations between X displays and ttys

0.1.1 (06/15/2012)
====
* Disable root login if needed
* Allow select users to only log in once
* Fix fbterm detection
* Put in that csv module import I forgot

0.1 (06/14/2012)
====
* Allow customization of session list on a per user basis. See sys.cfg for more details.
* List CLI and GUI sessions in *.csv files with the format "Name","Command".
* Autodetect available GUI sessions based on what is in /usr/share/xsessions and /etc/X11/sessions.
* PAMless authentication.
* List active sessions and switch between them.
* Configure commands for hibernate, suspend, shutdown, and restart buttons
* Color scheme configuration
* Optional FBTerm and Consolekit support
* Banner message support
* Always have a login shell command if cli.csv does not exist
