import urwid
import re
import os
import json
import csv

from platform import uname,python_version
from subprocess import check_call, check_output, Popen, CalledProcessError, PIPE
from pwd import getpwnam, getpwall
from configparser import ConfigParser
from io import StringIO
import syslog

try:
	 import dbus
except ImportError:
	 dbus = None
if dbus is not None:
	try:
		system_bus = dbus.SystemBus()
		manager = system_bus.get_object('org.freedesktop.ConsoleKit',
									'/org/freedesktop/ConsoleKit/Manager')
		manager_iface = dbus.Interface(manager,
					dbus_interface='org.freedesktop.ConsoleKit.Manager')
	except dbus.exceptions.DBusException:
		manager = None
		manager_iface = None
else:
	manager = manager_iface = system_bus = None

from miscwidgets import SelText, TabColumns, PasswordDialog, TextDialog
from logins import WhoView
import utils
import sessions

#http://www.nicosphere.net/selectable-list-with-urwid-for-python-2542/
#note: needs to run as root

class SessionTypeItem (urwid.RadioButton):
	def __init__ (self, group, tag, name, command):
		#, on_state_change=None, user_data=None
		self.tag = tag
		#self.content = '[{}] {}'.format(tag, name[:25])
		self.command = command
		self.name = name
		self.__super.__init__(group,self.name)

class LoginDetails(urwid.Pile):
	def __init__(self, settings, greet, font):
		self.group = []
		self.gui_items = urwid.SimpleListWalker([])
		self.cli_items = urwid.SimpleListWalker([])

		#header = urwid.AttrMap(urwid.Text('selected:'), 'head')
		self.gui_listbox = urwid.ListBox(self.gui_items)
		#add widget for consolekit checkbox
		self.cli_listbox = urwid.ListBox(self.cli_items)
		#add widget for fbterm checkbox and settings
		self.fb_check=urwid.CheckBox("Enable background image", state=False)
		self.ck_check=urwid.CheckBox("Enable Consolekit", state=False)

		cli_box=urwid.Pile([urwid.BoxAdapter(self.cli_listbox, 15),
							urwid.AttrMap(self.fb_check,'body','body')])
		gui_box=urwid.Pile([urwid.BoxAdapter(self.gui_listbox, 15),
							urwid.AttrMap(self.ck_check,'body','body')])

		tabs = TabColumns([urwid.AttrWrap(SelText("GUI"), 'tab active', 'focus'),
		urwid.AttrWrap(SelText("CLI"), 'body', 'focus')],
		[urwid.Filler(gui_box),urwid.Filler(cli_box)],'Sessions')

		ulabel = urwid.Text("Username")
		plabel = urwid.Text("Password")
		utext = urwid.Edit()
		ptext = urwid.Edit(mask="*")
		ustuff = urwid.Columns([urwid.AttrWrap(ulabel,'uname'),
								urwid.AttrWrap(utext,'uname')])
		pstuff = urwid.Columns([urwid.AttrWrap(plabel,'pw'),
								urwid.AttrWrap(ptext,'pw')])
		ffont=font()
		banner = urwid.BigText(greet,ffont)
		banner = urwid.AttrWrap(banner,'banner')
		banner = urwid.Padding(banner, 'left', width='clip')
		banner = urwid.Filler(banner,height=ffont.height)

		#banner = urwid.Padding(banner,align='center')
		login_details = urwid.Pile([ustuff,pstuff,
									urwid.AttrWrap(urwid.Text("Press enter to log in"),
									'body','body')])
		#sessions_box = urwid.Pile([urwid.Text("Sessions"),
		#							urwid.BoxAdapter(listbox, 40)])
		self.__super.__init__([banner, urwid.Columns([urwid.Filler(login_details), tabs])])
		self.username=utext
		self.password=ptext
		urwid.connect_signal(utext, 'change', self.refresh_sessions, settings)
	def refresh_sessions(self, widget, uname, settings):
		del self.group[:]
		del self.gui_items[:]
		del self.cli_items[:]
		clis = settings.get_cli_sessions(uname)
		guis = settings.get_gui_sessions(uname)
		self.gui_items.extend([urwid.AttrMap(SessionTypeItem(self.group,'X'
					,s[0],s[1]),'body','focus') for s in guis])
		self.cli_items.extend([urwid.AttrMap(SessionTypeItem(self.group,'C'
					,s[0],s[1]),'body','focus') for s in clis])
		self.ck_check.set_state(settings.get_ck(uname))
		self.fb_check.set_state(settings.get_fb(uname))

	def active_session(self):
		if len(self.group) == 0:
			return None
		return [x for x in self.group if x.get_state()][0]

#http://www.comptechdoc.org/os/linux/howlinuxworks/linux_hllogin.html
#https://bugzilla.redhat.com/attachment.cgi?id=510191

def csv_to_list(f):
	csv_file=open(f)
	entries=csv.reader(csv_file)
	next(entries)
	rest=list(entries)
	csv_file.close()
	return rest

#http://stackoverflow.com/questions/2885190/using-pythons-configparser-to-read-a-file-without-section-name
def fake_head(fname):
	sio=StringIO()
	sio.write('[DEFAULT]\n')
	f=open(fname)
	contents = f.read()
	sio.write(contents)
	f.close()
	sio.seek(0)
	return sio

class NCDMConfig:
	def __init__(self):
		self.sysconf = ConfigParser()
		#/etc/ncdm/sys.cfg
		self.sysconf.readfp(fake_head('/etc/ncdm/sys.cfg'))
		self.prep_logger()
		self.default = {}
		if os.path.exists(self.sysconf.get('DEFAULT','THEME')):
			t=open(self.sysconf.get('DEFAULT','THEME'))
			self.theme=json.load(t)
			t.close()
		else:
			self.theme=[]
		self.default['CLI']=self.fill_cli('/etc/ncdm/cli.csv')
		self.default['GUI']=self.fill_gui('/etc/ncdm/gui.csv')
		self.user_confs = {}
		uid_min=int(utils.parse_login_defs()['UID_MIN'])
		uid_max=int(utils.parse_login_defs()['UID_MAX'])
		sys_uid_min=int(utils.parse_login_defs()['SYS_UID_MIN'])
		for user in getpwall():
			if uid_min <= user.pw_uid <= uid_max or user.pw_uid < sys_uid_min:
				f = os.path.join(user.pw_dir,'.config/ncdm')
				self.user_confs[user.pw_name]={}
				if os.path.exists(f):
					self.user_confs[user.pw_name]['CLI'] = \
						self.fill_cli(os.path.join(f,'cli.csv'))
					self.user_confs[user.pw_name]['GUI'] = \
						self.fill_gui(os.path.join(f,'gui.csv'))
					self.user_confs[user.pw_name]['conf'] = ConfigParser()
					self.user_confs[user.pw_name]['conf'].readfp(fake_head(os.path.join(f,'usr.cfg')))
				else:
					self.user_confs[user.pw_name]['CLI'] = \
						self.default['CLI']
					self.user_confs[user.pw_name]['GUI'] = \
						self.default['GUI']
					self.user_confs[user.pw_name]['conf'] = self.sysconf
	def prep_logger(self):
		self.logme = self.sysconf.getboolean('DEFAULT','LOG',fallback=True)
		if not self.logme:
			self.log=None
			return
		import logging
		self.logging=logging
		os.sys.excepthook=self.log_exception
		self.log = logging.getLogger("ncdm")
		fhnd = logging.FileHandler('/var/log/ncdm.log')
		formatter = logging.Formatter('[%(asctime)s - %(levelname)s] - %(message)s')
		fhnd.setFormatter(formatter)
		lvl = self.sysconf.get('DEFAULT','LOGLVL',fallback='WARNING')
		self.log.addHandler(fhnd)
		lvln=getattr(logging,lvl,logging.WARNING)
		if not isinstance(lvln,int):
			syslog.syslog(syslog.INFO,("Specified warning level isn't "
						"valid, forcing it to be warning"))
			lvln=logging.WARNING
		self.log.setLevel(lvln)

	def get_fbimg(self, uname):
		confy = self.user_confs.get(uname,{}).get('conf',self.sysconf)
		return confy.get('DEFAULT','FBIMG',fallback='')

	def get_ck(self, uname):
		confy = self.user_confs.get(uname,{}).get('conf',self.sysconf)
		return confy.getboolean('DEFAULT', 'CONSOLEKIT',fallback=False)

	def get_fb(self, uname):
		confy = self.user_confs.get(uname,{}).get('conf',self.sysconf)
		return confy.getboolean('DEFAULT', 'FBTERM',fallback=False)

	def get_cli_sessions(self, uname):
		if not uname in self.user_confs.keys():
			return []
		return self.user_confs.get(uname,{}).get('CLI', [])

	def get_gui_sessions(self, uname):
		if not uname in self.user_confs.keys():
			return []
		return self.user_confs.get(uname,{}).get('GUI', [])

	def log_exception(self, *args):
		self.log.critical("CRITICAL:",exc_info=args)

	def let_root(self):
		return self.sysconf.getboolean('DEFAULT','ALLOW_ROOT',fallback=True)

	def greeter_msg(self):
		kname,node,kver,kdate,_,_=uname()
		fullos=check_output(['uname','-o']).decode(os.sys.getdefaultencoding())[:-1]
		pyver=python_version()
		return self.sysconf.get('DEFAULT','WELCOME',
				fallback="{kname}@{node} - Python {pyver}").format(**locals())

	def login_once(self):
		return self.sysconf.get('DEFAULT','LOGIN_ONCE',
					fallback='').split(':')

	def greeter_font(self):
		return [f for f in urwid.get_all_fonts() if \
				f[0] == self.sysconf.get('DEFAULT','FONT',
				fallback='Thin 6x6')][0][1]

	def fill_cli(self, f):
		if os.path.exists(f):
			return csv_to_list(f)
		else:
			return [("Login shell","")]

	def fill_gui(self, f):
		if os.path.exists(f):
			return csv_to_list(f)
		else:
			return utils.get_gui_sessions()

'''
this forks two times, one for running a process
dedicated to stopping sessions started by it, and
another for launching the process
'''

class NCDMInstance(object):
	def __init__(self):
		self.settings = NCDMConfig()

	def get_logins(self):
		out = check_output(['who']).decode(os.sys.getdefaultencoding()).split('\n')[:-1]
		return [w for w in out if re.findall('([a-z][-a-z0-9]*)[ ]*((?:tty|:)[0-9]*)',w)]

	def get_xinit(self, usr, cmd):
		usrxinit = os.path.join(usr.pw_dir,'.xinitrc')
		sysxinit = '/etc/X11/xinitrc'
		if os.path.exists(usrxinit):
			return "{} {}".format(usrxinit, cmd)
		elif os.path.exists(sysxinit):
			return "{} {}".format(sysxinit, cmd)
		else:
			return cmd

	def login(self, username, password, session, ck, fb, img):
		syslog.openlog('ncdm', syslog.LOG_PID, syslog.LOG_AUTH)
		if username == "":
			self.put_message("Cannot login! Missing username...")
			return
		if username == getpwnam(username).pw_uid == 0 \
		and not self.settings.let_root():
			self.put_message("Root login is forbidden!")
			syslog.syslog(syslog.LOG_CRIT, ("Failed login attempt as user"
						" {} occured (root forbidden)").format(username))
			return
		if username in self.settings.login_once():
			entries = self.get_logins()
			my_entries = [ s for s in entries if re.match(username,s) ]
			if my_entries:
				self.put_message(("Sorry, {}, you're already logged in."
							"\nLook at the active sessions"
							" panel for your session").format(username))
				syslog.syslog(syslog.LOG_WARNING,
					("Failed login attempt as user {} occured"
					" (attempted to log in multiple times)").format(username))
				return
		self.put_message("Authenticating login...")

		if sessions.check_pw(username,password):
			msgs,retcode=sessions.check_avail(username)
			if retcode > 1:
				statusbar.set_text(msgs)
				self.put_notification(msgs,"Account Expired")	
				syslog.syslog(syslog.LOG_NOTICE,
					("Failed login attempt as user {} occured"
					" (account expired)").format(username))
				return
			if retcode == 1:
				self.put_notification(msgs,"Password change required")
				self.change_password(username)
				#check here for root login and bail out if needed
				#check here for other existing login and switch out
				return
			if retcode == 0 and len(msgs) > 0:
				self.put_notification(msgs,"Notifications")	
			if session is None:
				self.put_message("Login is correct, but there are no valid sessions")
				syslog.syslog(syslog.LOG_INFO, ("Failed login attempt as user {}"
					" occured (no valid sessions)").format(username))
				return
			next_console=check_output(['fgconsole','-n']).decode(os.sys.getdefaultencoding())[:-1]
			self.put_message(("Initializing session "
			"on console {}...").format(next_console))
			#now, use the C or X tags to complete the login
			if len(session.tag) > 0 and session.tag in "CX":
				pid = os.fork()
				if pid == 0:
					#separate from parent
					os.setsid()
					if session.tag == 'C':
						self.cli_session(username,next_console,session.command,fb,img)
						#kill the daemon process that launched these in here
					elif session.tag == 'X':
						self.gui_session(username,next_console,session.command,ck)
						#kill the daemon process that launched these in here
					else:
						os._exit(1)
						#invalid tag
				else:
					syslog.syslog(syslog.LOG_INFO, ("Login attempt as user {}"
						" succeeded, launching their session now").format(username))
					'''
					ran = os.waitpid(pid,os.P_NOWAIT)
					if ran == pid:
						statusbar.set_text("Login command succeeded")
					else:
						statusbar.set_text("Login command failed")
					'''
			else:
				self.put_message('Invalid session tag {}'.format(session.tag))
				syslog.syslog(syslog.LOG_INFO, ("Failed login attempt as user {}"
					" occured (tried to launch an invalid session)").format(username))
		else:
			self.put_message("Login details are incorrect")
			syslog.syslog(syslog.LOG_INFO, ("Failed login attempt as user {}"
						" occured (wrong login details given)").format(username))
	
	def gui_session(self,username,tty,cmd,ck):
		ttytxt='tty{}'.format(tty)
		if self.settings.logme:
			self.settings.log.info("Preparing {}'s default environment".format(username))
		usr,env=utils.make_child_env(username)
		if self.settings.logme:
			self.settings.log.info("Checking for next available X display")
		new_d=":{}".format(utils.next_x())
		if self.settings.logme:
			self.settings.log.info("Found display {} for using".format(new_d))
		env['DISPLAY']=new_d #we need this only for sessreg purposes
		env['TERM']='xterm'
		check_failed=False
		cookie=''
		if ck:
			if None in (dbus,manager,manager_iface):
				if self.settings.logme:
					self.settings.log.warning(("Unable to connect to ConsoleKit,"
										" disabling consolekit..."))
				check_failed=True
		if not check_failed and ck:
			#open a consolekit sessio
			if self.settings.logme:
				self.settings.log.info("Launching consolekit session for {} on {}".format(username, new_d))
			cookie = manager_iface.OpenSessionWithParameters([
				('unix-user',usr.pw_uid),
				('x11-display',new_d),
				('x11-display-device',os.path.join('/dev',ttytxt)),
				('is-local',True),
				('display-device','')
				])
			env['XDG_SESSION_COOKIE']=cookie
		#let startx handle making the authority file
		totalcmd='startx {} -- {}'.format(self.get_xinit(usr,cmd),new_d).strip()
		if self.settings.logme:
			self.settings.log.info("Launching {} for {} on {} using {}"\
						.format(totalcmd, username, new_d, usr.pw_shell))
		#check_call(['startx','/etc/X11/xinitrc',
		pid = os.fork()
		if pid == 0:
			os.setsid()
			#do a check for consolekit goodiness
			with open(os.devnull, 'rb') as shutup:
				login_prs=Popen([usr.pw_shell,'--login','-c',totalcmd],
							cwd=usr.pw_dir, env=env, close_fds=True,
							stdout=shutup,stderr=shutup,
							preexec_fn=utils.drop_privs(username))
				if self.settings.logme:
					self.settings.log.debug("Waiting for process to finish")
				login_prs.wait()
				if self.settings.logme:
					self.settings.log.debug("Finished with {}".format(login_prs.returncode))
				os._exit(login_prs.returncode)
		else:
			#this'll be called after the process is done
			#register here since we have the PID
			if self.settings.logme:
				self.settings.log.info("Registering session "
							"for {} on {}".format(username, new_d))
			success=sessions.register_session(username,new_d)
			if self.settings.logme and not success:
				self.settings.log.error(("Unable to register session for {} on {},"
					" active logins display won't work as expected").format(username,new_d))
			#add_utmp_entry(username, new_d, spid)
			status=os.waitpid(pid,os.P_WAIT)[1]
			if not check_failed and ck:
				if self.settings.logme:
					self.settings.log.info("Cleaning up consolekit "
						"session for {} on {}".format(username, new_d))
				closed = manager_iface.CloseSession(cookie)
				del env['XDG_SESSION_COOKIE']
			#remove_utmp_entry(new_d)
			if self.settings.logme:
				self.settings.log.info("Deregistering session "
							"for {} on {}".format(username, new_d))
			success=sessions.delete_session(username,new_d)
			if self.settings.logme:
				if not success:
					self.settings.log.error(("Unable to deregister session for {} on {},"
						" active logins display won't work as expected").format(username,new_d))
				self.settings.log.debug("Exiting watcher process for {} on {}".format(username,new_d))	
			os._exit(status)
	
	def cli_session(self,username,tty,cmd,fb,img):
		ttytxt='tty{}'.format(tty)
		if self.settings.logme:
			self.settings.log.info("Preparing {}'s default environment".format(username))
		usr,env=utils.make_child_env(username)
		if self.settings.logme:
			self.settings.log.info("Preparing {} for {}".format(ttytxt,username))
		utils.prepare_tty(username,tty)
		pid = os.fork()
		if pid == 0:
			os.setsid()
			#do a check for fbterm goodiness
			check_failed=False
			if fb:
				try:
					check_call(['which','fbterm'])
				except CalledProcessError as e:
					if self.settings.logme:
						self.settings.log.warning(('Unable to find fbterm,'
									' disabling fbterm support'))
					check_failed=True
	
				try:
					check_call(['which','fbv'])
				except CalledProcessError as e:
					if self.settings.logme:
						self.settings.log.warning(('Unable to find fbv,'
									' disabling fbterm support'))
					check_failed=True
	
				try:
					check_call(['which','fbterm-bi'])
				except CalledProcessError:
					if self.settings.logme:
						self.settings.log.warning(('Unable to find fbterm-bi,'
									' disabling fbterm support'))
					check_failed=True
	
				if not check_failed:
					check_failed=not os.path.exists(img)
			if not fb or check_failed:
				totalcmd="openvt -ws -- {}".format(cmd).strip()
			else:
				env['TERM']='fbterm'
				#override TERM variable if fbterm support is officially enabled
				totalcmd="openvt -ws -- fbterm-bi {} {}".format(img,cmd).strip()
			if self.settings.logme:
				self.settings.log.info("Launching {} for {} on {} using {}"\
							.format(totalcmd, username, ttytxt, usr.pw_shell))
			#don't clutter the UI with output from what we launched
			#http://dslinux.gits.kiev.ua/trunk/user/console-tools/src/vttools/openvt.c
			with open(os.devnull, 'rb') as shutup:
				login_prs=Popen([usr.pw_shell,'--login','-c',totalcmd],
								env=env,cwd=usr.pw_dir,close_fds=True,
								stdout=shutup,stderr=shutup,
								preexec_fn=utils.drop_privs(username))
				if self.settings.logme:
					self.settings.log.debug("Waiting for process to finish")
				login_prs.wait()
				if self.settings.logme:
					self.settings.log.debug("Finished with {}".format(login_prs.returncode))
				#we need to wait for this to finish to log the entry properly
				#this'll be called after the process is done
				os._exit(login_prs.returncode)
		else:
			if self.settings.logme:
				self.settings.log.info(("Registering session"
								" for {} on {}").format(username, ttytxt))
			success = sessions.register_session(username,ttytxt)
			if self.settings.logme and not success:
				self.settings.log.error(("Unable to register session for {} on {},"
									" active logins display won't work as expected").format(username,ttytxt))			
			#register now that we have the PID
			status=os.waitpid(pid,os.P_WAIT)[1]
			if self.settings.logme:
				self.settings.log.debug("Restoring tty ownership")
			utils.restore_tty(tty)
			if self.settings.logme:
				self.settings.log.info("Deregistering session "
									"for {} on {}".format(username, ttytxt))
			success = sessions.delete_session(username,ttytxt)
			if self.settings.logme:
				if not success:
					self.settings.log.error(("Unable to deregister session for {} on {},"
						" active logins display won't work as expected").format(username,ttytxt))
				self.settings.log.debug("Exiting watcher process for {} on {}".format(username,ttytxt))	
			os._exit(status)

	def put_message(self, msg):
		print(msg)

	def put_notification(self, msg, title):
		print(title)
		print(msg)

	def ask_pw_prompt(self, prompt):
		if raw_input(prompt):
			return -1,'',''
		else:
			from getpass import getpass
			pw1 = getpass("Password: ")
			pw2 = getpass("Password again: ")
			return 0,pw1,pw2

	def ask_pw(self, first=True):
		if first:
			return self.ask_pw_prompt("Change your password")
		else:
			return self.ask_pw_prompt("Change your password (last attempt failed)")

	def change_password(self, username):
		data = self.ask_pw()
		if data[0] != 0:
			self.put_message("Didn't change your password...")
			syslog.syslog(syslog.LOG_INFO,
			("User {} didn't change his/her password"
			", rejecting login").format(username))
			return
		while data[1] != data[2]:
			data = self.ask_pw(first=False)
			if data[0] != 0:
				self.put_message("Didn't change your password...")
				syslog.syslog(syslog.LOG_INFO,
				("User {} didn't change his/her password"
				", rejecting login").format(username))
				return

		self.put_message("Changing password...")
		with open(os.devnull, 'rb') as shutup:
			chpw_prs=Popen(['passwd',username],
					stdin=PIPE,stdout=shutup,stderr=shutup)
			chpw_prs.communicate(((data[1]+'\n')*2)\
								.encode(os.sys.getdefaultencoding()))
		if chpw_prs.returncode > 0:
			self.put_message("Password change failed...")
			syslog.syslog(syslog.LOG_INFO,
			("User {} tried to change his/her password, but it failed").format(username))
		else:
			self.put_message("Done! Login with your new password!")
			syslog.syslog(syslog.LOG_INFO,
			("User {} changed his/her password").format(username))

	def power(self, ptype):
		if ptype.upper() not in ("HIBERNATE","SHUTDOWN","SUSPEND","REBOOT"):
			self.put_message(("Invalid power management"
					" type specified: {}").format(ptype))
			return
		pcmd = self.settings.sysconf.get('DEFAULT',ptype.upper(),fallback='/bin/true')
		self.put_message("Doing {} now...".format(ptype.lower()))
		with open(os.devnull, 'rb') as shutup:
			check_call([pcmd], close_fds=True, 
				stdout=shutup, stderr=shutup)

class NCDMGui(NCDMInstance, urwid.WidgetWrap):
	def __init__(self):
		NCDMInstance.__init__(self)
		self.screen = urwid.raw_display.Screen()
		self.login_sel = LoginDetails(self.settings, 
					self.settings.greeter_msg(), 
					self.settings.greeter_font())
		self.asessions_box = WhoView()
	
		sd_button = urwid.Button("Shutdown",on_press=self.power_button)
		rbt_button = urwid.Button("Reboot",on_press=self.power_button)
		hb_button = urwid.Button("Hibernate",on_press=self.power_button)
		sp_button = urwid.Button("Suspend",on_press=self.power_button)
		button_box = urwid.GridFlow([urwid.AttrWrap(sd_button,'button','btnfocus'),
					urwid.AttrWrap(rbt_button,'button','btnfocus'),
					urwid.AttrWrap(hb_button,'button','btnfocus'),
					urwid.AttrWrap(sp_button,'button','btnfocus')], 
					14, 0, 0, 'center')
		
		self.statusbar = urwid.Text("")
		footer = urwid.Pile([button_box,urwid.AttrWrap(self.statusbar,'statusbar','statusbar')])
		#http://lists.excess.org/pipermail/urwid/2008-November/000590.html
		tabs = TabColumns([urwid.AttrWrap(SelText("Login"), 'tab active', 'focus'),
				urwid.AttrWrap(SelText("Active Sessions"), 'body', 'focus')],
				[self.login_sel,self.asessions_box],'NCurses Display Manager')
		view = urwid.Frame(body=tabs, footer=footer)
		urwid.WidgetWrap.__init__(self,view)
	
	def run(self):
		loop = urwid.MainLoop(interface, screen=self.screen, 
			palette=self.settings.theme, 
			unhandled_input=self.keystroke)
		loop.run()

	def ask_pw_prompt(self, prompt):
		max_w,max_h=self.screen.get_cols_rows()
		d = PasswordDialog(prompt,max_h/2,max_w/2)
		return d.run(self.screen,self._w)

	def get_logins(self):
		self.asessions_box.who_list.body.refresh()
		return self.asessions_box.who_list.body.entries

	def put_message(self, msg):
		self.statusbar.set_text(msg)
	
	def put_notification(self, title, msg):
		max_w,max_h=self.screen.get_cols_rows()
		d = TextDialog(msg,max_h/2,max_w/2,header=title)
		d.run(self.screen,self._w)

	def keystroke (self, key):
		if key in ('q', 'Q'):
			if self.settings.log is not None:
				self.settings.logging.shutdown()
				#this is perfectly normal since this is the 
				#only exception that properly closes the program
			raise urwid.ExitMainLoop()

		if key in ('tab', 'shift tab'):
			focus = self._w.get_focus()
			if focus == 'body':
				self._w.set_focus('footer')
			else:
				self._w.set_focus('body')

		if key is 'enter' and self._w.get_focus() == 'body':
			panel = self._w.body.tab_map[self._w.body.active_tab]
			if panel is self.login_sel:
				active_session=self.login_sel.active_session()
				img=self.settings.get_fbimg(self.login_sel.username.edit_text)
				self.login(self.login_sel.username.edit_text,
					self.login_sel.password.edit_text,
					active_session, self.login_sel.ck_check.state,
					self.login_sel.fb_check.state, img)
				#statusbar.set_text("")
				self.login_sel.username.edit_text=""
				self.login_sel.password.edit_text=""
			elif panel is self.asessions_box:
				self.active_session=self.asessions_box.who_list.get_focus()[0]
				try:
					check_call(['chvt',str(self.active_session.tty)])
				except Exception as e:
					self.put_message(str(e.message))

	def power_button(self,button):
		self.power(button.label.lower())

if __name__ == '__main__':
	interface = NCDMGui()
	interface.run()
