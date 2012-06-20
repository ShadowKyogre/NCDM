import urwid
import re
import os
import glob
import json
import csv

from platform import uname,python_version
from subprocess import check_call, check_output, Popen, CalledProcessError, PIPE
from pwd import getpwnam, getpwall
from grp import getgrnam
from configparser import ConfigParser
from io import StringIO

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
		clis = settings.user_confs.get(uname,{}).get('CLI', [])
		guis = settings.user_confs.get(uname,{}).get('GUI', [])
		self.gui_items.extend([urwid.AttrMap(SessionTypeItem(self.group,'X'
								,s[0],s[1]),'body','focus') for s in guis])
		self.cli_items.extend([urwid.AttrMap(SessionTypeItem(self.group,'C'
								,s[0],s[1]),'body','focus') for s in clis])
		confy = settings.user_confs.get(uname,{}).get('conf',settings.sysconf)
		if confy.has_option('DEFAULT', 'CONSOLEKIT'):
			self.ck_check.set_state(confy.getboolean('DEFAULT', 'CONSOLEKIT'))
		else:
			self.ck_check.set_state(False)
		if confy.has_option('DEFAULT', 'FBTERM'):
			self.fb_check.set_state(confy.getboolean('DEFAULT', 'FBTERM'))
		else:
			self.fb_check.set_state(False)

	def active_session(self):
		if len(self.group) == 0:
			return None
		return [x for x in self.group if x.get_state()][0]

#http://www.comptechdoc.org/os/linux/howlinuxworks/linux_hllogin.html
#https://bugzilla.redhat.com/attachment.cgi?id=510191

__ld_line = re.compile(r'^[ \t]*'	  # Initial whitespace
					   r'([^ \t]+)'	# Variable name
					   r'[ \t][ \t"]*' # Separator - yes, may have multiple "s
					   r'(([^"]*)".*'  # Value, case 1 - terminated by "
					   r'|([^"]*\S)?\s*' # Value, case 2 - only drop trailing \s
					   r')$')

def parse_login_defs():
	res = {}
	with open('/etc/login.defs') as f:
		for line in f:
			match = __ld_line.match(line)
			if match is not None:
				name = match.group(1)
				if name.startswith('#'):
					continue
				value = match.group(3)
				if value is None:
					value = match.group(4)
					if value is None:
						value = ''
				res[name] = value # Override previous definition
	return res

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
		uid_min=int(parse_login_defs()['UID_MIN'])
		uid_max=int(parse_login_defs()['UID_MAX'])
		sys_uid_min=int(parse_login_defs()['SYS_UID_MIN'])
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

	def let_root(self):
		return self.sysconf.getboolean('DEFAULT','ALLOW_ROOT')

	def greeter_msg(self):
		kname,node,kver,kdate,_,_=uname()
		fullos=check_output(['uname','-o']).decode(os.sys.getdefaultencoding())[:-1]
		pyver=python_version()
		return self.sysconf.get('DEFAULT',
					'WELCOME').format(**locals())

	def login_once(self):
		return self.sysconf.get('DEFAULT','LOGIN_ONCE').split(':')

	def greeter_font(self):
		return [f for f in urwid.get_all_fonts() if \
				f[0] == self.sysconf.get('DEFAULT','FONT')][0][1]

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

def make_child_env(username):
	usr = getpwnam(username)
	env = {}
	env['HOME']=usr.pw_dir
	env['PWD']=usr.pw_dir
	# let the wrapper handle setting TERM
	env['SHELL']=usr.pw_shell
	env['LOGNAME']=usr.pw_name
	env['USER']=usr.pw_name
	env['PATH']=os.getenv('PATH')
	env['TERM']=os.getenv('TERM')
	#http://groups.google.com/group/alt.os.linux.debian/browse_thread/thread/1b5ec66456373b99
	env['MAIL']=os.path.join(parse_login_defs().get('MAIL_DIR'),usr.pw_name)
	#XAUTHORITY and DISPLAY are X dependent!
	return usr,env

def drop_privs(username):
	#we only want to temporarily drop the priveleges
	#http://comments.gmane.org/gmane.comp.web.paste.user/1641
	#http://stackoverflow.com/questions/1770209/run-child-processes-as-different-user-from-a-long-running-process
	def result():
		usr = getpwnam(username)
		os.initgroups(username,usr.pw_gid)
		os.setgid(usr.pw_gid)
		os.setuid(usr.pw_uid)
	return result

def prepare_tty(username,n):
	ttypath=os.path.join("/dev","tty{}".format(n))
	os.chown(ttypath, getpwnam(username).pw_uid, getgrnam('tty').gr_gid)

def restore_tty(n):
	prepare_tty('root',n)

def gui_session(username,tty,cmd,ck):
	ttytxt='tty{}'.format(tty)
	usr,env=make_child_env(username)
	active_xs=glob.glob('/tmp/.X*-lock')
	if len(active_xs) > 0:
		last_d=os.path.basename(active_xs[0]).replace('-lock','')[2:]
	else:
		last_d=-1
	new_d=":{}".format(int(last_d)+1)
	env['DISPLAY']=new_d #we need this only for sessreg purposes
	env['TERM']='xterm'
	check_failed=False
	cookie=''
	if ck:
		if None in (dbus,manager,manager_iface):
			check_failed=True
	if not check_failed and ck:
		#open a consolekit session
		cookie = manager_iface.OpenSessionWithParameters([
			('unix-user',usr.pw_uid),
			('x11-display',new_d),
			('x11-display-device',os.path.join('/dev',ttytxt)),
			('is-local',True),
			('display-device','')
			])
		env['XDG_SESSION_COOKIE']=cookie
	#let startx handle making the authority file
	totalcmd='startx {} -- {}'.format(cmd,new_d).strip()
	#check_call(['startx','/etc/X11/xinitrc',
	pid = os.fork()
	if pid == 0:
		os.setsid()
		#do a check for consolekit goodiness
		with open(os.devnull, 'rb') as shutup:
			login_prs=Popen([usr.pw_shell,'--login','-c',totalcmd],
						cwd=usr.pw_dir, env=env, close_fds=True,
						stdout=shutup,stderr=shutup,
						preexec_fn=drop_privs(username))
			login_prs.wait()
			os._exit(login_prs.returncode)
	else:
		#this'll be called after the process is done
		#register here since we have the PID
		sessions.register_session(username,new_d)
		#add_utmp_entry(username, new_d, spid)
		status=os.waitpid(pid,os.P_WAIT)[1]
		if not check_failed and ck:
			closed = manager_iface.CloseSession(cookie)
			del env['XDG_SESSION_COOKIE']
		#remove_utmp_entry(new_d)
		sessions.delete_session(username,new_d)
		os._exit(status)

def cli_session(username,tty,cmd,fb,img):
	ttytxt='tty{}'.format(tty)
	usr,env=make_child_env(username)
	prepare_tty(username,tty)
	pid = os.fork()
	if pid == 0:
		os.setsid()
		#do a check for fbterm goodiness
		check_failed=False
		if fb:
			try:
				check_call(['which','fbterm'])
			except CalledProcessError as e:
				check_failed=True

			try:
				check_call(['which','fbv'])
			except CalledProcessError as e:
				check_failed=True

			try:
				check_call(['which','fbterm-bi'])
			except CalledProcessError:
				check_failed=True

			if not check_failed:
				check_failed=not os.path.exists(img)
		if not fb or check_failed:
			totalcmd="openvt -ws -- {}".format(cmd).strip()
		else:
			env['TERM']='fbterm'
			#override TERM variable if fbterm support is officially enabled
			totalcmd="openvt -ws -- fbterm-bi {} {}".format(img,cmd).strip()
		#print("Launching {} for {} on {} - {}".format(totalcmd, username, ttytxt, usr.pw_shell))
		#don't clutter the UI with output from what we launched
		#http://dslinux.gits.kiev.ua/trunk/user/console-tools/src/vttools/openvt.c
		with open(os.devnull, 'rb') as shutup:
			login_prs=Popen([usr.pw_shell,'--login','-c',totalcmd],
							env=env,cwd=usr.pw_dir,close_fds=True,
							stdout=shutup,stderr=shutup,
							preexec_fn=drop_privs(username))
			#print("Waiting for process to finish")
			login_prs.wait()
			#print("Finished with {}".format(login_prs.returncode))
			#we need to wait for this to finish to log the entry properly
			#this'll be called after the process is done
			os._exit(login_prs.returncode)
	else:
		sessions.register_session(username,ttytxt)
		#register now that we have the PID
		#print("Registering session for {} on {}".format(username, ttytxt))
		status=os.waitpid(pid,os.P_WAIT)[1]
		#print("Child finished")
		#print("Restoring priveleges")
		restore_tty(tty)
		#print("Restoring tty ownership")
		sessions.delete_session(username,ttytxt)
		#print("Deregistering session for {} on {}".format(username, ttytxt))
		os._exit(status)

def main ():
	settings = NCDMConfig()
	def login(username, password, session, ck, fb, img):
		if username == 'root' and not settings.let_root():
			statusbar.set_text("Root login is forbidden!")
			return
		if username in settings.login_once():
			asessions_box.who_list.body.refresh()
			entries = asessions_box.who_list.body.entries
			my_entries = [ s for s in entries if re.match(username,s) ]
			if my_entries:
				statusbar.set_text(("Sorry, {}, you're already logged in."
							"\nLook at the active sessions"
							" panel for your session").format(username))
				return
		statusbar.set_text("Authenticating login...")

		if sessions.check_pw(username,password):
			msgs,retcode=sessions.check_avail(username)
			if retcode > 1:
				statusbar.set_text(msgs)
				d = TextDialog(msgs,max_h/2,max_w/2,header="Account Expired")
				d.run(loop.screen,view)
				return
			if retcode == 1:
				max_w,max_h=loop.screen.get_cols_rows()
				d = TextDialog(msgs,max_h/2,max_w/2,header="Password change required")
				d.run(loop.screen,view)
				d = PasswordDialog("Change your password",max_h/2,max_w/2)
				data = d.run(loop.screen,view)
				if data[0] != 0:
					return
				while data[1] != data[2]:
					d = PasswordDialog("Change your password (last attempt failed)",
										max_h/2,max_w/2)
					data = d.run(loop.screen,view)
					if data[0] != 0:
						statusbar.set_text("Didn't password...")
						return
				statusbar.set_text("Changing password...")
				with open(os.devnull, 'rb') as shutup:
					chpw_prs=Popen(['passwd',username],
								stdin=PIPE,stdout=shutup,stderr=shutup)
					chpw_prs.communicate((data[1]+'\n')*2)
				if chpw_prs.returncode > 0:
					statusbar.set_text("Password change failed...")
				else:
					statusbar.set_text("Done! Login with your new password!")
				#check here for root login and bail out if needed
				#check here for other existing login and switch out
				#change_password(username)
				return
			if session is None:
				statusbar.set_text("Login is correct, but there are no valid sessions")
				return
			next_console=check_output(['fgconsole','-n']).decode(os.sys.getdefaultencoding())[:-1]
			statusbar.set_text(("Initializing session "
			"on console {}...").format(next_console))
			#now, use the C or X tags to complete the login
			if len(session.tag) > 0 and session.tag in "CX":
				pid = os.fork()
				if pid == 0:
					#separate from parent
					os.setsid()
					#problem: session is deregistered when login manager exits
					#input is also funky because the stdin is stolen from the manager
					if session.tag == 'C':
						cli_session(username,next_console,session.command,fb,img)
						#kill the daemon process that launched these in here
					elif session.tag == 'X':
						gui_session(username,next_console,session.command,ck)
						#kill the daemon process that launched these in here
					else:
						os._exit(1)
						#invalid tag
				else:
					pass
					'''
					ran = os.waitpid(pid,os.P_NOWAIT)
					if ran == pid:
						statusbar.set_text("Login command succeeded")
					else:
						statusbar.set_text("Login command failed")
					'''
			else:
				statusbar.set_text('Invalid session tag {}'.format(session.tag))
		else:
			statusbar.set_text("Login details are incorrect")

	def power_button(button, user_data):
		statusbar.set_text("Doing {} now...".format(button.label.lower()))
		with open(os.devnull, 'rb') as shutup:
			check_call([user_data], close_fds=True, stdout=shutup, stderr=shutup)

	def keystroke (input):
		if input in ('q', 'Q'):
			raise urwid.ExitMainLoop()

		if input in ('tab', 'shift tab'):
			focus = view.get_focus()
			if focus == 'body':
				view.set_focus('footer')
			else:
				view.set_focus('body')

		if input is 'enter' and view.get_focus() == 'body':
			panel = view.body.tab_map[view.body.active_tab]
			if panel is login_sel:
				active_session=login_sel.active_session()
				if "" == login_sel.username.edit_text:
					statusbar.set_text("Cannot login! Missing username...")
				else:
					img=settings.user_confs.get(login_sel.username.edit_text,
						{}).get('conf', settings.sysconf).get('DEFAULT','FBIMG')
					login(login_sel.username.edit_text,
							login_sel.password.edit_text,
							active_session, login_sel.ck_check.state,
							login_sel.fb_check.state, img)
				#statusbar.set_text("")
				login_sel.username.edit_text=""
				login_sel.password.edit_text=""
			elif panel is asessions_box:
				active_session=asessions_box.who_list.get_focus()[0]
				try:
					check_call(['chvt',str(active_session.tty)])
				except Exception as e:
					statusbar.set_text(str(e.message))
					statusbar._invalidate()
		#view.set_header(urwid.AttrWrap(urwid.Text(
		#	'selected: %s' % str(focus)), 'head'))

	login_sel = LoginDetails(settings,settings.greeter_msg(),settings.greeter_font())

	asessions_box = WhoView()

	sd_button = urwid.Button("Shutdown",on_press=power_button,
							user_data=settings.sysconf.get('DEFAULT','SHUTDOWN'))
	rbt_button = urwid.Button("Reboot",on_press=power_button,
							user_data=settings.sysconf.get('DEFAULT','REBOOT'))
	hb_button = urwid.Button("Hibernate",on_press=power_button,
							user_data=settings.sysconf.get('DEFAULT','HIBERNATE'))
	sp_button = urwid.Button("Suspend",on_press=power_button,
							user_data=settings.sysconf.get('DEFAULT','SUSPEND'))
	button_box = urwid.GridFlow([urwid.AttrWrap(sd_button,'button','btnfocus'),
								urwid.AttrWrap(rbt_button,'button','btnfocus'),
								urwid.AttrWrap(hb_button,'button','btnfocus'),
								urwid.AttrWrap(sp_button,'button','btnfocus')], \
								14, 0, 0, 'center')
	
	statusbar = urwid.Text("")
	footer = urwid.Pile([button_box,urwid.AttrWrap(statusbar,'statusbar','statusbar')])
	#http://lists.excess.org/pipermail/urwid/2008-November/000590.html
	tabs = TabColumns([urwid.AttrWrap(SelText("Login"), 'tab active', 'focus'),
					urwid.AttrWrap(SelText("Active Sessions"), 'body', 'focus')],
					[login_sel,asessions_box],'NCurses Display Manager')
	view = urwid.Frame(body=tabs, footer=footer)
	#set palette somewhere
	loop = urwid.MainLoop(view, palette=settings.theme, unhandled_input=keystroke)
	loop.run()

if __name__ == '__main__':
	main()
