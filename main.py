import urwid
import re
import os
import glob
import json
import csv

from platform import uname,python_version
from subprocess import check_call, check_output, Popen, CalledProcessError
from pwd import getpwnam, getpwall
from grp import getgrnam
from spwd import getspnam
from crypt import crypt
from ConfigParser import ConfigParser

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

from miscwidgets import SelText, TabColumns
from logins import WhoView
import utils

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
	'''
	def selectable (self):
		return True
	def keypress(self, size, key):
		return key
	'''

class LoginDetails(urwid.Pile):
	def __init__(self, settings, greet, font):
		self.group = []
		self.gui_items = urwid.SimpleListWalker([])
		self.cli_items = urwid.SimpleListWalker([])
		'''
		for i in sessions:
			if sessions[i][0] == 'C':
				cli_items.append(SessionTypeItem(self.group,sessions[i][0],sessions[i][1],i))
			elif sessions[i][0] == 'X':
				gui_items.append(SessionTypeItem(self.group,sessions[i][0],sessions[i][1],i))
			else:
				exit(0)
		'''
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
		return filter(lambda x: x.get_state(),self.group)[0]

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
	entries.next()
	rest=list(entries)
	csv_file.close()
	return rest

class FakeSecHead(object):
	def __init__(self, fp):
		self.fp = fp
		self.sechead = '[DEFAULT]\n'
	def readline(self):
		if self.sechead:
			try: return self.sechead
			finally: self.sechead = None
		else: return self.fp.readline()

class NCDMConfig:
	def __init__(self):
		self.sysconf = ConfigParser()
		#/etc/ncdm/sys.cfg
		self.sysconf.readfp(FakeSecHead(open('/etc/ncdm/sys.cfg')))
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
					self.user_confs[user.pw_name]['conf'].readfp(FakeSecHead(open(os.path.join(f,'usr.cfg'))))
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
		fullos=check_output(['uname','-o'])[:-1]
		pyver=python_version()
		return self.sysconf.get('DEFAULT',
					'WELCOME').format(**locals())

	def login_once(self):
		return self.sysconf.get('DEFAULT','LOGIN_ONCE').split(':')

	def greeter_font(self):
		return filter(lambda f: f[0] == self.sysconf.get('DEFAULT','FONT'),
				urwid.get_all_fonts())[0][1]

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
#screen acts funky after a session is started
'''

def make_child_env(username):
	usr = getpwnam(username)
	env = {}
	env['HOME']=usr.pw_dir
	env['PWD']=usr.pw_dir
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
	def result():
		#print("Changing to {}".format(username))
		#print("UID: {}, GID: {}".format(os.getuid(),os.getgid()))
		#print("EUID: {}, EGID: {}".format(os.geteuid(),os.getegid()))
		usr = getpwnam(username)
		os.initgroups(username,usr.pw_gid)
		os.setgid(usr.pw_gid)
		os.setuid(usr.pw_uid)
		#print("Changed creds")
		#print("UID: {}, GID: {}".format(os.getuid(),os.getgid()))
		#print("EUID: {}, EGID: {}".format(os.geteuid(),os.getegid()))
	return result
	#we only want to temporarily drop the priveleges
	#http://comments.gmane.org/gmane.comp.web.paste.user/1641
	#http://stackoverflow.com/questions/1770209/run-child-processes-as-different-user-from-a-long-running-process

def restore_privs():
	drop_privs('root')()

def prepare_tty(username,n):
	ttypath=os.path.join("/dev","tty{}".format(n))
	os.chown(ttypath, getpwnam(username).pw_uid, getgrnam('tty').gr_gid)

def restore_tty(n):
	prepare_tty('root',n)

def main ():
	'''
	def fix_arrows(key,raw):
		write_this="Key: {}, Raw: {}".format(key,raw)
		statusbar.set_text(write_this)
		f=open('/tmp/rawr.txt','a')
		f.write(write_this)
		f.write('\n')
		f.close()
		if len(key) == 0:
			return key
		if key[0] == "meta C" or key == ['[','right']:
			return "right"
		elif key[0] == "meta D" or key == ['[','left']:
			return "left"
		elif key[0] == "meta A" or key == ['[','up']:
			return "up"
		elif key[0] == "meta B" or key == ['[','down']:
			return "down"
		else:
			return key
	'''
	settings = NCDMConfig()
	def login(username, password, session, ck, fb, img):
		#check here for root login and bail out if needed
		#check here for other existing login and switch out
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
		encrypted_password = getspnam(username).sp_pwd
		encrypted_attempt = crypt(password,encrypted_password)
		if encrypted_attempt == encrypted_password:
			if session is None:
				statusbar.set_text("Login is correct, but there are no valid sessions")
				return
			next_console=check_output(['fgconsole','-n'])[:-1]
			statusbar.set_text(("Initializing session "
			"on console {}...").format(next_console))
			if session.tag in 'CX':
				pid = os.fork()
				if pid == 0:
					#separate from parent
					os.setsid()
					#problem: session is deregistered when login manager exits
					#input is also funky because the stdin is stolen from the manager
					ttytxt='tty{}'.format(next_console)
					if session.tag == 'C':
						usr,env=make_child_env(username)
						#env['TERM']='linux'
						# let the wrapper handle setting TERM
						#print("Setting up environment for {}".format(username))
						prepare_tty(username,next_console)
						#print("Making {} own {}".format(username, ttytxt))
						#we have to do slightly more work for normal ttys
						#see http://www.linuxmisc.com/22-unix-security/d7e7d987a8860b8f.htm for more details
						'''
						check_call(['openvt','-ws','--',
									'su',username,'-c',session.command],
									env=env,cwd=usr.pw_dir,close_fds=True)
						'''
						spid = os.fork()
						if spid == 0:
							os.setsid()
							#do a check for fbterm goodiness
							check_failed=False
							if fb:
								try:
									check_call(['which','fbterm'])
								except CalledProcessError,e:
									check_failed=True
								try:
									check_call(['which','fbv'])
								except CalledProcessError,e:
									check_failed=True

								try:
									check_call(['which','fbterm-bi'])
								except CalledProcessError:
									check_failed=True

								if not check_failed:
									check_failed=os.path.exists(img)
							if check_failed:
								totalcmd="openvt -ws -- {}".format(session.command).strip()
							else:
								totalcmd="openvt -ws -- fbterm-bi {} {}".format(img,session.command).strip()
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
							check_call(['sessreg','-a','-l',ttytxt,username])
							#register now that we have the PID
							#print("Registering session for {} on {}".format(username, ttytxt))
							status=os.waitpid(spid,os.P_WAIT)[1]
							#print("Child finished")
							#restore_privs()
							#print("Restoring priveleges")
							restore_tty(next_console)
							#print("Restoring tty ownership")
							check_call(['sessreg','-d','-l',ttytxt, username])
							#print("Deregistering session for {} on {}".format(username, ttytxt))
							os._exit(status)
						#check_call(['sessreg','-d','-l',ttytxt, username.edit_text])
						#exit the child thread?
					elif session.tag == 'X':
						usr,env=make_child_env(username)
						#get next empty display
						active_xs=glob.glob('/tmp/.X*-lock')
						if len(active_xs) > 0:
							last_d=os.path.basename(active_xs[-1]).replace('-lock','')[2:]
						else:
							last_d=-1
						new_d=":{}".format(int(last_d)+1)
						env['DISPLAY']=new_d #we need this only for sessreg purposes
						env['TERM']='xterm'
						check_failed=False
						cookie=''
						if ck:
							if dbus is None or manager_iface is None:
								check_failed=True
						if not check_failed:
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
						totalcmd='startx {} -- {}'.format(session.command,new_d)
						#check_call(['startx','/etc/X11/xinitrc',
						spid = os.fork()
						if spid == 0:
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
							check_call(['sessreg','-a','-l', new_d, username])
							#add_utmp_entry(username, new_d, spid)
							status=os.waitpid(spid,os.P_WAIT)[1]
							if not check_failed:
								closed = manager_iface.CloseSession(cookie)
								del env['XDG_SESSION_COOKIE']
							#remove_utmp_entry(new_d)
							check_call(['sessreg','-d','-l', new_d, username])
							os._exit(status)
				else:
					pass
					'''
					child_pr=os.waitpid(pid,os.P_NOWAIT)
					statusbar.set_text(str(child_pr))
					ss=os.fdopen(fd)
					f=open('/tmp/rawr.txt','a')
					f.write("Status: {}".format(child_pr))
					f.write(", output: {}".format(ss.read()))
					f.write('\n___________\n')
					f.close()
					ss.close()
					'''
			else:
				statusbar.set_text('Invalid session tag {}'.format(session.tag))
						#kill the daemon process
		else:
			statusbar.set_text("Login failed, password is incorrect")
		#now, use the C or X tags to complete the login

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
					login_sel.username.edit_text=""
					login_sel.password.edit_text=""
			elif panel is asessions_box:
				active_session=asessions_box.who_list.get_focus()[0]
				statusbar.set_text(str(active_session.username))
				try:
					check_call(['chvt',str(active_session.tty)])
				except Exception, e:
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

'''
'''

