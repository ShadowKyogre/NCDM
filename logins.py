from subprocess import check_output
import re
import time
import urwid
#import utmp
#from UTMPCONST import *

#http://linux.die.net/man/3/logout
'''
active_logins = utmp.UtmpRecord(UTMP_FILE)
logins = utmp.UtmpRecord(WTMP_FILE)
def add_utmp_entry(username, tty_or_x, pid):
	now=time.time()
	sec,usec=divmod(now, 1)
	usec=usec*1E6
	entry = utmp.UtmpEntry(ut_type=USER_PROCESS,
					ut_pid=pid,
					ut_user=username,
					ut_id=tty_or_x[-4:],
					ut_line=tty_or_x,
					ut_tv=(int(sec),int(usec)))
	#write host?
	active_logins.setutent()
	active_logins.getutid(USER_PROCESS,entry.ut_id)
	active_logins.pututline(entry)
	active_logins.endutent() #?
	logins.setutent()
	logins.getutid(USER_PROCESS,entry.ut_id)
	logins.pututline(entry)
	logins.endutent() #?

def remove_utmp_entry(tty_or_x):
	active_logins.setutent()
	entry = active_logins.getutline(tty_or_x)
	entry.ut_type=DEAD_PROCESS
	entry.ut_pid=0
	#entry.ut_line=''
	entry.ut_user=''
	entry.ut_host=''
	now=time.time()
	sec,usec=divmod(now, 1)
	usec=usec*1E6
	entry.ut_tv=(int(sec),int(usec))
	active_logins.getutid(USER_PROCESS,entry.ut_id)
	active_logins.pututline(entry)
	active_logins.endutent() #?
'''

class WhoItem (urwid.WidgetWrap):

	#def __init__ (self, username, line, pid, host, login, tty):
	def __init__ (self, username, line, tty):
		self.username = username
		#self.pid = pid
		#self.host = host
		#self.login = time.ctime(login)
		self.line = line
		self.tty = tty
		#self.content = '%s: %s (terminal %s)' % (username, details, tty)
		#self.item = urwid.AttrWrap(urwid.Text('%s' % self.content), 'body', 'focus')
		w = urwid.Columns([urwid.Text(self.username),
							#urwid.Text(str(self.pid)),
							#urwid.Text(self.host),
							#urwid.Text(self.login),
							urwid.Text(self.line),
							urwid.Text(self.tty)])
		self.__super.__init__(urwid.AttrWrap(w,'body','focus'))

	def selectable (self):
		return True

	def keypress(self, size, key):
		return key

class WhoWalker(urwid.ListWalker):
	"""ListWalker-compatible class for browsing logged in sessions.
	positions returned are (value at position-1, value at poistion) tuples.
	"""
	def __init__(self):
		self.focus = 0L
		self.refresh()

	def refresh(self):
		'''
		active_logins.setutent()
		self.entries = [b for b in active_logins if b.ut_type == USER_PROCESS \
					and not re.match('pts/',b.ut_line) ]
		active_logins.endutent()
		'''
		self.entries=filter(lambda w: re.findall('([a-z][-a-z0-9]*)[ ]*((?:tty|:)[0-9]*)',w),
							check_output(['who']).split('\n')[:-1])

	def process_line(self, pos):
		e=self.entries[pos]
		'''
		username=e.ut_user
		device=e.ut_line
		'''
		username, device = re.findall('([a-z][-a-z0-9]*)[ ]*((?:tty|:)[0-9]*)',e)[0]
		#invalid entry?
		if re.match(':',device):
			x_pids=check_output(["pidof","X"])[:-1]
			x_line=filter(lambda s: ' {}'.format(device) in s,
					check_output(['ps','p',x_pids]).split('\n')[:-1])[0]
			#terminal=check_output('cut -d\  -f4'.format(device),shell=True)[:-1]
			terminal=x_line.split(' ')[3][-1]
		else:
			terminal=device[3:]
		#return WhoItem(username,device,e.ut_pid,e.ut_host,e.ut_tv[0],terminal)
		return WhoItem(username,device,terminal)

	def _get_at_pos(self, pos):
		"""Return a widget and the position passed."""
		self.refresh()
		if pos < 0 or pos >= len(self.entries) or len(self.entries) == 0:
			return None, None
		else:
			return self.process_line(pos), pos

	def get_focus(self):
		return self._get_at_pos(self.focus)

	def set_focus(self, focus):
		self.focus = focus
		self._modified()

	def get_next(self, start_from):
		return self._get_at_pos(start_from+1)

	def get_prev(self, start_from):
		return self._get_at_pos(start_from-1)

class WhoView(urwid.Filler):
	def __init__(self):
		header = urwid.Columns([urwid.Text("User"),
		#urwid.Text("PID"),
		#urwid.Text("Host"),
		#urwid.Text("Login time"),
		urwid.Text("Display"),
		urwid.Text("Terminal")])
		self.who_list = urwid.ListBox(WhoWalker())
		who_box = urwid.Pile([urwid.AttrWrap(header,'body','body'),
							urwid.BoxAdapter(self.who_list,40)])
		self.__super.__init__(who_box)