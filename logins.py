from subprocess import check_output
import re
#import time
import urwid
import sys

#http://linux.die.net/man/3/logout

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
		self.focus = 0
		self.refresh()

	def refresh(self):
		'''
		active_logins.setutent()
		self.entries = [b for b in active_logins if b.ut_type == USER_PROCESS \
					and not re.match('pts/',b.ut_line) ]
		active_logins.endutent()
		'''
		out=check_output(['who']).decode(sys.getdefaultencoding()).split('\n')[:-1]
		self.entries=[w for w in out if re.findall('([a-z][-a-z0-9]*)[ ]*((?:tty|:)[0-9]*)',w)]

	def process_line(self, pos):
		e=self.entries[pos]
		'''
		username=e.ut_user
		device=e.ut_line
		'''
		username, device = re.findall('([a-z][-a-z0-9]*)[ ]*((?:tty|:)[0-9]*)',e)[0]
		#invalid entry?
		if re.match(':',device):
			x_pids=check_output(["pidof","X"]).decode(sys.getdefaultencoding())[:-1]
			x_line=[s for s in check_output(['ps','p',x_pids])\
					.decode(sys.getdefaultencoding()).split('\n')[:-1] \
					if ' {}'.format(device) in s][0]
			#terminal=check_output('cut -d\  -f4'.format(device),shell=True)[:-1]
			#terminal=x_line.split(' ')[3][-1]
			terminal=re.findall('^[ ]*[0-9]* (tty[0-9]*)[ ]*',x_line)[0][3:]
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
