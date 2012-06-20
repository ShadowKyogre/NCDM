import urwid

#http://bazaar.launchpad.net/~wicd-devel/wicd/experimental/view/head:/curses/curses_misc.py
class SelText(urwid.Text):
	"""A selectable text widget. See urwid.Text."""

	def selectable(self):
		"""Make widget selectable."""
		return True

	def keypress(self, size, key):
		"""Don't handle any keys."""
		return key

class TabColumns(urwid.WidgetWrap):
	"""
	titles_dict = dictionary of tab_contents (a SelText) : tab_widget (box)
	attr = normal attributes
	attrsel = attribute when active
	"""
	# FIXME Make the bottom_part optional
	def __init__(self,tab_str,tab_wid,title,bottom_part=None,attr=('body','focus'),
			attrsel='tab active', attrtitle='header'):
		#self.bottom_part = bottom_part
		#title_wid = urwid.Text((attrtitle,title),align='right')
		column_list = []
		for w in tab_str:
			text,trash = w.get_text()
			column_list.append(('fixed',len(text),w))
		column_list.append(urwid.Text((attrtitle,title),align='right'))

		self.tab_map = dict(zip(tab_str,tab_wid))
		self.active_tab = tab_str[0]
		self.columns = urwid.Columns(column_list,dividechars=1)
		#walker   = urwid.SimpleListWalker([self.columns,tab_wid[0]])
		#self.listbox = urwid.ListBox(walker)
		self.gen_pile(tab_wid[0],True)
		self.frame = urwid.Frame(self.pile)
		self.__super.__init__(self.frame)

	# Make the pile in the middle
	def gen_pile(self,lbox,firstrun=False):
		self.pile = urwid.Pile([
			('fixed',1,urwid.Filler(self.columns,'top')),
			urwid.Filler(lbox,'top',height=('relative',99)),
			#('fixed',1,urwid.Filler(self.bottom_part,'bottom'))
			])
		if not firstrun:
			self.frame.set_body(self.pile)
			self._w = self.frame
			self._invalidate()

	def selectable(self):
		return True

	def keypress(self,size,key):
		# If the key is page up or page down, move focus to the tabs and call
		# left or right on the tabs.
		if key == "page up" or key == "page down":
			self._w.get_body().set_focus(0)
			if key == "page up":
				newK = 'left'
			else:
				newK = 'right'
			self.keypress(size,newK)
			self._w.get_body().set_focus(1)
		else:
			key = self._w.keypress(size,key)
			wid = self.pile.get_focus().get_body()
			if wid == self.columns:
				self.active_tab.set_attr('body')
				self.columns.get_focus().set_attr('tab active')
				self.active_tab = self.columns.get_focus()
				self.gen_pile(self.tab_map[self.active_tab])

		return key

	def mouse_event(self,size,event,button,x,y,focus):
		wid = self.pile.get_focus().get_body()
		if wid == self.columns:
			self.active_tab.set_attr('body')

		self._w.mouse_event(size,event,button,x,y,focus)
		if wid == self.columns:
			self.active_tab.set_attr('body')
			self.columns.get_focus().set_attr('tab active')
			self.active_tab = self.columns.get_focus()
			self.gen_pile(self.tab_map[self.active_tab])

class DialogExit(Exception):
	pass

class Dialog2(urwid.WidgetWrap):
	def __init__(self, text, height,width, body=None ):
	   self.width = int(width)
	   if width <= 0:
		   self.width = ('relative', 80)
	   self.height = int(height)
	   if height <= 0:
		   self.height = ('relative', 80)
 	   
	   self.body = body
	   if body is None:
		   # fill space with nothing
		   body = urwid.Filler(urwid.Divider(),'top')
	
	   self.frame = urwid.Frame( body, focus_part='footer')
	   if text is not None:
			   self.frame.header = urwid.Pile( [urwid.Text(text,align='right'),
					   urwid.Divider()] )
	   w = self.frame
	   self.view = w

	# buttons: tuple of name,exitcode
	def add_buttons(self, buttons):
		l = []
		maxlen = 0
		for name, exitcode in buttons:
			b = urwid.Button( name, self.button_press )
			b.exitcode = exitcode
			b = urwid.AttrWrap( b, 'body','focus' )
			l.append( b )
			maxlen = max(len(name), maxlen)
		maxlen += 4 # because of '< ... >'
		self.buttons = urwid.GridFlow(l, maxlen, 3, 1, 'center')
		self.frame.footer = urwid.Pile( [ urwid.Divider(),
			self.buttons ], focus_item = 1)

	def button_press(self, button):
		raise DialogExit(button.exitcode)

	def run(self,ui,parent):
		ui.set_mouse_tracking()
		size = ui.get_cols_rows()
		overlay = urwid.Overlay(urwid.LineBox(self.view),
								parent, 'center', self.width,
								'middle', self.height)
		try:
			while True:
				canvas = overlay.render( size, focus=True )
				ui.draw_screen( size, canvas )
				keys = None
				while not keys:
					keys = ui.get_input()
				for k in keys:
					if urwid.VERSION < (1, 0, 0):
						check_mouse_event = urwid.is_mouse_event
					else:
						check_mouse_event = urwid.util.is_mouse_event
					if check_mouse_event(k):
						event, button, col, row = k
						overlay.mouse_event( size,
								event, button, col, row,
								focus=True)
					else:
						if k == 'window resize':
							size = ui.get_cols_rows()
						k = self.view.keypress( size, k )
						if k == 'esc':
							raise DialogExit(-1)
						if k:
							self.unhandled_key( size, k)
		except DialogExit, e:
			return self.on_exit( e.args[0] )
			   
	def on_exit(self, exitcode):
		return exitcode, ""

	def unhandled_key(self, size, key):
		pass

# Simple dialog with text in it and "OK"
class TextDialog(Dialog2):
	def __init__(self, text, height, width, header=None, align='left',
		buttons=('OK', 1)):
		l = [urwid.Text(text)]
		body = urwid.ListBox(l)
		body = urwid.AttrWrap(body, 'body')

		Dialog2.__init__(self, header, height+2, width+2, body)
		if type(buttons) == list:
			self.add_buttons(buttons)
		else:
			self.add_buttons([buttons])

	def unhandled_key(self, size, k):
		if k in ('up','page up','down','page down'):
			self.frame.set_focus('body')
			self.view.keypress( size, k )
			self.frame.set_focus('footer')

class PasswordDialog(Dialog2):
	def __init__(self, text, height, width,ok_name='OK'):
		self.edit = urwid.Edit(wrap='clip',mask='*')
		self.edit2 = urwid.Edit(wrap='clip',mask='*')
		body = urwid.ListBox([self.edit,self.edit2])
		body = urwid.AttrWrap(body, 'pw','pw')
	   
		Dialog2.__init__(self, text, height, width, body)
	   
		self.frame.set_focus('body')
		self.add_buttons([(ok_name,0),('Cancel',-1)])
	   
	def unhandled_key(self, size, k):
		if k in ('up','page up'):
			self.frame.set_focus('body')
		if k in ('down','page down'):
			self.frame.set_focus('footer')
		if k == 'enter':
			# pass enter to the "ok" button
			self.frame.set_focus('footer')
			self.view.keypress( size, k )
	   
	def on_exit(self, exitcode):
		return exitcode, self.edit.get_edit_text(), \
			self.edit2.get_edit_text()
