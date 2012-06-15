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