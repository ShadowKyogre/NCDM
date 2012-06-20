try:
	import PAM
except ImportError as e:
	PAM = None
PAM = None
import time
from subprocess import check_call, CalledProcessError
from spwd import getspnam
from crypt import crypt

if PAM is not None:
	def mute_conv(auth, query_list, userData):
		resp = []
		for i in range(len(query_list)):
			query, qtype = query_list[i]
			if qtype == PAM.PAM_PROMPT_ECHO_ON:
				#val = raw_input(query)
				resp.append(('', 0))
			elif qtype == PAM.PAM_PROMPT_ECHO_OFF:
				#val = getpass(query)
				resp.append(('', 0))
			elif qtype == PAM.PAM_ERROR_MSG or type == PAM.PAM_TEXT_INFO:
				print(query)
				resp.append(('', 0))
			else:
				return None
		return resp
	def gather_msgs(auth, query_list, userData):
		resp = []
		for i in range(len(query_list)):
			query, qtype = query_list[i]
			if qtype == PAM.PAM_PROMPT_ECHO_ON:
				resp.append(('', 0))
			elif qtype == PAM.PAM_PROMPT_ECHO_OFF:
				resp.append(('', 0))
			elif qtype == PAM.PAM_ERROR_MSG or type == PAM.PAM_TEXT_INFO:
				userData.append(query)
				resp.append(('', 0))
			else:
				return None
		return resp

def delete_session(username,tty_or_x):
	if PAM is None:
		try:
			check_call(['sessreg','-d','-l', new_d, username])
		except CalledProcessError as e:
			return False
		else:
			return True
	else:
		auth = PAM.pam()
		auth.start('ncdm')
		auth.set_item(PAM.PAM_USER, username)
		auth.set_item(PAM.PAM_TTY,tty_or_x)
		auth.set_item(PAM.PAM_CONV, mute_conv)
		try:
			auth.close_session()
		except PAM.error as e:
			return False
		else:
			return True

def register_session(username,tty_or_x,try_creds=False):
	if PAM is None:
		try:
			check_call(['sessreg','-a','-l', new_d, username])
		except CalledProcessError as e:
			return False
		else:
			return True
	else:
		auth = PAM.pam()
		auth.start('ncdm')
		auth.set_item(PAM.PAM_USER, username)
		auth.set_item(PAM.PAM_TTY,tty_or_x)
		auth.set_item(PAM.PAM_CONV, mute_conv)
		try:
			if try_creds:
				auth.setcred(PAM.PAM_ESTABLISH_CRED)
			auth.open_session()
		except PAM.error as e:
			return False
		else:
			return True

def check_avail(username):
	#match expiry
	if PAM is None:
		usr = getspnam(username)
		daysleft = -1
		msgs=[]
		
		#translated from pam_unix/passverify.c

		today = time.time()/(3600*24)

		#check account expiry
		if today >= usr.sp_expire and usr.sp_expire != -1:
			msgs.append(("Your account has expired; please"
						" contact your system administrator"))
			#tell them them their account expired and bail out
			return '\n'.join(msgs),3
		
		if usr.sp_lstchg == 0:
			daysleft = 0
			msgs.append(("You are required to change your password"
							" immediately (root enforced)"))
			#this was because of a forced expirty
			#show a box to the user to tell them to change
			#their password or remind them with a dialog box
			return '\n'.join(msgs),1
		
		#check if pw change will happen in the future
		if today < usr.sp_lstchg:
			msgs.append(("Your password will be changed in the future."))
			return '\n'.join(msgs),0

		#did password expire?
		deltapw = today - usr.sp_lstchg
		if deltapw > usr.sp_max and deltapw > usr.sp_inact \
			and deltapw > (usr.sp_max+usr.sp_inact) and \
			-1 not in (usr.sp_inact, usr.sp_max):
			daysleft = usr.sp_lstchg+spent.sp_max-curdays
			msgs.append(("Your account expired since"
						"you didn't change it. "
						"Please contact the administrator."))
			#this was because of aging
			#show a box to the user to tell them their pw expired
			return '\n'.join(msgs),2
		
		if deltapw > usr.sp_max and sp.max != -1:
			#this was because of aging
			#show a box to user to change pw or remind them
			msgs.append(("You are required to change your "
						"password immediately (password aged)"))
			return '\n'.join(msgs),1
		
		if deltapw > usr.sp_max-usr.sp_warn and \
			-1 not in (usr.sp_warn, usr.sp_max):
			daysleft = usr.sp_lstchg+spent.sp_max-curdays
			
			if daysleft == 1:
				msgs.append(("Warning: your password will expire in %d day").format(daysleft))
			else:
				msgs.append(("Warning: your password will expire in %d days").format(daysleft))
			#show a box to the user reminding them of how long they have
		
		if deltapw < usr.sp_min and usr.sp_min != -1:
			#show a box saying that the pw change was too recent
			msgs.append(("Your password changed too recently"))
			return '\n'.join(msgs),0
			
		return '\n'.join(msgs),0

	else:
		msgs=[]
		auth = PAM.pam()
		auth.start('ncdm')
		auth.set_item(PAM.PAM_USER, username)
		auth.set_item(PAM.PAM_CONV, gather_msgs)
		auth.setUserData(msgs)
		err_map={PAM.PAM_ACCT_EXPIRED:3,
				PAM.PAM_NEW_AUTHTOK_REQD:1,
				PAM.PAM_AUTHTOK_EXPIRED:2,
				PAM.PAM_AUTHTOK_ERR:0,}
		try:
			auth.acct_mgmt()
		except PAM.error as e:
			#return msg and the error code
			return '\n'.join(msgs),err_map[e.args[1]]
		else:
			return '\n'.join(msgs),0

def check_pw(username,password,nopw=True):
	'''
	nopw only has an effect when PAM is not enabled. 
	Otherwise, let PAM handle that
	'''
	if PAM is None:
		try:
			encrypted_password = getspnam(username).sp_pwd
		except KeyError as e:
			return False
		encrypted_attempt = crypt(password,encrypted_password)
		#allow no passwd logins by default
		#we do not need to check ! or * entries
		#since they will never match
		if len(encrypted_password) == 0 and nopw is False:
			return False
		return encrypted_attempt == encrypted_password
	else:
		def conv(auth, query_list, userData):
			resp = []
			for i in range(len(query_list)):
				query, qtype = query_list[i]
				if qtype == PAM.PAM_PROMPT_ECHO_OFF:
					resp.append((password, 0))
			return resp
		auth = PAM.pam()
		auth.start('ncdm')
		auth.set_item(PAM.PAM_USER, username)
		auth.set_item(PAM.PAM_CONV, conv)
		try:
			auth.authenticate()
		except PAM.error as e:
			return False
		else:
			return True
