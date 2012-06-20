import PAM
import time


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

def check_avail(username,auth=None):
	#match expiry
	msgs=[]
	if auth is None:
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

def check_pw(username,password):
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
		return auth,False
	else:
		return auth,True
