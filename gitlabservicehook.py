# GitlabServiceHookPlugin
# Trac-version: 1.0.x
# Events: push, merge
# Based on https://github.com/trac-hacks/githubservicehook/
#	and https://trac.edgewall.org/browser/branches/1.0-stable/tracopt/ticket/commit_updater.py

import json
import re
from trac.config import BoolOption, Option
from trac.core import *
from trac.config import Option
from trac.web import IRequestHandler
from trac.ticket import Ticket
from trac.ticket.notification import TicketNotifyEmail
from trac.util.datefmt import datetime_now, utc
from trac.resource import ResourceNotFound


class GitlabServiceHookPlugin(Component):
	implements(IRequestHandler)

	commentPush = """In [changeset:"%s/%s"]:
{{{
#!CommitTicketReference repository="%s" revision="%s"
%s
}}}"""

	commentMerge = """Merge request %s for: [%s %s][[BR]]
Branch: %s[[BR]]"""

	token = Option('gitlabservicehook', 'token', '')

	notify = BoolOption('ticket', 'commit_ticket_update_notify', 'true',
		"""Send ticket change notification when updating a ticket.""")
	
	def match_request(self, request):
		self.env.log.debug("match_request: {method} -> {path}".format(method=request.method, path=request.path_info))
		if (request.path_info.rstrip('/') == '/gitlabservicehook' and request.method == 'POST'):
			# Check token
			if (self.token != request.get_header('X-Gitlab-Token')):
				self.env.log.debug('token mismatch')
				return False
			self.env.log.debug('accepted request')
			return True
		else:
			self.env.log.debug('refused request ' + request.path_info.rstrip('/'))
			return False

	def process_request(self, request):
		self.env.log.debug("process_request: {method} -> {path}".format(method=request.method, path=request.path_info))
		size = request.get_header('Content-Length')
		data = request.read(int(size))
		self.env.log.debug("body=")
		self.env.log.debug(data)
		httpContent = "No Data"
		httpCode = 500
		if data:
			httpContent = "Okay"
			httpCode = 200
			
			jsondata = json.loads(data)
			self.env.log.debug('got json')
			reponame = jsondata['project']['path_with_namespace']
			reponame = reponame.replace('main/', '') # Special for us

			# Push
			if (jsondata['object_kind'] == 'push'):
				self.env.log.debug("PUSH")
				for commit in jsondata['commits']:
					# Create push comment
					author = "%s <%s>" % (commit['author']['name'],commit['author']['email'])
					msg = self.commentPush % (commit['id'], reponame, reponame, commit['id'], commit['message'])
					self.env.log.debug(msg)
					self.process_action(msg, author, commit['id'])
			# Merge
			elif (jsondata['object_kind'] == 'merge_request'):
				self.env.log.debug("MERGE")
				author = jsondata['user']['name']
				username = jsondata['user']['username']
				# Get email
				for user, name, email in self.env.get_known_users():
					if (user == username):
						author = "%s <%s>" % (author,email)
						break
				# Create merge comment
				if 'action' not in jsondata['object_attributes']:
					jsondata['object_attributes']['action'] = "unknown" # Gitlab-webhook-test does not set action
				msg = self.commentMerge % (jsondata['object_attributes']['action'], jsondata['object_attributes']['url'], jsondata['object_attributes']['title'], jsondata['object_attributes']['source_branch'])
				# Add changeset for final merge
				if (jsondata['object_attributes']['merge_commit_sha'] is not None):
					msg = msg + "\n\n" + self.commentPush % (jsondata['object_attributes']['merge_commit_sha'], reponame, reponame, jsondata['object_attributes']['merge_commit_sha'], jsondata['object_attributes']['title'])
				self.env.log.debug(msg)
				self.process_action(msg, author)
			# Unknown
			else:
				httpContent = "Unknown Action: " + str(jsondata['object_kind'])
				httpCode = 500
				self.env.log.debug(content)
		request.send_response(httpCode)
		request.send_header('Content-Type', 'text/plain')
		request.end_headers()
		request.write(httpContent)

	def process_action(self, msg, author, githash = None):
		self.env.log.debug('process_action')

		# Find all the #123 strings in the commit message.
		ticket_re = re.compile('#[0-9]+')
		ticket_numbers = ticket_re.findall(msg)

		# Turn the ticket numbers into ints.
		ticket_numbers = set([int(ticket_number[1:]) for ticket_number in ticket_numbers])

		# For each ticket
		date = datetime_now(utc)
		for ticket_number in ticket_numbers:
			self.env.log.debug('Found ticket number: {n}'.format(n=str(ticket_number)))
			if (githash is not None and self._githash_storecheck(ticket_number, githash)):
				continue
			try:
				db = self.env.get_db_cnx()
				ticket = Ticket(self.env, int(ticket_number), db)
				ticket.save_changes(author, msg, date)
				db.commit()
				self._notify(ticket, date)
				self.env.log.debug('Comment added')
			except ResourceNotFound, e:
				self.log.error('Ticket not found: {n}'.format(n=str(ticket_number)))
				continue

	def _githash_storecheck(self, ticket, githash):
		self.env.log.debug('_githash_storecheck')
		# Check Githash in Ticket
		sql = """SELECT COUNT(ticket) AS amount FROM ticket_change
WHERE ticket=%s AND field='comment' AND newvalue LIKE '%%changeset:"%s/%%'""" % (ticket, githash)
		self.env.log.debug("Query: " + sql)
		fields = self.env.db_query(sql)
		self.env.log.debug("Result: " + str(fields[0][0]))
		if (fields[0][0] == 0):
			self.env.log.debug('Githash ' + githash + ' NOT yet found in ticket ' + str(ticket))
			return False
		else:
			self.env.log.debug('Githash ' + githash + ' already found in ticket ' + str(ticket))
			return True

	def _notify(self, ticket, date):
		self.env.log.debug('_notify')
		"""Send a ticket update notification."""
		if not self.notify:
			self.env.log.debug('Notification disabled')
			return
		tn = TicketNotifyEmail(self.env)
		try:
			self.env.log.debug('Sending notification')
			tn.notify(ticket, newticket=False, modtime=date)
		except Exception, e:
			self.log.error("Failure sending notification on change to ticket #%s: %s", ticket.id, exception_to_unicode(e))
