import json
import sys

from java.io import PrintWriter

from burp import IBurpExtender
from burp import IHttpRequestResponse
from burp import IHttpService
from burp import ISessionHandlingAction

class BurpExtender(IBurpExtender, ISessionHandlingAction):
    
    def getActionName(self):
        # return extension name
        return 'Auth Header Injector'

    def registerExtenderCallbacks(self, callbacks):
        # set extension name
        callbacks.setExtensionName('Auth Header Injector')

        # register for scanner callbacks
        callbacks.registerSessionHandlingAction(self)

        # make errors more readable ad required for debugger burp-exceptions
        sys.stdout = callbacks.getStdout()

        # use PrintWriter for all output
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStdout(), True)

        # write a message to output stream
        self.stdout.println('Auth Header Injector')

        # keep reference to the callbacks
        self.callbacks = callbacks

        # obtain extension to the helper object
        self.helpers = callbacks.getHelpers()

    def performAction(self, baseRequestResponse, macroItems):
        # analyse request to be modified
        request_info = self.helpers.analyzeRequest(baseRequestResponse)
        # get the first response from a macro item
        macro_response_info = self.helpers.analyzeResponse(macroItems[0].getResponse())
        self.stdout.println('Starting up')

        # extract the token from the macro response
        macro_msg = macroItems[0].getResponse()
        macro_body_offset = macro_response_info.getBodyOffset()
        macro_body = macro_msg[macro_body_offset:-1]
        macro_body_string = self.helpers.bytesToString(macro_body)
        response_body = json.loads(macro_body_string)

        # UPDATE THIS LINE
        new_access_token = response_body['access_token']

        # get headers from base request
        headers = request_info.getHeaders()

        # ref to existing header
        auth_to_delete = ''

        # headers = ArrayList so iterate and find index of header to delete
        for header in headers:
            if 'Authorization: Bearer' in header:
                auth_to_delete = header

        # remove header if found
        headers.remove(auth_to_delete)

        # added new Bearer auth header with new token
        headers.add('Authorization: Bearer ' + new_access_token)

        # get body and add headers
        msg = baseRequestResponse.getRequest()
        body_offset = request_info.getBodyOffset()
        body = msg[body_offset:-1]

        # create new message with headers and body
        new_message = self.helpers.buildHttpMessage(headers, body)
        self.stdout.println('Changed token to: ' + new_access_token)

        baseRequestResponse.setRequest(new_message)

