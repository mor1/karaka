#!/usr/bin/env python
#
# Karaka Skype-XMPP Gateway: Registration service
# <http://www.vipadia.com/products/karaka.html>
#
# Copyright (C) 2008-2009 Vipadia Limited
# Richard Mortier <mort@vipadia.com>
# Neil Stratford <neils@vipadia.com>
#

## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License version
## 2 as published by the Free Software Foundation.

## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License version 2 for more details.

## You should have received a copy of the GNU General Public License
## version 2 along with this program; if not, write to the Free
## Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
## MA 02110-1301, USA.

import sys, logging, locale, codecs, time, signal, threading

## pyrepl appears to conflict with screen - get EINTR in os.read() on reattch
## from pyrepl.unix_console import UnixConsole
## from pyrepl.historical_reader import HistoricalReader

from pyxmpp.all import JID, Iq, Presence, Message, StreamError
from pyxmpp.jabber.client import JabberClient
from pyxmpp import streamtls
from pyxmpp.stanza import Stanza

from karaka import *
from karaka.api.api import DatabaseAPI
from karaka.common import *

## ## KeyCzar settings
## from keyczar import keyczar

## PRIVATE_KEYLOC="/etc/karaka/keys/private/"
## PUBLIC_KEYLOC="/etc/karaka/keys/public/"
## ## end KeyCzar settings

from karaka.common import _dbg
Debug = 5
def dbg(s, l=0):
    if Debug > l: _dbg(s)

WELCOME_MSG = COPYRIGHT_MESSAGE + """\

Karaka Register Buddy Controller
"""
   
GOING_MSG = "Karaka Register Buddy Controller exiting - cleaning up..."
GONE_MSG = """\
Karaka Register Buddy exited - goodbye!
"""

HELP_MSG = """\
Commands are:
copying   | show license information pertaining to copying
debug [n] | show debug level, or set it to n
help      | show this help message
quit      | quit the slave
status    | show connection status
warranty  | show license information pertaining to warranty
"""

LOGFILE = "/tmp/karaka_register.log"
PIDFILE = "/tmp/karaka_register.pid"
PKLFILE = "/tmp/karaka_register.pkl"
PROMPT = 'karaka register> '

PrecedingMessage = {}                   # { ujid: last-sent-message }

Running = True
RegDB = None

def sigkill_handler(signal, frame):
    err("signal: %s" % signal)
    global Running
    Running = False

################################################################################

class _Register(JabberClient):

    def __init__(self, config):
        self.config = config
        self.connection = CONNECTION.idle
        self.running = True
        
        self.jid = JID("%s@%s/%s" % (config.register, config.domain, config.register))
        log("register: jid:%s" % (self.jid.as_utf8(),))
        
        tls = streamtls.TLSSettings(require=True, verify_peer=False)
        auth = [ 'digest' ]

        JabberClient.__init__(self, self.jid, self.config.secret,
            disco_name="Vipadia Skype Gateway Register", disco_type="bot",
            tls_settings=tls, auth_methods=auth)
        
    def stream_state_changed(self, state, arg):
        dbg("stream_state_changed: %s %r" % (state, arg), 3)
        
    def safe_send(self, stanza):
        to = stanza.get_to()
        if not to.domain.endswith(self.config.domain): to = to.bare()
            
        stanza = Stanza(stanza, to_jid=to)
        dbg("tx:\n%s" % (fmt_evt(stanza),))
        self.stream.send(stanza)

    def session_started(self):
        log("session_started: jid:%s" % (self.jid.as_utf8(),))

        self.connection = CONNECTION.connected
        JabberClient.session_started(self)

        self.stream.set_message_handler("normal", self.message)
        self.stream.set_presence_handler("subscribe", self.subscription)
        self.stream.set_iq_set_handler(
            "command", "http://vipadia.com/skype", self.vipadia_command)

        global Connected
        Connected = True

        self.safe_send(Presence(to_jid=self.config.master, stanza_type="subscribe"))

    #
    # message handler
    #
    
    def message(self, stanza):
        dbg("message:\nfrm:%s to:%s" % (
            stanza.get_from().as_utf8(), stanza.get_to().as_utf8(),), 3)
        global RegDB
        
        body = stanza.get_body()
        frm = stanza.get_from()
        user = stanza.get_from().bare().as_utf8()

        ujid = JID(user)
        dbg("  ++ujid:%s precedingmessage:%s" % (ujid.as_utf8(), PrecedingMessage,))
        if ujid in PrecedingMessage: del PrecedingMessage[ujid]
        dbg("  --ujid:%s precedingmessage:%s" % (ujid.as_utf8(), PrecedingMessage,))
                                                               
        if body:         
            cmd = body.split()
            if len(cmd) > 0 :
                reply = ""
                if cmd[0].lower() == "register":
                    if len(cmd) != 3:
                        reply = "error, please use: register <skypeuser> <skypepassword>"

                    skypeuser = cmd[1]
                    skypepass = cmd[2]
                    
                    RegDB.remove_credentials(user)
                    RegDB.set_credentials_plain(user, skypeuser, skypepass)
                                                                     
                    reply = "Registration successful for " + skypeuser
                    message = Message(to_jid=stanza.get_from(), body=reply)
                    self.safe_send(message)

                    sub = Iq(to_jid=self.config.master, stanza_type="set")
                    query = sub.new_query('http://vipadia.com/skype', "command")
                    add_child(query, "item", attrs={ "command" : "register-available",
                                                     "jid": frm.as_utf8() })
                    dbg("  sub:\n%s" % (fmt_evt(sub),))
                    self.safe_send(sub)
                    reply = "Presence request sent"

                elif cmd[0].lower() == "register-carrier":
                    if len(cmd) != 3:
                        reply = "error, please use: register <skypeuser> <skypepassword>"
                        
                    skypeuser = cmd[1]
                    ## KeyCzar
##                     crypter = keyczar.Encrypter.Read(PUBLIC_KEYLOC)
                    skypesecret = cmd[2]
                    ## KeyCzar
##                     skypesecret = crypter.Encrypt(str(skypesecret))
                    
                    spawn = Iq(to_jid=self.config.master, stanza_type="set")
                    command = spawn.new_query("http://vipadia.com/skype", "command")
                    add_child(command, "item", attrs={ "command": "spawn",
                                                       "ujid": frm.as_utf8(),
                                                       "skypeuser": skypeuser,
                                                       "skypesecret": skypesecret,
                                                       })
                    self.safe_send(spawn)
                    
                elif cmd[0].lower() == "unregister":
                    if len(cmd) == 1:
                        RegDB.remove_credentials(user)
                        reply = "Unregistration successful"

                else:
                    reply = "Skype Registration Commands:\r\n" + \
                    " register <skypeuser> <skypepass>\r\n" + \
                    " unregister"
                
                message = Message(to_jid=stanza.get_from(), body=reply)
                self.safe_send(message)
        
        return True

    #
    # presence handlers
    #
    
    def subscription(self, stanza):
        dbg("subscription:\n%s" % (fmt_evt(stanza),), 3)
        
        send_response = not (stanza.get_type() == 'subscribed')
        if send_response:
            self.safe_send(stanza.make_accept_response())

        return True

    #
    # iq handlers
    #

    def vipadia_command(self, iq):
        dbg("vipadia_command:\n%s" % (fmt_evt(iq),))

        items = iq.xpath_eval("v:command/v:item", { "v": "http://vipadia.com/skype", })
        for item in items:
            command = item.prop("command")
            if command == "message":
                ujid = JID(item.prop("ujid"))
                message = item.prop("message")

                dbg("  +ujid:%s precedingmessage:%s" % (ujid.as_utf8(), PrecedingMessage,))
                if ujid in PrecedingMessage and PrecedingMessage[ujid] == message:
                    continue

                PrecedingMessage[ujid] = message
                self.safe_send(Message(to_jid=ujid, body=message))
                dbg("  -ujid:%s precedingmessage:%s" % (ujid.as_utf8(), PrecedingMessage,))

        return True

################################################################################

def register_keepalive():    
    config = registerconfig.RegisterConfig()

    global Register
    Register = _Register(config)
    
    global RegDB
    RegDB = DatabaseAPI()

    keepalive = Iq(to_jid=config.domain, stanza_type="set")
    keptalive = 0

    while Register.running:
        try:
            if Register.connection == CONNECTION.idle:
                dbg("register connecting")
                Register.connect()                
                Register.connection = CONNECTION.connecting
                    
            elif Register.connection == CONNECTION.connecting:
                dbg("register connecting...")
                if Register.stream: Register.stream.loop_iter(1)
                
            elif Register.connection == CONNECTION.connected:
                dbg("looping register")
                if Register.stream: Register.stream.loop_iter(1)
                
                Register.idle()
                now = time.time()
                if now - keptalive > 60:
                    dbg("register keepalive! %s" % (fmt_evt(keepalive),), 5)
                    Register.safe_send(keepalive)
                    keptalive = now

            elif Register.connection == CONNECTION.error:
                Register.connection = CONNECTION.idle
        
        except Exception, exc:
            log_stacktrace(exc)
            try:
                Register.disconnect()
            except Exception, exc:
                err("second chance!  failing")
                log_stacktrace(exc)
            
            Register.connection = CONNECTION.error

    log("register exit: jid:%s" % (Register.jid.as_utf8(),))

################################################################################
    
if __name__ == '__main__':

    try:
        try:
            print WELCOME_MSG
            
            signal.signal(signal.SIGINT, sigkill_handler)
            signal.signal(signal.SIGTERM, sigkill_handler)
            openlog()

            if check_running(PIDFILE):
                die("Karaka Register already runnning - check %s" % (PIDFILE,))

            ## unicode magic
            locale.setlocale(locale.LC_CTYPE, "")
            encoding = locale.getlocale()[1]
            if not encoding: encoding = "us-ascii"
            sys.stdout = codecs.getwriter(encoding)(sys.stdout, errors="replace")
            sys.stderr = codecs.getwriter(encoding)(sys.stderr, errors="replace")

            ## pyxmpp logger setup
            logger = logging.getLogger()
            logger.addHandler(logging.FileHandler(LOGFILE))
            logger.setLevel(logging.DEBUG) # change to DEBUG for higher verbosity

            ## master
            register_thread = threading.Thread(name="Register", target=register_keepalive)
            register_thread.setDaemon(True)
            register_thread.start()
            time.sleep(1)

            ## loop, processing user input 
##             reader = HistoricalReader(UnixConsole())
##             reader.ps1 = PROMPT
            try:
                while Running:
##                     line = reader.readline()
                    line = raw_input(PROMPT)
                    if not line or len(line) == 0: continue
                    
                    cmd = line.split()
                    if cmd[0] == 'quit':
                        Running = False

                    elif cmd[0] in ('help', '?'):
                        print HELP_MSG

                    elif cmd[0] in 'copying':
                        print COPYING_MESSAGE

                    elif cmd[0] in 'warranty':
                        print WARRANTY_MESSAGE
                    
                    elif cmd[0] in 'status':
                        print "Status = %s" % Register.connection                

                    elif cmd[0] == 'debug':
                        if len(cmd) == 2: Debug = int(cmd[1])
                        print "Debug = %s" % Debug
                        
            except IOError, ioe:
                if ioe.errno == 4: ## interrupted system call
                    err("exception due to signal handling; ignore")
                    log_stacktrace(ioe)

            except EOFError, eof:
                Running = False

            if os.path.exists(PIDFILE): os.remove(PIDFILE)

        except KeyboardInterrupt:
            print "^C"
            if os.path.exists(PIDFILE): os.remove(PIDFILE)
        
        except Exception, exc:
            print "### exception caught! see error log for details"
            log_stacktrace(exc)

        print GOING_MSG
        
    finally:
        print GONE_MSG
        os._exit(os.EX_OK)
