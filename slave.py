#!/usr/bin/env python
#
# Karaka Skype-XMPP Gateway: Slave bundle manager
# <http://www.vipadia.com/products/karaka.html>
#
# Copyright (C) 2008-2009 Vipadia Limited
# Copyright (C) 2010 Voxeo Corporation
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

import sys, logging, locale, codecs, subprocess, time, signal, threading, base64

from pyxmpp.all import JID, Iq, Presence, Message, StreamError
from pyxmpp.jabber.client import JabberClient
from pyxmpp import streamtls
from pyxmpp.stanza import Stanza

## pyrepl appears to conflict with screen - get EINTR in os.read() on reattch
## from pyrepl.unix_console import UnixConsole
## from pyrepl.historical_reader import HistoricalReader

from karaka import *
from karaka.common import *

from karaka.common import _dbg
Debug = 5
def dbg(s, l=0):
    if Debug > l: _dbg(s)

WELCOME_MSG = COPYRIGHT_MESSAGE + """\

Karaka Slave Controller
"""
   
GOING_MSG = "Karaka Slave Controller exiting - cleaning up..."
GONE_MSG = """\
Karaka Slave exited - goodbye!
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

LOGFILE = "/tmp/karaka_%s.log"
PIDFILE = "/tmp/karaka_%s.pid"
PKLFILE = "/tmp/karaka_%s.pkl"
PROMPT = 'karaka slave> '

Running = True
Slave = None

def sigkill_handler(signal, frame):
    err("signal: %s" % signal)
    global Running
    Running = False

################################################################################

class SkypeSlave(JabberClient):

    def __init__(self, config):
        self.config = config
        self.running = True
        self.connection = CONNECTION.idle
        
        self.jid = JID("%s@%s/slave" % (config.slave, config.domain,))
        log("slave: jid:%s" % (self.jid.as_utf8(),))
        
        tls = streamtls.TLSSettings(require=True, verify_peer=False)
        auth = [ 'digest' ]

        JabberClient.__init__(self, self.jid, self.config.secret,
            disco_name="Vipadia Skype Gateway Slave", disco_type="bot",
            tls_settings=tls, auth_methods=auth)
        
    def safe_send(self, stanza):
        to = stanza.get_to()
        if not to.domain.endswith(self.config.domain): to = to.bare()
            
        stanza = Stanza(stanza, to_jid=to)
        dbg("tx:\n%s" % (fmt_evt(stanza),))
        self.stream.send(stanza)

    def stream_state_changed(self, state, arg):
        dbg("stream_state_changed: %s %r" % (state, arg), 3)
        
    def session_started(self):
        log("session_started: jid:%s" % (self.jid.as_utf8(),))

        self.connection = CONNECTION.connected
        JabberClient.session_started(self)
        
        self.stream.set_presence_handler("subscribe", self.subscribe)
        self.stream.set_iq_set_handler(
            "query", "http://vipadia.com/skype", self.vipadia_iq)

        self.slave_online()
        
    def slave_online(self):
        slavejid = JID("%s@%s/slave" % (self.config.slave, self.config.domain))
        iq = Iq(to_jid=self.config.master, from_jid=slavejid, stanza_type="set")
        command = iq.new_query('http://vipadia.com/skype', "command")
        digest = generate_slave_digest(str(slavejid.as_utf8()),
                                       self.config.slave_secret)
        add_child(command, "item", attrs={ "command": "slave-online",
                                           "capacity": self.config.capacity,
                                           "base": self.config.base,
                                           "digest": digest
                                           })
        dbg("  iq:\n%s" % (fmt_evt(iq),))
        self.safe_send(iq)
        
    def disconnected(self):
        log("slave disconnected! jid:%s" % (self.jid.as_utf8(),))
        self.connection = CONNECTION.error

    def subscribe(self, presence):
        dbg("subscribe: presence:\n%s" % (fmt_evt(presence),))

        resp = presence.make_accept_response()
        dbg("  resp:\n%s" % (fmt_evt(resp),))
        self.safe_send(resp)
        
    def vipadia_iq(self, iq):
        dbg("vipadia_iq:\n%s" % (fmt_evt(iq),), 3)

        items = iq.xpath_eval("v:query/v:item", { "v": "http://vipadia.com/skype", })
        for item in items:
            jid = JID(item.prop("dialback"))
            (_, screen, _) = jid.resource.split(":")
            secret = item.prop("secret")
            skypeuser = item.prop("skypeuser")
            skypesecret = item.prop("skypesecret")
            xmppujid = item.prop("xmppujid")
            mode = item.prop("mode")
            marketing_message = item.prop("marketing-message")

            argstring = base64.b64encode(
                "%s\0%s\0%s\0%s\0%s\0%s\0%s\0%s\0%s\0%s" % (
                jid.as_utf8(), secret,
                skypeuser, skypesecret, xmppujid,
                mode, self.config.master, self.config.muc,
                "%s@%s" % (self.config.slave, self.config.domain),
                marketing_message,
                ))
            cmd = [ "./karaka/bundle.sh", screen, argstring ] 
            dbg("  cmd:%s"  % (cmd,))
            ps = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        
        return True

################################################################################

def slave_keepalive():    
    name = sys.argv[1]
    config = slaveconfig.SlaveConfig(name)

    global Slave
    Slave = SkypeSlave(config)

    keepalive = Iq(to_jid=config.domain, stanza_type="set")
    keptalive = 0

    while Slave.running:
        try:
            if Slave.connection == CONNECTION.idle:
                dbg("slave connecting")
                Slave.connect()                
                Slave.connection = CONNECTION.connecting
                    
            elif Slave.connection == CONNECTION.connecting:
                dbg("slave connecting...")
                if Slave.stream: Slave.stream.loop_iter(1)
                
            elif Slave.connection == CONNECTION.connected:
                dbg("looping slave")
                if Slave.stream: Slave.stream.loop_iter(1)
                
                Slave.idle()
                now = time.time()
                if now - keptalive > 60:
                    dbg("slave keepalive! %s" % (fmt_evt(keepalive),), 5)
                    Slave.safe_send(keepalive)
                    keptalive = now

            elif Slave.connection == CONNECTION.error:
                Slave.connection = CONNECTION.idle
        
        except Exception, exc:
            log_stacktrace(exc)
            try:
                Slave.disconnect()
            except Exception, exc:
                err("second chance!  failing")
                log_stacktrace(exc)
            
            Slave.connection = CONNECTION.error

    log("slave exit: jid:%s" % (Slave.jid.as_utf8(),))

################################################################################

if __name__ == '__main__':

    try:
        try:
            print WELCOME_MSG
            
            signal.signal(signal.SIGINT, sigkill_handler)
            signal.signal(signal.SIGTERM, sigkill_handler)

            openlog()
            if len(sys.argv) < 2:
                die("Karaka slave requires a name: ./slave.py <slavename>")
                
            name = sys.argv[1]
            PIDFILE = PIDFILE % (name,)
            
            if check_running(PIDFILE):
                die("Karaka slave already runnning - check %s" % (PIDFILE,))

            ## unicode magic
            locale.setlocale(locale.LC_CTYPE, "")
            encoding = locale.getlocale()[1]
            if not encoding: encoding = "us-ascii"
            sys.stdout = codecs.getwriter(encoding)(sys.stdout, errors="replace")
            sys.stderr = codecs.getwriter(encoding)(sys.stderr, errors="replace")

            ## pyxmpp logger setup
            logger = logging.getLogger()
            logger.addHandler(logging.FileHandler(LOGFILE % (sys.argv[1],)))
            logger.setLevel(logging.DEBUG) # change to DEBUG for higher verbosity

            ## master
            slave_thread = threading.Thread(name="Slave", target=slave_keepalive)
            slave_thread.setDaemon(True)
            slave_thread.start()
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
                        print "Status = %s" % Slave.connection                

                    elif cmd[0] == 'debug':
                        if len(cmd) == 2: Debug = int(cmd[1])
                        print "Debug = %s" % Debug
                        
            except IOError, ioe:
                if ioe.errno == 4: ## interrupted system call
                    err("exception due to signal handling; ignore")
                    log_stacktrace(ioe)

            except EOFError: 
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
