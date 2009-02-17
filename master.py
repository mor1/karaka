#!/usr/bin/env python
#
# Karaka Skype-XMPP Gateway: Master controller
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

import sys, os, logging, locale, codecs, time, signal, threading, pprint

from pyxmpp.all import Iq

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

Karaka Master Controller
"""
   
GOING_MSG = "Karaka Master Controller exiting - cleaning up..."
GONE_MSG = """\
Karaka Master exited - goodbye!
"""

HELP_MSG = """\
Commands are:
copying   | show license information pertaining to copying
debug [n] | show debug level, or set it to n
help      | show this help message
quit      | quit the slave
state     | show bundle state
status    | show connection status
warranty  | show license information pertaining to warranty
"""

LOGFILE = "/tmp/karaka_master.log"
PIDFILE = "/tmp/karaka_master.pid"
CHAT_PKLFILE = "/tmp/karaka_master_chat.pkl"
GROUPCHAT_PKLFILE = "/tmp/karaka_master_groupchat.pkl"
PROMPT = 'karaka master> '

Running = True
Master = None
Master_thread = None
Muc = None
Muc_thread = None

def sigkill_handler(signal, frame):
    err("signal: %s" % signal)
    global Running
    Running = False

################################################################################

def master_keepalive():    
    config = masterconfig.MasterConfig()
    
    global Master
    Master = chat.Master(config)

    keepalive = Iq(to_jid=config.domain, from_jid=config.component, stanza_type="set")
    keptalive = 0

    while Master.running:
        try:
            if Master.connection == CONNECTION.idle:
                dbg("master connecting")
                Master.connect()                
                Master.connection = CONNECTION.connecting

            elif Master.connection == CONNECTION.connecting:
                dbg("master connecting...")
                if Master.stream: Master.stream.loop_iter(1)

            elif Master.connection == CONNECTION.connected:
                dbg("looping master")
                if Master.stream: Master.stream.loop_iter(1)

                Master.idle()
                now = time.time()
                if now - keptalive > 60:
                    dbg("master keepalive! %s" % (fmt_evt(keepalive),), 5)
                    Master.stream.send(keepalive)
                    keptalive = now

            elif Master.connection == CONNECTION.error:
                Master.connection = CONNECTION.idle

        except Exception, exc:
            log_stacktrace(exc)
            try:
                Master.disconnect()
            except Exception, exc:
                err("second chance!  failing")
                log_stacktrace(exc)

            Master.connection = CONNECTION.error
            time.sleep(1)
            
    log("master exit: jid:%s" % (Master.jid.as_utf8(),))

def muc_keepalive():
    config = masterconfig.MasterConfig()
    
    global Muc
    Muc = groupchat.Muc(config)

    keepalive = Iq(to_jid=config.domain, from_jid=config.muc, stanza_type="set")
    keptalive = 0
 
    while Muc.running:
        try:
            if Muc.connection == CONNECTION.idle:
                dbg("muc connecting")
                Muc.connect()
                Muc.connection = CONNECTION.connecting

            elif Muc.connection == CONNECTION.connecting:
                dbg("muc connecting...")
                if Muc.stream: Muc.stream.loop_iter(1)
                Muc.idle()

            elif Muc.connection == CONNECTION.connected:
                dbg("looping muc")
                if Muc.stream: Muc.stream.loop_iter(1)
                Muc.idle()
                now = time.time()
                if now - keptalive > 60:
                    dbg("muc keepalive! %s" % (fmt_evt(keepalive),), 5)
                    Muc.stream.send(keepalive)
                    keptalive = now

            elif Muc.connection == CONNECTION.error:
                Muc.connection = CONNECTION.idle

        except Exception, exc:
            log_stacktrace(exc)
            try:
                Muc.disconnect()
            except Exception, exc:
                err("second chance!  failing")
                log_stacktrace(exc)

            Muc.connection = CONNECTION.error
            time.sleep(1)

    log("muc exit: jid:%s" % (Muc.jid.as_utf8(),))

################################################################################

if __name__ == '__main__':
    try:
        try:
            print WELCOME_MSG

            signal.signal(signal.SIGINT, sigkill_handler)
            signal.signal(signal.SIGTERM, sigkill_handler)
            openlog()

            if check_running(PIDFILE):
                die("Karaka already runnning - check %s" % PIDFILE)

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
            Master_thread = threading.Thread(name="Master", target=master_keepalive)
            Master_thread.setDaemon(True)
            Master_thread.start()
            time.sleep(1)

            ## groupchat
            Muc_thread = threading.Thread(name="MUC", target=muc_keepalive)
            Muc_thread.setDaemon(True)
            Muc_thread.start()

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
                    
                    elif cmd[0] == 'debug':
                        if len(cmd) == 2: Debug = int(cmd[1])
                        print "Debug = %s" % Debug

                    elif cmd[0] in 'state':
                        chat.StLock.acquire()
                        pprint.pprint(chat.St)
                        chat.StLock.release()

                        groupchat.StLock.acquire()
                        pprint.pprint(groupchat.St)
                        groupchat.StLock.release()

                    elif cmd[0] in 'status':
                        print "Status = master:%s, muc:%s" % (
                            Master.connection, Muc.connection)

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
        if Master_thread: Master_thread.running = False
        if Muc_thread: Muc_thread.running = False

        print GONE_MSG
        os._exit(os.EX_OK)
