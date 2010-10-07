#
# Karaka Skype-XMPP Gateway: Customer API
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

import time
import MySQLdb

##
## Copied from common.py
##  DO NOT EDIT
##
import syslog
def _log(level, mesg):
    if "\n" in mesg: mesgs = mesg.split("\n")
    else: mesgs = [mesg]

    pfx = ""
    for mesg in mesgs:
        while len(mesg) > 254:
            syslog.syslog(level, "%s%s" % (pfx, mesg[:254].encode("utf-8"),))
            mesg = "%s" % mesg[254:]
            pfx = "||"
        syslog.syslog(level, "%s%s" % (pfx, mesg.encode("utf-8")))
        pfx = "|"                      

def _dbg(s): _log(syslog.LOG_DEBUG, s)
##
## End
##

from apiconfig import APIConfig

## # Crypto - KeyCzar
## from keyczar import keyczar
## PRIVATE_KEYLOC="/etc/karaka/keys/private/"
## PUBLIC_KEYLOC="/etc/karaka/keys/public/"

# Debug
Debug = 6
def dbg(s, l=0):
    if Debug > l: _dbg(s)

##
## Database API
##  Invoked by MASTER to persist registrations and CDRs
##-----------------------------------------------------
class DatabaseAPI:
    def __init__(self):
        self.config = APIConfig()

        self.conn = MySQLdb.connect(
            self.config.sql_server, self.config.sql_user, self.config.sql_password,
            self.config.sql_database)
        self.conn.autocommit(True)
        
    def _invoke(self, cmd, args=None):
        dbg("_invoke: cmd:%s args:%s" % (cmd, args), 5)
        cursor = self.conn.cursor()
        nrows = cursor.execute(cmd, args)
        rows = cursor.fetchall() 
        cursor.close()
        dbg("  nrows:%s rows:%s" % (nrows, rows,), 5)
        return (nrows, rows)

    ## set_credentials_plain(user-jid, skype-handle, skype-secret) -> (bool, reason)
    ##   insert credentials into the database for this user
    def set_credentials_plain(self, userjid, skypeuser, skypesecret):
        # Encrypt before writing to DB
        dbg("set_credentials: userjid:%s skypeuser:%s skypesecret:*" % (
            userjid, skypeuser), 4)
        ## KeyCzar
##         crypter = keyczar.Encrypter.Read(PUBLIC_KEYLOC)
##         skypesecret = crypter.Encrypt(str(skypesecret))

        dbg("  encrypt(skypesecret):%s" % (skypesecret,), 4)
        
        cmd = "INSERT INTO registrations (userjid, user, secret) VALUES (%s, %s, %s)"
        args = (userjid, skypeuser, skypesecret,)
        (cnt, res) = self._invoke(cmd, args)
        dbg("  cnt:%d res:%s" % (cnt, res), 4)
        return (True, "Success")

    ## remove_credentials(user-jid)
    ##   delete credentials from the database for this user
    def remove_credentials(self, userjid):
        dbg("remove_credentials: userjid:%s" % (userjid,), 4)

        cmd = "DELETE FROM registrations WHERE userjid=%s"
        args = (userjid,)
        (cnt, res) = self._invoke(cmd, args)
        dbg("  cnt:%d res:%s" % (cnt, res), 4)

    ## get_credentials_crypt(user-jid) -> (skype-user, encrypted-skype-password)
    ##   retrieve credentials (enctypted password) for this user
    def get_credentials_crypt(self, userjid):
        dbg("get_credentials: userjid:%s" % (userjid,), 4)

        cmd = "SELECT user, secret FROM registrations WHERE userjid=%s"
        args = (userjid,)
        (cnt, res) = self._invoke(cmd, args)
        dbg("  cnt:%d res:%s" % (cnt, res), 4)
        if not res: return res
        return (res[0][0], res[0][1])

    ## get_marketing_message(user-jid)
    ##   retrieve mood message prefix
    def get_marketing_message(self, userjid):
        dbg("get_marketing_message: userjid:%s" % (userjid,), 4)
        return self.config.marketing_message

    ## log_start(user-jid, skype-user)
    ##   record the start event for a user signing in
    def log_start(self, userjid, skypehandle):
        dbg("log_start: user:%s skypehandle:%s" % (userjid, skypehandle), 4)
        now = time.time()
        cmd = "INSERT INTO log (userjid, skypehandle, at, event, message) " \
              + " VALUES (%s,%s,%s,%s,%s)"
        args = (userjid, skypehandle, now, "start", "")
        self._invoke(cmd, args)

    ## log_stop(user-jid, skype-user)
    ##   record the stop event for a user signing out
    def log_stop(self, userjid, skypehandle):
        dbg("log_stop: user:%s skypehandle:%s" % (userjid, skypehandle), 4)
        now = time.time()
        cmd = "INSERT INTO log (userjid, skypehandle, at, event, message) " \
              + " VALUES (%s,%s,%s,%s,%s)"
        args = (userjid, skypehandle, now, "stop", "")
        self._invoke(cmd, args)
        
    ## log_error(user-jid, skype-user, errormsg)
    ##   record an error event
    def log_error(self, userjid, skypehandle, errormsg):
        dbg("log_error: user:%s skypehandle:%s errormsg:%s" % (userjid, skypehandle, errormsg), 4)
        now = time.time()
        cmd = "INSERT INTO log (userjid, skypehandle, at, event, message) " \
              + " VALUES (%s,%s,%s,%s,%s)"
        args = (userjid, skypehandle, now, "error", errormsg)
        self._invoke(cmd, args)
        
#
# Cryptography API
#  Invoked by individual BUNDLE to decode credentials
#----------------------------------------------------
class CryptoAPI:
    def __init__(self): pass

    ## decrypt(encrypted-skype-password) -> skype-password
    ##   decrypt the given input password
    def decrypt(self, inputtext):
        ## KeyCzar
##         crypter = keyczar.Crypter.Read(PRIVATE_KEYLOC)
##         return crypter.Decrypt(inputtext)
        return inputtext

