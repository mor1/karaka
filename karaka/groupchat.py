#
# Karaka Skype-XMPP Gateway: Master MUC manager
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

import threading, md5

from pyxmpp.all import JID, Message
from pyxmpp.jabberd.component import Component
from pyxmpp.stanza import Stanza

from common import *
from common import _dbg
Debug = 5
def dbg(s, l=0):
    if Debug > l: _dbg(s)

StLock = threading.RLock()
St = {
    'conferences': {},                 # { confid: (dialback-jid,user-jid) }
    }

################################################################################

def groupchatid(chatid):
    return md5.new(chatid).hexdigest()

class Muc(Component):

    def __init__(self, config):
        log("muc: jid:%s" % (config.muc,))
        
        self.connection = CONNECTION.idle
        self.running = True
        self.config = config
        Component.__init__(
            self, JID(config.muc), config.secret, config.server, int(config.port),
            disco_name="Vipadia Ltd Skype Muc Gateway",
            )

        self.disco_info.add_feature('http://jabber.org/protocol/disco#info')
        self.disco_info.add_feature('jabber:iq:version')
        
    def safe_send(self, stanza):
        to = stanza.get_to()
        if not to.domain.endswith(self.config.domain): to = to.bare()
            
        stanza = Stanza(stanza, to_jid=to)
        self.stream.send(stanza)

    def stream_state_changed(self,state,arg):
        dbg("stream_state_changed: %s %r" % (state, arg))

    def disconnected(self):
        log("master groupchat disconnected! jid:%s" % (self.jid,))        
        self.connection = CONNECTION.error
        
    def authenticated(self):
        dbg("authenticated: jid:%s" % (self.jid.as_utf8(),))
        
        Component.authenticated(self)
        
        self.connection = CONNECTION.connected
        
        self.stream.set_iq_get_handler("query", "jabber:iq:version",  self.get_version)
        self.stream.set_iq_set_handler(
            "command", "http://vipadia.com/skype", self.vipadia_command)
        self.stream.set_presence_handler("available",    self.presence)
        self.stream.set_presence_handler("unavailable",  self.presence)
        self.stream.set_message_handler("normal", self.message)

    #
    # iq handlers
    #

    def get_version(self, iq):
        dbg("get_version:\n%s" % (fmt_evt(iq),))
        StLock.acquire()
        try:
            iq = iq.make_result_response()
            q = iq.new_query("jabber:iq:version")
            add_child(q, "name", q.ns(), "Vipadia Skype Gateway: MUC")
            add_child(q, "version", q.ns(), "1.0")

            self.safe_send(iq)
            return True
        finally:
            StLock.release()
            
    def vipadia_command(self, iq):
        dbg("vipadia_command:\n%s" % (fmt_evt(iq),))
        StLock.acquire()
        try:
            items = iq.xpath_eval("v:command/v:item", { "v": "http://vipadia.com/skype", })
            for item in items:
                command = item.prop("command")
                if command == "create-muc":
                    chatid = item.prop("chatid") # skype chat name
                    jid = JID(item.prop("jid"))
                    member = item.prop("member")

                    gid = groupchatid(chatid)

                    # populate St['conferences']
                    St['conferences'][gid] = (iq.get_from(),jid)

                    invite = Message(from_jid="%s@%s" % (gid, self.config.muc),
                                     to_jid=jid,
                                     )
                    x = invite.add_new_content("http://jabber.org/protocol/muc#user", "x")
                    add_child(add_child(x, "invite",
                                        attrs={"from": "%s@%s" % (member, self.config.component)}
                                        ), "reason", value=Msgs.join_chat)
                    add_child(x, "password")
                    self.safe_send(invite)

                    result = iq.make_result_response()
                    q = result.new_query("http://vipadia.com/skype", "command")
                    add_child(q, "item", attrs={"command": "create-muc",
                                                "gid": gid,
                                                "chatid": chatid})
                    self.safe_send(result)

                elif command == "destroy-muc":
                    gid = item.prop("gid") # skype chat name
                    if gid in St['conferences']:
                        # Tidy up
                        del St['conferences'][gid]

                        result = iq.make_result_response()
                        q = result.new_query("http://vipadia.com/skype", "command")
                        add_child(q, "item", attrs={"command": "destroy-muc",
                                                    "gid": gid})

                        self.safe_send(result)

                else:
                    err("unknown command!  command:%s\n%s" % (command, fmt_evt(iq),))

            return True
        finally:
            StLock.release()

    #
    # presence handler
    #

    def presence(self, stanza):
        dbg("presence:\n%s" % (fmt_evt(stanza),))
        StLock.acquire()
        try:
            frm = stanza.get_from()
            to = stanza.get_to()
            confid = to.node

            if confid not in St['conferences']:
                dbg("unknown confid!  confid:%s" % (confid,))
                return True

            (djid, ujid) = St['conferences'][confid]
            dbg("  djid:%s ujid:%s" % (djid.as_utf8(), ujid.as_utf8()))
            if (frm == djid):
                ## from the bundle
                stanza.set_to(ujid)
                stanza.set_from(to)
                self.safe_send(stanza)

            elif (frm.bare() == ujid): ## from the user
                stanza.set_to(djid)
                stanza.set_from(to)
                self.safe_send(stanza)

            return True
        finally:
            StLock.release()

    #
    # message handler
    #

    def message(self, stanza):
        dbg("message:\n%s" % (fmt_evt(stanza),))
        StLock.acquire()
        try:
            frm = stanza.get_from()
            to = stanza.get_to()
            confid = to.node

            if confid not in St['conferences']:
                dbg("unknown confid!  confid:%s" % (confid,))
                return True

            (djid, ujid) = St['conferences'][confid]

            if (frm == djid):
                ## from the bundle - will have the resource in already
                stanza.set_to(ujid)
                stanza.set_from(to)
                self.safe_send(stanza)

            elif (frm.bare() == ujid):
                ## from the user
                stanza.set_to(djid)
                stanza.set_from(to)
                self.safe_send(stanza)

            return True

        finally:
            StLock.release()
        
################################################################################

if __name__ == '__main__': pass
