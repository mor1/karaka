#
# Karaka Skype-XMPP Gateway: Master bundle manager
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

import threading

from pyxmpp.all import JID, Iq, Presence
from pyxmpp.jabberd.component import Component
from pyxmpp.stanza import Stanza

from api.api import DatabaseAPI
from common import *
from common import _dbg

Debug = 5
def dbg(s, l=0):
    if Debug > l: _dbg(s)

## CLIENT_MODE = "STANDARDSCOMPLIANT"
## CLIENT_MODE = "CARRIER"
CLIENT_MODE = "GOOGLETALK"

StLock = threading.RLock()
St = {
    'dialbacks': {},         # { dialback-jid: user-bare-jid }
    'dialback_online': {},   # { dialback-jid: DIALBACK() }
    'users': {},             # { user-bare-jid: dialback-jid }
    'userjids': {},          # { user-bare-jid: user-full-jid: None }

    'slaves': {},            # { live-slave-jid: None }
    'slots': {},             # { slave-jid: slave-slot: dialback }
    'dialback_slave': {},    # { dialback: (slave-jid, slave-slot) }
    }

################################################################################

def is_googletalk(): return CLIENT_MODE == "GOOGLETALK"
def is_carrier(): return CLIENT_MODE == "CARRIER"

def get_from(stanza):
    frm = stanza.get_from()
    resource = frm.resource
    if not resource: resource = ""
    return JID("%s@%s/%s" % (frm.node.lower(), frm.domain.lower(), resource))

class Master(Component):

    def __init__(self, config):
        log("master: jid:%s" % (config.component,))
        
        self.running = True
        self.connection = CONNECTION.idle

        self.config = config
        self.regdb = DatabaseAPI()
        
        Component.__init__(
            self, JID(config.component), config.secret, config.server, int(config.port),
            disco_name="Vipadia Ltd Skype Gateway",
            disco_type="skype", disco_category="gateway",
            )

        self.disco_info.add_feature('http://jabber.org/protocol/disco#info')
        self.disco_info.add_feature('jabber:iq:register')
        self.disco_info.add_feature('jabber:iq:time')
        self.disco_info.add_feature('jabber:iq:version')
        self.disco_info.add_feature('http://jabber.org/protocol/rosterx')

    def is_valid_slave(self, frm, digest):
        return (generate_slave_digest(frm, self.config.slave_secret)
                == digest)

    def safe_send(self, stanza):
        dbg("safe_send:\n%s" % (fmt_evt(stanza),))
        to = stanza.get_to()
        if (to.node == self.config.dialback
            and to.domain.endswith(self.config.domain)):

            ## if this is to a dialback that is *not* online, swallow it rather
            ## than forwarding

            ## if it is an unavailable, that's always safe and may be a suicide
            ## note to a dialback that surprised us or didn't start properly so
            ## send it anyway

            if (get_presence(stanza) != "unavailable"
                and not (to in St['dialback_online']
                         and St['dialback_online'][to] == DIALBACK.online)):
                
                err("destination dialback not online!  dbo:%s stanza:\n%s" % (
                    (to in St['dialback_online'] and St['dialback_online'][to] or "None"),
                    fmt_evt(stanza)))
                return True            

        ## if this is *not* an iq and *not* to a dialback, strip the destination
        ## jid
        if (not is_iq(stanza) and not to.domain.endswith(self.config.domain)):
            to = to.bare()
            
        stanza = Stanza(stanza, to_jid=to)
        dbg("tx:\n%s" % (fmt_evt(stanza),))
        self.stream.send(stanza)
        
    def stream_state_changed(self,state,arg):
        dbg("stream_state_changed: %s %r" % (state, arg))

    def disconnected(self):
        log("master chat disconnected! jid:%s" % (self.jid,))
        self.connection = CONNECTION.error
        
    def authenticated(self):
        dbg("authenticated: jid:%s" % (self.jid.as_utf8(),))
        
        self.connection = CONNECTION.connected
        Component.authenticated(self)
        
        self.stream.set_iq_get_handler("query", "jabber:iq:version",  self.get_version)
        self.stream.set_iq_get_handler("query", "jabber:iq:register", self.get_register)
        self.stream.set_iq_set_handler("query", "jabber:iq:register", self.set_register)

        self.stream.set_presence_handler("available",    self.presence_available)
        self.stream.set_presence_handler("unavailable",  self.presence_unavailable)
        self.stream.set_presence_handler("error",        self.presence_error)        
        self.stream.set_presence_handler("probe",        self.probe)        

        self.stream.set_presence_handler("subscribe",    self.subscribe)
        self.stream.set_presence_handler("subscribed",   self.subscribed)

        self.stream.set_presence_handler("unsubscribe",  self.unsubscribe)
        self.stream.set_presence_handler("unsubscribed", self.unsubscribed)

        ## default handlers
        self.stream.set_message_handler("normal", self.default_handler)

        self.default_presence_handler = self.stream.process_presence
        self.stream.process_presence = self.default_handler

        ## not possible to set a default IQ handler since all IQs either handled
        ## by user handler, or cause feature-not-implemented or bad-request to
        ## be sent
        
        self.stream.set_iq_set_handler(
            "x", "http://jabber.org/protocol/rosterx", self.default_handler)
        self.stream.set_iq_set_handler(
            "command", "http://vipadia.com/skype", self.vipadia_command)

    def default_handler(self, stanza):
        dbg("default_handler:\n%s" % (fmt_evt(stanza),))
        StLock.acquire()
        try:
            if stanza.stanza_type == "presence":
                handled = self.default_presence_handler(stanza)
                if handled: return True

            frm = get_from(stanza)
            dbg("  frm:%s node:%s domain:%s resource:%s config:%s,%s" % (
                frm.as_utf8(), frm.node, frm.domain, frm.resource,
                self.config.dialback, self.config.domain))

            if (frm.node, frm.domain) == (self.config.dialback, self.config.domain):
                ## ...from dialback
                djid = frm
                if djid not in St['dialbacks']: return True

                ujid = St['dialbacks'][djid]
                hsh = "%s" % (hash(ujid),)
                if not frm.resource.endswith(hsh):
                    err("*** SPOOFED MESSAGE DETECTED ***")
                    err("    ujid:%s hash(ujid):%s frm:%s" % (ujid.as_utf8(), hsh, frm.as_utf8()))
                    err(fmt_evt(stanza))
                    err("*** DIE DIE DIE ***")
                    os._exit(os.EX_PROTOCOL)

                if stanza.stanza_type == "iq":
                    userjids = St['userjids'][ujid].keys()
                    forward = Stanza(stanza, to_jid=userjids[0], from_jid=stanza.get_to())
                else:
                    forward = Stanza(stanza, to_jid=ujid, from_jid=stanza.get_to())

            else: ## ...from the user
                ujid = frm.bare()
                dbg("  frm:%s ujid:%s users:%s" % (
                    frm.as_utf8(), ujid.as_utf8(), St['users'].keys()))
                if ujid not in St['users']: return True

                djid = St['users'][ujid]
                dbg("  djid:%s to:%s" % (djid.as_utf8(), stanza.get_to().as_utf8(),))
                forward = Stanza(stanza, to_jid=djid, from_jid=stanza.get_to())

            dbg("  forward:\n%s" % (fmt_evt(forward),))
            if stanza.stanza_type == "message" and stanza.get_body() == None:
                dbg("  not forwarding blank message!")
                return True

            self.safe_send(forward)
            return True
        finally:
            StLock.release()
            
    #
    # iq handlers
    #

    def get_register(self, iq):
        dbg("get_register:\n%s" % (fmt_evt(iq),))
        StLock.acquire()
        try:
            iq = iq.make_result_response()
            q = iq.new_query("jabber:iq:register")
            add_child(q, "instructions", ns=q.ns(),
                      value="Please provide Skype username and password")
            add_child(q, "username", ns=q.ns())
            add_child(q, "password", ns=q.ns())

            self.safe_send(iq)
            return True
        finally:
            StLock.release()
            
    def set_register(self, iq):
        #dbg("set_register:\n%s" % (fmt_evt(iq),))
        # Do not log the password
        dbg("set_register: from:%s to:%s" % (
            iq.get_from().as_utf8(), iq.get_to().as_utf8()))
        StLock.acquire()
        try:
            frm = get_from(iq)
            to = iq.get_to()
            removes = iq.xpath_eval("reg:query/reg:remove", { "reg": "jabber:iq:register", })
            if len(removes) > 0:
                self.regdb.remove_credentials(frm.bare().as_utf8())

                self.safe_send(Presence(
                    from_jid=to, to_jid=frm.bare(), stanza_type="unsubscribe"))
                self.safe_send(Presence(
                    from_jid=to, to_jid=frm.bare(), stanza_type="unsubscribed"))
                self.safe_send(Presence(
                    from_jid=to, to_jid=frm.bare(), stanza_type="unavailable"))
                
                return True

            usernames = iq.xpath_eval("reg:query/reg:username", { "reg": "jabber:iq:register", })
            username = usernames[0].getContent()
            passwords = iq.xpath_eval("reg:query/reg:password", { "reg": "jabber:iq:register", })
            password = passwords[0].getContent()

            ## check username/password for validity...
            if ("'" in username or '"' in username or ' ' in username or ' ' in password):
                self.safe_send(iq.make_error_response("not-acceptable"))
                return True
                
            ujid = frm.bare().as_utf8()
            self.regdb.remove_credentials(ujid)
            self.regdb.set_credentials_plain(ujid, username, password)

            self.safe_send(iq.make_result_response())
            self.safe_send(Presence(
                from_jid=to, to_jid=frm, stanza_type="subscribe",))

            return True

        finally:
            StLock.release()

    def get_version(self, iq):
        dbg("get_version:\n%s" % (fmt_evt(iq),))
        StLock.acquire()
        try:
            iq = iq.make_result_response()
            q = iq.new_query("jabber:iq:version")
            add_child(q, "name", q.ns(), "Vipadia Skype Gateway: MASTER")
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
                if command == "subscribe":
                    djid = JID(item.prop("djid"))

                    if djid not in St['dialbacks']:
                        self.safe_send(iq.make_result_response())
                        return True

                    self.safe_send(Presence(
                        to_jid=St['dialbacks'][djid], from_jid=item.prop("from"),
                        stanza_type="subscribe"))

                elif command == "subscribed":
                    frm = JID("%s@%s" % (item.prop("from"), self.config.component))

                    ujid = St['dialbacks'][get_from(iq)]
                    self.safe_send(Presence(
                        to_jid=ujid, from_jid=frm, stanza_type="subscribed"))

                elif command == "register-subscribe":
                    jid = JID(item.prop("jid"))
                    self.safe_send(Presence(
                        to_jid=jid.bare(), from_jid=self.config.component, stanza_type="subscribe"))

                elif command == "register-available":
                    jid = JID(item.prop("jid"))
                    fake_available = Presence(to_jid=self.config.component, from_jid=jid)
                    self.presence_available(fake_available)

                elif command == "out-subscribe":
                    frm = JID("%s@%s" % (item.prop("from"), self.config.component))

                    iq_frm = get_from(iq)
                    if iq_frm not in St['dialbacks']:
                        self.safe_send(iq.make_result_response())
                        return True

                    ujid = St['dialbacks'][iq_frm]
                    self.safe_send(Presence(
                        to_jid=ujid, from_jid=frm, stanza_type="subscribe"))                

                elif command == "slave-online":
                    frm = get_from(iq)
                    digest = str(item.prop("digest"))
                    if not self.is_valid_slave(frm.as_utf8(), digest):
                        err("invalid slave!  frm:%s iq:\n%s" % (frm.as_utf8(), fmt_evt(iq)))
                        self.safe_send(iq.make_error_response("forbidden"))
                        return True

                    capacity = int(item.prop("capacity"))
                    base = int(item.prop("base"))

                    St['slaves'][frm] = None                
                    St['slots'][frm] = {}
                    dbg("  before St['slots']:%s" % (St['slots'],))
                    for i in range(base, base+capacity):
                        if i not in St['slots'][frm]: St['slots'][frm][i] = None
                    dbg("  after St['slots']:%s" % (St['slots'],))

                    self.safe_send(Presence(
                        to_jid=frm, from_jid=self.config.component, stanza_type="subscribe"))

                elif command == "spawn":
                    ujid = item.prop("ujid")
                    skypeuser = item.prop("skypeuser")
                    skypesecret = item.prop("skypesecret")
                    
                    errstr = self._spawn(JID(ujid), skypeuser, skypesecret)
                    if errstr: err("_spawn error!  errstr:%s" % (errstr,))

                else:
                    err("unknown command!  command:%s\n%s" % (command, fmt_evt(iq),))
                    self.safe_send(iq.make_error_response("feature-not-implemented"))
                    return True

            self.safe_send(iq.make_result_response())
            return True
        finally:
            StLock.release()

    #
    # presence handlers
    #

    def probe(self, stanza):
        dbg("probe:\n%s" % (fmt_evt(stanza,)))
        StLock.acquire()
        try:
            to = stanza.get_to()
            if (to.node, to.domain) == (None, self.config.component):
                ## probe to us
                self.safe_send(Presence(from_jid=self.config.component, to_jid=get_from(stanza)))

            elif to.domain == self.config.component:
                frm = get_from(stanza)
                ujid = frm.bare()
                if ujid not in St['users']:
                    err("probe from unknown user!  ujid:%s" % (ujid.as_utf8(),))
                    return True

                djid = St['users'][ujid]
                if (djid not in St['dialback_online']
                    or (djid in St['dialback_online']
                        and St['dialback_online'][djid] == DIALBACK.pending
                        )):
                    return True
                
                iq = Iq(to_jid=djid, from_jid=self.config.component, stanza_type="set")
                command = iq.new_query("http://vipadia.com/skype", "command")
                add_child(command, "item", attrs={ "command": "probe",
                                                   "from": to.node,
                                                   })
                dbg("  probe:\n%s" % (fmt_evt(iq),))
                self.safe_send(iq)

            return True
        finally:
            StLock.release()
        
    def presence_available(self, stanza):
        dbg("presence_available:\n%s" % (fmt_evt(stanza),))
        StLock.acquire()
        try:
            global St

            frm = get_from(stanza) ## FFS.  GoogleTalk
            ujid = frm.bare()
            dbg("  frm:%s ujid:%s node:%s domain:%s resource:%s  config:%s,%s" % (
                frm.as_utf8(), ujid.as_utf8(), frm.node, frm.domain, frm.resource,
                self.config.dialback, self.config.domain))

            if (frm.node, frm.domain) == (self.config.dialback, self.config.domain):
                ## from bundle...
                djid = frm
                if djid not in St['dialbacks']:
                    self._send_suicide(djid) # tell bundle to suicide since it surprised us
                    return True

                to = stanza.get_to()
                if to.node: # ...for a skype jid (user@skype.vipadia.com) -- BUNDLE > USER
                    self.safe_send(Presence(stanza, to_jid=St['dialbacks'][frm], from_jid=to))

                else: # ...for us (master) -- bundle is online -- BUNDLE > MASTER
                    St['dialback_online'][djid] = DIALBACK.online
                    self.safe_send(Presence( # tell user that bundle online
                        stanza, to_jid=St['dialbacks'][djid], from_jid=self.config.component))
                    self.safe_send(Presence( # tell bundle that user online
                        stanza, to_jid=djid, from_jid=self.config.component))

            else: # from the user...
                dbg("  frm:%s St['users']:%s  Dbo:%s" % (
                    frm.as_utf8(), St['users'], St['dialback_online']))
                if (ujid in St['users'] and St['users'][ujid] in St['dialback_online']):
                    # ...which we knew about
                    dbg("  KNOWN JID")
                    djid = St['users'][ujid]
                    if St['dialback_online'][djid] == DIALBACK.online:
                        self.safe_send(Presence(
                            stanza, to_jid=djid, from_jid=self.config.component))
                    if ujid not in St['userjids']: St['userjids'][ujid] = {}
                    St['userjids'][ujid][frm] = None

                else: # ...but this is a new user -- spawn a bundle
                    if is_carrier(): return True

                    usersecret = self.regdb.get_credentials_crypt(ujid.as_utf8())
                    if not usersecret: return True
                    (user, secret) = usersecret

                    errstr = self._spawn(frm, user, secret)
                    if errstr:
                        err("spawn error! errstr:%s presence:\n%s" % (errstr, fmt_evt(stanza),))
                        ret = stanza.make_error_response(errstr)
                        ret.set_from(self.config.component)
                        self.safe_send(ret)

                        ## for the poor clients who haven't the foggiest about the
                        ## above error, send a message
                        if is_googletalk():
                            iq = Iq(to_jid=self.config.register, from_jid=self.config.component,
                                    stanza_type="set")
                            command = iq.new_query("http://vipadia.com/skype", "command")
                            add_child(command, "item", attrs={ "command": "message",
                                                               "message": Msgs.resource_constraint,
                                                               "ujid": ujid.as_utf8(),
                                                               })
                            dbg("  iq:\n%s" % (fmt_evt(iq),))
                            self.safe_send(iq)

            return True

        finally:
            StLock.release()

    def _spawn(self, frm, user, secret):
        dbg("_spawn: frm:%s user:%s secret:%s" % (frm.as_utf8(), user, secret))

        ujid = frm.bare()
        
        ## don't spawn if one already exists for this user
        if ujid in St['users']: return
        
        self.regdb.log_start(ujid.as_utf8(), user) # log it

        (slavejid, screen) = self.allocate_djid()
        if not slavejid: return "resource-constraint"

        djid = JID("%s@%s/%s:%s:%s" % (
            self.config.dialback, self.config.domain, slavejid.node, screen, hash(ujid)))

        dbg("  before avail: St['slots']:%s  St['dialback_slave']:%s" % (
            St['slots'], St['dialback_slave']))
        St['slots'][slavejid][screen] = djid
        St['dialback_slave'][djid] = (slavejid, screen)
        dbg("  after avail: St['slots']:%s  St['dialback_slave']:%s" % (
            St['slots'], St['dialback_slave']))

        St['dialbacks'][djid] = ujid
        St['users'][ujid] = djid
        if ujid not in St['userjids']: St['userjids'][ujid] = {}
        St['userjids'][ujid][frm] = None

        St['dialback_online'][djid] = DIALBACK.pending

        spawn = Iq(to_jid=slavejid, from_jid=self.config.component, stanza_type="set")
        query = spawn.new_query('http://vipadia.com/skype', "query")
        add_child(query, "item",
                  attrs={ "skypeuser": user,
                          "skypesecret": secret,
                          "dialback": djid.as_utf8(),
                          "secret": self.config.dialback_secret,
                          "xmppujid": ujid.as_utf8(),
                          "mode": CLIENT_MODE,
                          "marketing-message": self.regdb.get_marketing_message(frm.as_utf8()),
                          })
        dbg("  spawn:\n%s" % (fmt_evt(spawn),))
        self.safe_send(spawn)

    def presence_unavailable(self, stanza):
        dbg("presence_unavailable:\n%s" % (fmt_evt(stanza),))
        StLock.acquire()
        try:
            global St

            frm = get_from(stanza)
            dbg("frm:%s"% (frm.as_utf8(),))

            if (frm.node, frm.domain) == (self.config.dialback, self.config.domain):
                ## from the bundle
                djid = frm
                dbg("  djid:%s" % (djid.as_utf8(),))
                if djid not in St['dialbacks']:
                    err("unknown bundle!  djid:%s St['dialbacks']:%s" % (
                        djid.as_utf8(), St['dialbacks'],))
                    return True

                if djid not in St['dialback_slave']:
                    err("unknown bundle!  djid:%s St['dialback_slave']:%s" % (
                        djid.as_utf8(), St['dialback_slave'],))
                    return True

                ujid = St['dialbacks'][djid]
                self.safe_send(Presence(
                    to_jid=ujid, from_jid=self.config.component, stanza_type="unavailable"))

                to = stanza.get_to()
                if (to.node, to.domain) == (None, self.config.component):
                    # log it
                    self.regdb.log_stop(ujid.as_utf8(), "")

                    del St['dialbacks'][djid]
                    if djid in St['dialback_online']: del St['dialback_online'][djid]
                    if ujid in St['users']: del St['users'][ujid]
                    if ujid in St['userjids']: del St['userjids'][ujid]

                    dbg("  before unavail: St['slots']:%s  St['dialback_slave']:%s" % (
                        St['slots'], St['dialback_slave']))
                    if djid in St['dialback_slave']:
                        slavejid, screen = St['dialback_slave'][djid]
                        del St['dialback_slave'][djid]
                        if slavejid in St['slaves']: St['slots'][slavejid][screen] = None
                        else:
                            del St['slots'][slavejid][screen]
                            if len(St['slots'][slavejid]) == 0: del St['slots'][slavejid]

                    dbg("  after unavail: St['slots']:%s  St['dialback_slave']:%s" % (
                        St['slots'], St['dialback_slave']))

            elif frm in St['slots']:
                ## from a slave; delete unused slots
                del St['slaves'][frm]
                slots = St['slots'][frm].keys()
                for i in slots:
                    if not St['slots'][frm][i]: del St['slots'][frm][i]
                if len(St['slots'][frm]) == 0: del St['slots'][frm]

            else: ## from the user
                ujid = frm.bare()
                if ujid not in St['users']:
                    dbg("unknown user!  ujid:%s" % (ujid.as_utf8(),))
                    return True

                ## if there are no more resources for this user, then suicide
                if ujid in St['userjids'] and frm in St['userjids'][ujid]:
                    del St['userjids'][ujid][frm]

                    if len(St['userjids'][ujid]) == 0:
                        del St['userjids'][ujid]
                        djid = St['users'][ujid]
                        self._send_suicide(djid)

            return True
        finally:
            StLock.release()

    def _send_suicide(self, djid):
        dbg("_send_suicide: djid:%s" % (djid.as_utf8(),))
        self.safe_send(Presence(
            to_jid=djid, from_jid=self.config.component, stanza_type="unavailable"))
        
    def subscribe(self, stanza):
        dbg("subscribe:\n%s" % (fmt_evt(stanza),))
        StLock.acquire()
        try:
            to = stanza.get_to()
            if to.bare().as_utf8() == self.config.component:
                ## to master
                self.safe_send(stanza.make_accept_response())

            else: ## to user @ skype
                frm = get_from(stanza)
                if frm in St['dialbacks']:
                    ## ...from a dialback: forward on to user
                    ujid = St['dialbacks'][frm]
                    self.safe_send(Stanza(stanza, to_jid=ujid, from_jid=stanza.get_to()))

                else: ## ...from skype user
                    ujid = frm.bare()
                    if ujid not in St['users']: return True
                    djid = St['users'][ujid]

                    iq = Iq(to_jid=djid, from_jid=self.config.component, stanza_type="set")
                    command = iq.new_query("http://vipadia.com/skype", "command")
                    add_child(command, "item", attrs={ "from": "%s" % to.node,
                                                       "command": "subscribe",
                                                       })
                    dbg("  subscribe:\n%s" % (fmt_evt(iq),))
                    self.safe_send(iq)

            return True
        finally:
            StLock.release()

    def subscribed(self, stanza):
        dbg("subscribed:\n%s" % (fmt_evt(stanza),))
        StLock.acquire()
        try:
            to = stanza.get_to()
            if to.bare().as_utf8() == self.config.component:
                ## to master
                pass

            else: ## to user @ skype
                frm = get_from(stanza)
                if frm in St['dialbacks']:
                    ## ...from skype user
                    ujid = St['dialbacks'][frm]
                    self.safe_send(Stanza(stanza, to_jid=ujid, from_jid=stanza.get_to()))

                else: ## ...from a dialback: forward on to user
                    ujid = frm.bare()
                    if ujid not in St['users']: return True
                    djid = St['users'][ujid]

                    iq = Iq(to_jid=djid, from_jid=self.config.component, stanza_type="set")
                    command = iq.new_query("http://vipadia.com/skype", "command")
                    add_child(command, "item", attrs={ "from": "%s" % to.node,
                                                       "command": "subscribed",
                                                       })
                    dbg("  subscribed:\n%s" % (fmt_evt(iq),))
                    self.safe_send(iq)

            return True
        finally:
            StLock.release()

    def unsubscribe(self, stanza):
        dbg("unsubscribe:\n%s" % (fmt_evt(stanza),))
        StLock.acquire()
        try:
            send_response = not (stanza.get_type() == 'subscribed')
            if send_response:
                self.safe_send(stanza.make_accept_response())

            return True
        finally:
            StLock.release()

    def unsubscribed(self, stanza):
        dbg("unsubscribed:\n%s" % (fmt_evt(stanza),))
        StLock.acquire()
        try:
            send_response = not (stanza.get_type() == 'subscribed')
            if send_response:
                self.safe_send(stanza.make_accept_response())

            return True

        finally:
            StLock.release()
            
    def presence_error(self, p):
        dbg("presence_error:\n%s" % (fmt_evt(p),))
        StLock.acquire()
        try:
            djid = get_from(p)
            if djid in St['dialbacks']:
                to = St['dialbacks'][djid]
                p.set_from(p.get_to())
                p.set_to(to)
                self.safe_send(p)

                if is_googletalk():
                    iq = Iq(to_jid=self.config.register,
                            from_jid=self.config.component, stanza_type="set")
                    command = iq.new_query("http://vipadia.com/skype", "command")
                    add_child(command, "item", attrs={ "command": "message",
                                                       "message": Msgs.bad_credentials,
                                                       "ujid": to.as_utf8(),
                                                       })
                    dbg("  iq:\n%s" % (fmt_evt(iq),))
                    self.safe_send(iq)

            return True
        finally:
            StLock.release()

    #
    # helpers
    #

    def allocate_djid(self):
        dbg("allocate_djid:")
        StLock.acquire()
        try:
            u = 0
            chosen = None
            for slave in St['slaves']:
                empty_slots = [ s for s in St['slots'][slave] if St['slots'][slave][s] == None ]
                if len(empty_slots) > u:
                    u = len(empty_slots)
                    chosen = slave
                    dbg("  u:%s chosen:%s"  % (u, chosen.as_utf8()))

            if not chosen: rv = (None, 0)
            else:
                for i in St['slots'][chosen]:
                    if St['slots'][chosen][i]: continue
                    rv = (chosen, i)
                    break
            return rv

        finally:
            StLock.release()
        
################################################################################

if __name__ == '__main__': pass
