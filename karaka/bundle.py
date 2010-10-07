#!/usr/bin/env python
#
# Karaka Skype-XMPP Gateway: Skype instance manager ("bundle")
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

import sys, logging, locale, codecs, subprocess, time, os, threading, signal, base64
import Skype4Py

from pyxmpp.all import JID, Iq, Presence, Message
from pyxmpp.jabber.client import JabberClient
from pyxmpp import streamtls

from api.api import CryptoAPI 

from common import *
from common import _dbg
Debug = 6
def dbg(s, l=0):
    if Debug > l: _dbg(s)

Bundle = None

SKYPE_ATTEMPTS = 5

CONFIG_XML = """<?xml version="1.0"?>
<config version="1.0" serial="6" timestamp="%s">
  <Lib>
    <Account>
      <IdleTimeForAway>30000000</IdleTimeForAway>
      <IdleTimeForNA>300000000</IdleTimeForNA>
      <LastUsed>%d</LastUsed>
    </Account>
  </Lib>
  <UI>
    <API>
      <Authorizations>Skype4Py</Authorizations>
      <BlockedPrograms></BlockedPrograms>
    </API>
  </UI>
</config>"""

SHARED_XML = """<?xml version="1.0"?>
<config version="1.0" serial="10" timestamp="%s">
  <UI>
    <Installed>2</Installed>
    <Language>en</Language>
  </UI>
</config>"""

ChatIDs = {}     # { chatid: gid }
GIDs = {}        # { gid: chatid }
Nicks = {}       # { gid: nick }
Msgs = {}        # { chatid: [ Msg, ... ] }
Members = {}     # { chatid: handle: None }
Declines = {}    # { }

Mode = None 
Master = None
Muc = None
Slave = None
Marketing_message = None

class MembersLock:
    def __init__(self):
        dbg("creating MembersLock")
        self._lock = threading.RLock()
        dbg("created MembersLock")

    def acquire(self):
        dbg("acquire")
        self._lock.acquire()
        
    def release(self):
        dbg("release")
        self._lock.release()
                                      
MembersLock = MembersLock()

################################################################################

def is_googletalk(): return (Mode == "GOOGLETALK")

def destroy_muc(gid):
    dbg("  destroy-muc: gid:%s" % (gid,))
    iq = Iq(to_jid=Muc, stanza_type="set")
    command = iq.new_query("http://vipadia.com/skype", "command")
    add_child(command, "item", attrs={ "command": "destroy-muc",
                                       "gid": gid,
                                       })
    Bundle.safe_send(Iq(iq))

class SkypeBundle(JabberClient):

    def __init__(self, jid, secret, skypeuser, skypesecret, xmppujid):
        dbg("creating bundle: jid:%s secret:%s skypeuser:%s skypesecret:%s xmppujid:%s" % (
            jid.as_utf8(), secret, skypeuser, skypesecret, xmppujid.as_utf8()), 3)

        self.running    = True
        self.attached   = False           # skype
        self.connection = CONNECTION.idle # xmppp
        
        self.jid         = jid
        self.secret      = secret
        self.skypeuser   = skypeuser
        self.skypesecret = CryptoAPI().decrypt(skypesecret)
        self.skype_ps    = None
        self.xmppujid    = xmppujid
        
        tls = streamtls.TLSSettings(require=False, verify_peer=False)
        auth = [ 'digest' ]

        JabberClient.__init__(self, jid, secret,
            disco_name="Vipadia Skype Gateway Bundle", disco_type="bot",
            tls_settings=tls, auth_methods=auth)

        self.disco_info.add_feature("jabber:iq:version")

    def stream_state_changed(self, state, arg):
        dbg("stream_state_changed: %s %r" % (state, arg), 3)
        
    def disconnected(self):
        log("bundle disconnected! jid:%s skypeuser:%s" % (self.jid, self.skypeuser))
        self.connection = CONNECTION.error
        
    def session_started(self):
        log("session_started: jid:%s" % (self.jid.as_utf8(),))
        
        self.connection = CONNECTION.connected
        JabberClient.session_started(self)

        self.stream.set_iq_get_handler("query", "jabber:iq:version", self.get_version)

        self.stream.set_message_handler("normal", self.message)

        self.stream.set_presence_handler("available",    self.available)
        self.stream.set_presence_handler("unavailable",  self.unavailable)

        self.stream.set_presence_handler("subscribe",    self.subscription)
        self.stream.set_presence_handler("subscribed",   self.subscription)
        self.stream.set_presence_handler("unsubscribe",  self.subscription)
        self.stream.set_presence_handler("unsubscribed", self.subscription)

        self.stream.set_iq_set_handler(
            "command", "http://vipadia.com/skype", self.vipadia_command)

        ## start skype
        echo_ps = subprocess.Popen(
            ["echo", self.skypeuser, self.skypesecret], stdout=subprocess.PIPE)

        if not os.path.exists('/tmp/skype/%s-db' % (self.skypeuser,)):
            cmd = "mkdir -p /tmp/skype/%s-db/%s" % (self.skypeuser, self.skypeuser)
            dbg("  cmd:%s " % (cmd,))
            os.system(cmd)

            now_long = long(time.time())
            now_str = "%0.1f" % (time.time(),)
                                  
            f = open("/tmp/skype/%s-db/shared.xml" % (self.skypeuser,), "w")
            f.write(SHARED_XML % (now_str,))
            f.close()
            f = open("/tmp/skype/%s-db/%s/config.xml" % (self.skypeuser,self.skypeuser), "w")
            config_str = CONFIG_XML % (now_str, now_long)
            dbg("  cfg:%s" % (config_str,))
            f.write(config_str)
            f.close()
            
        self.skype_ps = subprocess.Popen(
            ["skype","--pipelogin", '--dbpath=/tmp/skype/%s-db' % (self.skypeuser,)],
            stdin=echo_ps.stdout, stdout=subprocess.PIPE,
            )

        # We need to give skype time to appear before looking for it...
##         time.sleep(5)

        self.skype = Skype4Py.Skype()
        self.skype.OnAttachmentStatus = skype_OnAttachmentStatus
        self.skype.OnMessageStatus = skype_OnMessageStatus
        self.skype.OnOnlineStatus = skype_OnOnlineStatus
        self.skype.OnUserMood = skype_OnUserMood
        self.skype.OnCommand = skype_OnCommand
        self.skype.OnNotify = skype_OnNotify
        self.skype.OnChatMembersChanged = skype_OnChatMembersChanged
        self.skype.OnUserAuthorizationRequestReceived = skype_OnUserAuthorizationRequestReceived
        
        dbg("connected")

    def safe_send(self, stanza):
        to = stanza.get_to()
        if not (to.domain in (Master, Muc) or to.as_utf8() == Slave):
            err("bogus destination!  stanza:\n%s" % (fmt_evt(stanza),))
            return

        dbg("tx:\n%s" % (fmt_evt(stanza),))
        self.stream.send(stanza)

    #
    # iq handlers
    #

    def vipadia_command(self, iq):
        dbg("vipadia_command:\n%s" % (fmt_evt(iq),), 3)

        if not self.attached: return True

        to = iq.get_to()
        if to != self.jid:
            err("misdirected vipadia_command!\n%s" % (fmt_evt(iq),))
            return True

        frm = iq.get_from()
        if (frm.domain not in (Master, Muc)):
            err("command untrusted source!  jid:%s stanza:\n%s" % (self.jid, fmt_evt(iq)))
            return True
            
        items = iq.xpath_eval("v:command/v:item", { "v": "http://vipadia.com/skype", })
        for item in items:
            command = item.prop("command")
            if command == "subscribed":
                frm = item.prop("from")
                for user in self.skype.UsersWaitingAuthorization:
                    dbg("  frm:%s waiting:%s" % (frm, user.Handle,))
                    if user.Handle == frm: user.IsAuthorized = True ; break
            
            elif command == "subscribe":
                frm = item.prop("from")
                for friend in self.skype.Friends:
                    if friend.Handle == frm and friend.BuddyStatus == 3:
                        ## already a friend
                        iq = Iq(to_jid=Master, stanza_type="set")
                        command = iq.new_query("http://vipadia.com/skype", "command")
                        add_child(command, "item", attrs={ "command": "subscribed",
                                                           "from": friend.Handle,
                                                           })
                        self.safe_send(iq)
                        return True
                    
                skcmd = self.skype.Command(
                    "SET USER %s BUDDYSTATUS 2 Please authorize me" % (frm,))
                self.skype.SendCommand(skcmd)

            elif command == "probe":
                frm = item.prop("from")
                for friend in self.skype.Friends:
                    if friend.Handle != frm: continue
                    skype_OnOnlineStatus(friend, friend.OnlineStatus)
            
            else:
                err("unknown command!  command:%s\n%s" % (command, fmt_evt(iq),))
        
        return True
    
    def get_version(self, iq):
        dbg("get_version:\n%s" % (fmt_evt(iq),), 3)

        to = iq.get_to()
        if to != self.jid:
            err("misdirected version!\n%s" % (fmt_evt(iq),))
            return True
        
        frm = iq.get_from()
        if (frm.domain not in (Master, Muc)):
            err("version untrusted source!  jid:%s stanza:\n%s" % (self.jid, fmt_evt(iq)))
            return True

        iq = iq.make_result_response()
        q = iq.new_query("jabber:iq:version")
        add_child(q, "name", q.ns(), "Vipadia Skype Gateway: BUNDLE")
        add_child(q, "version", q.ns(), "1.0")
        self.safe_send(iq)

        return True

    #
    # message handler
    #
    
    def message(self, msg):
        dbg("message:\n%s" % (fmt_evt(msg),), 3)
        if not self.attached: return True

        to = msg.get_to()
        if to != self.jid:
            err("misdirected message!\n%s" % (fmt_evt(msg),))
            return True

        frm = msg.get_from()
        if (frm.domain not in (Master, Muc)):
            err("message untrusted source!  jid:%s stanza:\n%s" % (self.jid, fmt_evt(msg)))
            return True

        body = msg.get_body()
        subject = msg.get_subject()

        frm = msg.get_from()
        if frm.domain == Muc:
            declines = msg.xpath_eval("u:x/u:decline",
                                      { "u": "http://jabber.org/protocol/muc#user", })
            if declines:
                if frm.node not in GIDs: Declines[gid] = None
                else:
                    chatid = GIDs[frm.node]
                    self.skype.Chat(chatid).Leave()
                
                return True
                
            if frm.node not in GIDs:
                err("unknown gid!  gid:%s\n%s" % (frm.node, fmt_evt(msg),))
                return True

            chatid = GIDs[frm.node]
            chat = self.skype.Chat(chatid)
            if not chat:
                err("unknown chatid!  chatid:%s" % (chatid,))
                return True
            if subject: chat.Topic = subject

            try:
                if body: chat.SendMessage(body)
            except Exception, exc:
                err("message: skype sendmessage error!\n%s" % (fmt_evt(msg),))
                log_stacktrace(exc)
                err("continuing...")
                return True
            
            to = "%s@%s/%s" % (frm.node, frm.domain, Nicks[frm.node])
            self.safe_send(Message(msg, to_jid=to))

        else: ## not groupchat
            self.skype.SendMessage(frm.node, body)

        return True
    
    #
    # presence handlers
    #

    def unavailable(self, presence):
        dbg("unavailable:\n%s" % (fmt_evt(presence),), 3)

        to = presence.get_to()
        if to != self.jid:
            err("misdirected unavailable!\n%s" % (fmt_evt(presence),))
            return True

        frm = presence.get_from()
        if (frm.domain not in (Master, Muc)):
            err("message untrusted source!  jid:%s stanza:\n%s" % (self.jid, fmt_evt(presence)))
            return True

        if frm.domain == Master:
            # Quit as the user has gone offline
            for gid in GIDs: destroy_muc(gid)
            self.running = False

        elif frm.domain == Muc:
            ## the xmpp person leaving the room: skype_OnChatMembersChanged will
            ## be invoked
            if frm.node not in GIDs:
                err("unknown gid!  gid:%s" % (frm.node,))
                return True
            
            chatid = GIDs[frm.node]
            self.skype.Chat(chatid).Leave()

        return True

    def available(self, stanza):
        dbg("available:\n%s" % (fmt_evt(stanza),), 3)
        if not self.attached: return True                            

        to = stanza.get_to()
        if to != self.jid:
            err("misdirected available!\n%s" % (fmt_evt(stanza),))
            return True

        frm = stanza.get_from()
        if (frm.domain not in (Master, Muc)):
            err("available untrusted source!  jid:%s stanza:\n%s" % (self.jid, fmt_evt(stanza)))
            return True

        if frm == Master:
            # Set our skype status appropriately
            show = stanza.get_show()
            if show == 'away': status = 'AWAY'
            elif show == 'dnd': status = 'DND'
            elif show == 'xa': status = 'NA'
            else: status = 'ONLINE'
        
            self.skype.ChangeUserStatus(status)

            mood = stanza.get_status()
            marketing_mood = "%s%s%s" % (
                (Marketing_message and Marketing_message or ""),
                ((Marketing_message and mood) and " - " or ""),
                (mood and mood or ""))
            
            self.skype.CurrentUserProfile.MoodText = marketing_mood

        else:
            if frm.domain == Muc: ## MUC
                ## if from a gid@skypemuc.example.com then do some muc stuff:
                gid = frm.node
                if gid not in GIDs:
                    dbg("unknown gid: %s" % (gid),)
                    return True

                ## Find that chat, get its member list and send initial
                ## presences from other chat members

                Nicks[gid] = frm.resource
                chatid = GIDs[gid]
                chat = self.skype.Chat(chatid)
                
                for member in chat.Members:
                    try:
                        MembersLock.acquire()
                        Members[chatid][member.Handle] = None
                    finally:
                        MembersLock.release()
                        
                    ## presence for existing members *must* come first
                    if member.Handle == self.skypeuser: continue
                    self.safe_send(Presence(
                        to_jid="%s@%s/%s" % (gid, Muc, member.Handle)))
                    
                self.safe_send(Presence(
                    to_jid="%s@%s/%s" % (gid, Muc, frm.resource)))

                if chatid in Msgs:
                    for msg in Msgs[chatid]: skype_OnMessageStatus(msg, "RECEIVED")
                    del Msgs[chatid]

        return True

    def subscription(self, stanza):
        dbg("subscription:\n%s" % (fmt_evt(stanza),), 3)

        to = stanza.get_to()
        if to != self.jid:
            err("misdirected subscription!\n%s" % (fmt_evt(stanza),))
            return True

        frm = stanza.get_from()
        if (frm.domain not in (Master, Muc)):
            err("subscription untrusted source!  jid:%s stanza:\n%s" % (self.jid, fmt_evt(stanza)))
            return True

        send_response = not (stanza.get_type() == 'subscribed')
        if send_response:
            self.safe_send(stanza.make_accept_response())

        return True

    def muc_result(self, iq):
        dbg("muc_result:\n%s" % (fmt_evt(iq),), 3)

        to = iq.get_to()
        if to != self.jid:
            err("misdirected muc_result!\n%s" % (fmt_evt(iq),))
            return True

        frm = iq.get_from()
        if (frm.domain not in (Master, Muc)):
            err("muc_result untrusted source!  jid:%s stanza:\n%s" % (self.jid, fmt_evt(iq)))
            return True

        # Grab the gid and chatid and stash them for later lookups
        items = iq.xpath_eval("v:command/v:item", { "v": "http://vipadia.com/skype", })
        for item in items:
            command = item.prop("command")
            if command == "create-muc":
                chatid = item.prop("chatid") # skype chat name
                gid = item.prop("gid")       # conference ID our muc has allocated

                ChatIDs[chatid] = gid
                GIDs[gid] = chatid

                if gid in Declines:
                    dbg("  MUC invite already declined!  gid:%s chatid:%s" % (gid, chatid))
                    del Declines[gid]
                    self.skype.Chat(chatid).Leave()

        return True
    
#
# Skype callbacks
#

def skype_OnAttachmentStatus(status):
    try:
        dbg("skype_OnAttachmentStatus: status:%s" % (status,), 3)

        if status == Skype4Py.apiAttachAvailable:
            try:
                status = Bundle.skype.Attach()

            except Exception, exc:
                log_stacktrace(exc)
                Bundle.running = False
                raise

        if status != Skype4Py.apiAttachSuccess:
            return

        dbg("  attached!")
        Bundle.attached = True
        
        time.sleep(1) ## skype needs some me-time before doing anything
        Bundle.safe_send(Presence(to_jid=Master))

        rosterq = Iq(to_jid=Master, stanza_type="set")

        x = rosterq.new_query('http://jabber.org/protocol/rosterx', "x")
        for user in Bundle.skype.Friends:
            handle, name = user.Handle, user.Handle
            jid = "%s@%s" % (handle, Master)

            add_child(x, "item", attrs={ "action": "add",
                                         "jid": jid,
                                         "name": name,
                                         "group": "Skype", })

        dbg("  roster:\n%s" % (fmt_evt(rosterq),), 3)
        Bundle.safe_send(rosterq)

        if is_googletalk():
            for friend in Bundle.skype.Friends:
                iq = Iq(to_jid=Master, stanza_type="set")
                command = iq.new_query("http://vipadia.com/skype", "command")
                add_child(command, "item", attrs={ "command": "out-subscribe",
                                                   "from": friend.Handle,
                                                   })
                Bundle.safe_send(iq)
            
        dbg("  waiting:%s" % (Bundle.skype.UsersWaitingAuthorization,))
        for user in Bundle.skype.UsersWaitingAuthorization:
            skype_OnUserAuthorizationRequestReceived(user)

    except Exception, exc:
        log_stacktrace(exc)
                                          
def skype_OnChatMembersChanged(chat, members):
    try:
        dbg("skype_OnChatMembersChanged: chat:%s members:%s" % (chat, members,), 4)
        if is_googletalk(): return True
        
        chatid = chat.Name
        handles = [ m.Handle for m in members ]
        dbg("  chatid:%s handles:%s" % (chatid, handles), 4)
        
        if Bundle.skypeuser not in handles:
            ## we've left!  tidy up
            gid = ChatIDs[chatid]
            del GIDs[gid], Nicks[gid]
            del ChatIDs[chatid]
            
            try:
                MembersLock.acquire()
                del Members[chatid]
            finally:
                MembersLock.release()
                                     
            if chatid in Msgs: del Msgs[chatid]
            destroy_muc(gid)
            return True

        if chatid not in Members and len(members) > 2:
            ## 1-1 chat has become multi-user chat!
            iq = Iq(to_jid=Muc, stanza_type="set")
            command = iq.new_query("http://vipadia.com/skype", "command")
            add_child(command, "item", attrs={ "command": "create-muc",
                                               "chatid": chat.Name,
                                               "jid": Bundle.xmppujid.as_utf8(),
                                               "member": members[0].Handle,
                                               })
            dbg("  create-muc:\n%s" % (fmt_evt(iq),))

            try:
                MembersLock.acquire()
                Members[chatid] = {}
            finally:
                MembersLock.release()

            # set a handler for the reply
            Bundle.stream.set_response_handlers(iq, Bundle.muc_result, Bundle.muc_result)
            Bundle.safe_send(iq)

        empty_members = False
        try:            
            MembersLock.acquire()
            empty_members = (chatid not in Members or len(Members[chatid]) == 0)
        finally:
            MembersLock.release()
            if empty_members: return True
            
        ## on departure, we need to send unavailable to remove them from room
        try:
            MembersLock.acquire()
            chat_handles = Members[chatid].keys()
        finally:
            MembersLock.release()
            
        for handle in chat_handles:
            if handle not in handles: ## ...member has left
                jid = "%s@%s/%s" % (ChatIDs[chatid], Muc, handle)
                Bundle.safe_send(Presence(to_jid=jid, stanza_type="unavailable"))
                try:
                    MembersLock.acquire()
                    del Members[chatid][handle]
                finally:
                    MembersLock.release()

        ## on arrival, if there are *no* existing members, then the room is
        ## really "pending" and we don't send the presences yet (that will be
        ## handled when the groupchat sends us the room presence saying that the
        ## room is created).  if there *are* existing members, then this is
        ## simply someone joining an ongoing room and so we send available
        ## presence on their behalf.
        for handle in handles:
            if handle not in chat_handles: ## ...member has joined
                jid = "%s@%s/%s" % (ChatIDs[chatid], Muc, handle)
                Bundle.safe_send(Presence(to_jid=jid))
                try:
                    MembersLock.acquire()
                    Members[chatid][handle] = None
                finally:
                    MembersLock.release()
           
    except Exception, exc:
        log_stacktrace(exc)

def skype_OnCommand(command):
    try:
        dbg("skype_OnCommand: command:%s" % (command,), 4)

    except Exception, exc:
        log_stacktrace(exc)

def skype_OnNotify(notification):
    try:
        dbg("skype_OnNotify: notification:%s" % (notification,), 4)

    except Exception, exc:
        log_stacktrace(exc)

def skype_OnMessageStatus(msg, status):
    try:
        dbg("skype_OnMessageStatus: msg:%s status:%s" % (msg, status), 3)

        if status != "RECEIVED": return

        chat = msg.Chat
        chatid = chat.Name

        if chatid not in ChatIDs:
            ## currently 1-1 chat
            if len(chat.Members) > 2:
                ## ...but will become group chat: initiate that and stash msg
                skype_OnChatMembersChanged(chat, chat.Members)
                if chatid in Msgs: Msgs[chatid].append(msg)
                else:
                    Msgs[chatid] = [msg]

            else:
                dbg("  body:%s topic:%s" % (msg.Body, chat.Topic))
                Bundle.safe_send(Message(
                    to_jid="%s@%s" % (msg.FromHandle, Master), stanza_type="chat",
                    subject=chat.Topic, body=msg.Body))

        else:
            ## currently group chat
            if len(Members[chatid]) == 0:
                ## ...noone actually here yet: stash msg for later
                if chatid in Msgs: Msgs[chatid].append(msg)
                else:
                    Msgs[chatid] = [msg]

            else:
                ## send the msg as a groupchat msg to MUC
                gid = ChatIDs[chatid]
                nick = msg.FromHandle ## DisplayName
                dbg("  body:%s topic:%s" % (msg.Body, chat.Topic))
                Bundle.safe_send(Message(
                    to_jid="%s@%s/%s" % (gid, Muc, nick), stanza_type="groupchat",
                    subject=chat.Topic, body=msg.Body))

    except Exception, exc:
        log_stacktrace(exc)

def skype_OnUserAuthorizationRequestReceived(user):
    try:
        dbg("skype_OnUserAuthorizationRequestReceived: user:%s" % (user,), 2)

        iq = Iq(to_jid=Master, stanza_type="set")
        command = iq.new_query("http://vipadia.com/skype", "command")
        add_child(command, "item", attrs={ "from": "%s@%s" % (user.Handle, Master),
                                           "djid": Bundle.jid.as_utf8(),
                                           "command": "subscribe",
                                           })
        dbg("  subscribe:\n%s" % (fmt_evt(iq),))
        Bundle.safe_send(iq)

    except Exception, exc:
        log_stacktrace(exc)

def skype_OnOnlineStatus(user, status):
    try:
        dbg("skype_OnOnlineStatus: user:%s status:%s" % (user, status), 3)

        pres = Presence(to_jid="%s@%s" % (user.Handle, Master))
        if status == 'OFFLINE': pres.set_type('unavailable')
        elif status == 'AWAY': pres.set_show('away')
        elif status == 'NA': pres.set_show('xa') #??
        elif status == 'DND': pres.set_show('dnd')
        elif status == 'INVISIBLE': pres.set_type('unavailable')

        if (user.Handle != Bundle.skypeuser and user.MoodText != None):
            pres.set_status(user.MoodText)
            
        Bundle.safe_send(pres)

    except Exception, exc:
        log_stacktrace(exc)

def skype_OnUserMood(user, mood):
    try:
        dbg("skype_OnUserMood: user:%s mood:%s" % (user, mood), 3)
        skype_OnOnlineStatus(user, user.OnlineStatus)

    except Exception, exc:
        log_stacktrace(exc)

## due to odd comment in skype4py that callbacks may be garbage
## collected if they're only referenced when assigned to the handler.
## so we need to maintain some other reference to them, here.
_SkypeCallbacks = [
    skype_OnAttachmentStatus,
    skype_OnMessageStatus,
    skype_OnOnlineStatus,
    skype_OnUserMood,
    skype_OnCommand,
    skype_OnNotify,
    skype_OnChatMembersChanged,
    skype_OnUserAuthorizationRequestReceived
    ]
    
#
# Skype helpers
#

def skype_bad_credentials():
    dbg("skype_bad_credentials", 3)
    
    Bundle.safe_send(Presence(
        to_jid=Master, stanza_type="error", error_cond='not-authorized'))

################################################################################
    
if __name__ == '__main__':

    openlog()
    log(" ".join(sys.argv))
    
    locale.setlocale(locale.LC_CTYPE, "")
    encoding = locale.getlocale()[1]
    if not encoding: encoding = "us-ascii"
    sys.stdout = codecs.getwriter(encoding)(sys.stdout, errors="replace")
    sys.stderr = codecs.getwriter(encoding)(sys.stderr, errors="replace")

    args = base64.b64decode(sys.argv[1]).split("\0")
    dbg("  args:[%d] %s" % (len(args), args,))

    jid, secret, skypeuser, skypesecret, xmppujid, \
         Mode, Master, Muc, Slave, Marketing_message = args
    
    jid = JID(jid)
    xmppujid = JID(xmppujid)
    
    logger = logging.getLogger()
    logger.addHandler(logging.FileHandler("/tmp/bundle-%s.log" % jid.resource))
    logger.setLevel(logging.DEBUG) # change to DEBUG for higher verbosity

    try:
        log("bundle: jid:%s xmppujid:%s" % (jid.as_utf8(), xmppujid.as_utf8()))
        Bundle = SkypeBundle(jid, secret, skypeuser, skypesecret, xmppujid)

        attempts = 0
        keepalive = Iq(to_jid=Slave, stanza_type="set")
        keptalive = 0
        while Bundle.running:
            try:
                if Bundle.connection == CONNECTION.idle:
                    dbg("bundle [%s] connecting" % (jid.as_utf8(),))
                    Bundle.connect()                
                    Bundle.connection = CONNECTION.connecting

                elif Bundle.connection == CONNECTION.connecting:
                    dbg("bundle [%s] connecting..." % (jid.as_utf8(),))
                    if Bundle.stream: Bundle.stream.loop_iter(1)

                elif Bundle.connection == CONNECTION.connected:
                    dbg("looping bundle [%s]" % (jid.as_utf8(),))
                    if Bundle.stream: Bundle.stream.loop_iter(1)

                    Bundle.idle()

                    now = time.time()
                    if now - keptalive > 60:
                        dbg("bundle [%s] keepalive! %s" % (jid.as_utf8(), fmt_evt(keepalive),), 5)
                        Bundle.safe_send(keepalive)
                        keptalive = now

                    if not Bundle.skype_ps: continue
                    retcode = Bundle.skype_ps.poll()
                    if retcode == 255:
                        skype_bad_credentials()
                        break
                    
                    elif not retcode:
                        if attempts >= SKYPE_ATTEMPTS: break
                                              
                        try: Bundle.skype.Attach()
                        except Skype4Py.errors.ISkypeAPIError:
                            attempts += 1

                elif Bundle.connection == CONNECTION.error:
                    Bundle.connection = CONNECTION.idle

            except Exception, exc:
                log_stacktrace(exc)
                try:
                    Bundle.disconnect()
                except Exception, exc:
                    err("second chance!  failing")
                    log_stacktrace(exc)

                Bundle.connection = CONNECTION.error

    finally:
        if Bundle.skype_ps: os.kill(Bundle.skype_ps.pid, signal.SIGTERM)
        log("bundle exit: jid:%s" % (jid.as_utf8(),))

        ## otherwise the bundle can continue while skype finishes itself off
        os._exit(os.EX_OK)
