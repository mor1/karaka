#
# Karaka Skype-XMPP Gateway: slave configuration handler
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

import ConfigParser
FILENAME = '/etc/karaka-slave.conf'

class SlaveConfig:
    def __init__(self, slave):
        self.config = ConfigParser.ConfigParser()
        self.config.read(FILENAME)

        self.slave = slave
        self.secret = self.get(slave, "secret")
        self.port = self.get(slave, "port")
        self.server = self.get(slave, "server")
        self.domain = self.get(slave, "domain")
        self.capacity = self.get(slave, "capacity")
        self.base = self.get(slave, "base")
        self.slave_secret = self.get(slave, "slave_secret")
        
        self.master = self.get(slave, "component")
        self.muc = self.get(slave, "muc")
        
        self.complete = True

    def get(self, section, option):
        if self.config.has_option(section, option):
            return self.config.get(section, option)
        else:
            print "No option " + option + " in section " + section + " in " + FILENAME
            self.complete = False
            return ""
