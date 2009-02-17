#
# Karaka Skype-XMPP Gateway: register buddy configuration handler
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

import ConfigParser
FILENAME = '/etc/karaka-register.conf'

class RegisterConfig:
    def __init__(self):
        self.config = ConfigParser.ConfigParser()
        self.config.read(FILENAME)

        self.register = self.get("register", "register")
        self.secret = self.get("register", "secret")
        self.port = self.get("register", "port")
        self.server = self.get("register", "server")
        self.domain = self.get("register", "domain")
        self.master = self.get("register", "master")
            
        self.sql_server = self.get("mysql", "server")
        self.sql_database = self.get("mysql", "database")
        self.sql_user = self.get("mysql", "user")
        self.sql_password = self.get("mysql", "password")

        self.complete = True

    def get(self,section,option):
        if self.config.has_option(section,option):
            return self.config.get(section,option)
        else:
            print "No option " + option + " in section " + section + " in " + FILENAME
            self.complete = False
            return ""
