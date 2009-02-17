#!/bin/sh
#
# Karaka Skype-XMPP Gateway: Bundle launch wrapper
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

XSCREEN=$1
ARGSTRING=$2
rm -f /tmp/x-skype-gw*
setsid xvfb-run -n ${XSCREEN} -s "-screen 0 10x10x8" -f /tmp/x-skype-gw \
  ./karaka/bundle.py ${ARGSTRING}

