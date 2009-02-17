#!/bin/sh
#
# Karaka Skype-XMPP Gateway: control script
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

verbose=0
command=

## process options
while getopts vlcrao opt
  do
  case "$opt" in
    v ) verbose=1 ;;
    
    l ) command=list ;;
    c ) command=connect ;;
    
    r ) command=restart ;;
    a ) command=start ;; 
    o ) command=stop ;;
    
    \? )
      echo >&2 \
      "usage: $0 [-v] [-r] [-l] <services...>"
      exit 1
    ;;
  esac
done
shift `expr $OPTIND - 1`

case "$command" in

  kill-world )
    echo INCOMPLETE.
  ;;
  
  list )
    sudo screen -list karaka/
  ;;
  
  connect )
    while [ $# != 0 ]; do
      service=$1
      pid=$(echo $(sudo screen -list karaka/ | grep $service | cut -d"." -f 1) | tr -d [:blank:])
      echo screen -r karaka/$pid
      shift
    done
  ;;
  
  restart|start|stop )
    while [ $# != 0 ]; do
      service=$1
      case "$service" in
        master|register )
          /etc/init.d/karaka-$service $command
        ;;

        * )
          name=$1
          /etc/init.d/karaka-slave $command $name
        ;;
      esac
      shift
    done
  ;;
  
esac


