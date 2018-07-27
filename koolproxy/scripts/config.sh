#!/bin/sh

. /koolshare/scripts/base.sh
. /koolshare/scripts/jshn.sh

on_post() {
    echo '{"status":"ok"}'
}

on_get() {
    echo '{"status":"ok"}'
}

case $ACTION in
start)
    ;;
post)
    on_post
    ;;
get)
    on_get
    ;;
installed)
    ;;
status)
    ;;
stop)
    ;;
*)
    ;;
esac

