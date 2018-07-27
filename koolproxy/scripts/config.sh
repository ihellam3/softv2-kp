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
    mkdir -p /koolshare/apps/koolproxy/bin
    cp -rf $APP_ROOT/rdata/* $APP_ROOT/bin/
    ;;
status)
    ;;
stop)
    ;;
*)
    ;;
esac

