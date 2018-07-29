#!/bin/sh

. /koolshare/scripts/base.sh
. /koolshare/scripts/jshn.sh
. /koolshare/scripts/uci.sh
LOCK_FILE=/var/lock/koolproxy.lock
KP_DIR=$APP_ROOT/bin

set_lock(){
    exec 1000>"$LOCK_FILE"
    flock -x 1000
}

unset_lock(){
    flock -u 1000
    rm -rf "$LOCK_FILE"
}

load_uci_env(){
    config_load koolproxy
    config_get koolproxy_mode main mode
    config_get koolproxy_acl_default main acl
}

detect_cert(){
    if [ ! -f $KP_DIR/data/private/ca.key.pem -o ! -f $KP_DIR/data/certs/ca.crt ]; then
        cd $KP_DIR/data && sh gen_ca.sh
    fi
}

write_user_txt(){
    if [ -n "$koolproxy_custom_rule" ];then
        echo $koolproxy_custom_rule| base64_decode |sed 's/\\n/\n/g' > $KP_DIR/data/rules/user.txt
    fi
}

start_koolproxy(){
    write_user_txt
    cd $KP_DIR > /dev/null && ./koolproxy -d && cd - > /dev/null
}

stop_koolproxy(){
    kill -9 `pidof koolproxy` >/dev/null 2>&1
    killall koolproxy >/dev/null 2>&1
}

flush_nat(){
    cd /tmp > /dev/null
    iptables -t nat -S | grep -E "KOOLPROXY|KP_HTTP|KP_HTTPS|KP_ALL_PORT" | sed 's/-A/iptables -t nat -D/g'|sed 1,4d > kp_clean.sh && chmod 777 kp_clean.sh && ./kp_clean.sh > /dev/null
    iptables -t nat -X KOOLPROXY > /dev/null 2>&1
    iptables -t nat -X KP_HTTP > /dev/null 2>&1
    iptables -t nat -X KP_HTTPS > /dev/null 2>&1
    iptables -t nat -X KP_ALL_PORT > /dev/null 2>&1
    ipset -F black_koolproxy > /dev/null 2>&1 && ipset -X black_koolproxy > /dev/null 2>&1
    ipset -F white_kp_list > /dev/null 2>&1 && ipset -X white_kp_list > /dev/null 2>&1
    ipset -F kp_full_port > /dev/null 2>&1 && ipset -X kp_full_port > /dev/null 2>&1
    cd - > /dev/null
}

creat_ipset(){
    # Load ipset netfilter kernel modules and kernel modules
    ipset -! create white_kp_list nethash > /dev/null
    ipset -! create black_koolproxy iphash > /dev/null
    cat $KP_DIR/data/rules/koolproxy.txt $KP_DIR/data/rules/daily.txt $KP_DIR/data/rules/user.txt | grep -Eo "(.\w+\:[1-9][0-9]{1,4})/" | grep -Eo "([0-9]{1,5})" | sort -un | sed -e '$a\80' -e '$a\443' | sed -e "s/^/-A kp_full_port &/g" -e "1 i\-N kp_full_port bitmap:port range 0-65535 " | ipset -R -! > /dev/null
}

add_white_black_ip(){
    ip_lan="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4"
    for ip in $ip_lan
    do
        ipset -A white_kp_list $ip >/dev/null 2>&1

    done
    ipset -A black_koolproxy 110.110.110.110 >/dev/null 2>&1
}

write_nat_start(){
    uci -q batch <<-EOT
delete firewall.ks_koolproxy
set firewall.ks_koolproxy=include
set firewall.ks_koolproxy.type=script
set firewall.ks_koolproxy.path=/koolshare/scripts/koolproxy-config.sh
set firewall.ks_koolproxy.family=any
set firewall.ks_koolproxy.reload=1
commit firewall
EOT

}


remove_nat_start(){
    uci -q batch <<-EOT
delete firewall.ks_koolproxy
commit firewall
EOT

}

get_action_chain() {
    case "$1" in
        0)
            echo "RETURN"
        ;;
        1)
            echo "KP_HTTP"
        ;;
        2)
            echo "KP_HTTPS"
        ;;
        3)
            echo "KP_ALL_PORT"
        ;;
    esac
}

load_nat(){
    [ -z "$koolproxy_mode" ] && koolproxy_mode=1
    [ -z "$koolproxy_acl_default" ] && koolproxy_acl_default=1

    # 创建KOOLPROXY nat rule
    iptables -t nat -N KOOLPROXY
    # 局域网地址不走KP
    iptables -t nat -A KOOLPROXY -m set --match-set white_kp_list dst -j RETURN
    # 生成对应CHAIN
    iptables -t nat -N KP_HTTP
    iptables -t nat -A KP_HTTP -p tcp -m multiport --dport 80 -j REDIRECT --to-ports 3000
    iptables -t nat -N KP_HTTPS
    iptables -t nat -A KP_HTTPS -p tcp -m multiport --dport 80,443 -j REDIRECT --to-ports 3000
    iptables -t nat -N KP_ALL_PORT
    #iptables -t nat -A KP_ALL_PORT -p tcp -j REDIRECT --to-ports 3000
    # 端口控制 
    if [ "$koolproxy_port" == "1" ]; then
        iptables -t nat -A KP_ALL_PORT -p tcp -m multiport ! --dport $koolproxy_bp_port -m set --match-set kp_full_port dst -j REDIRECT --to-ports 3000
    else
        iptables -t nat -A KP_ALL_PORT -p tcp -m set --match-set kp_full_port dst -j REDIRECT --to-ports 3000
    fi
    # 局域网控制
    # lan_acess_control
    # 剩余流量转发到缺省规则定义的链中
    iptables -t nat -A KOOLPROXY -p tcp -j $(get_action_chain $koolproxy_acl_default)
    # 重定所有流量到 KOOLPROXY
    # 全局模式和视频模式
    PR_NU=`iptables -nvL PREROUTING -t nat |sed 1,2d | sed -n '/prerouting_rule/='`
    if [ "$PR_NU" == "" ]; then
        PR_NU=1
    else
        let PR_NU+=1
    fi
    [ "$koolproxy_mode" == "1" ] || [ "$koolproxy_mode" == "3" ] && iptables -t nat -I PREROUTING "$PR_NU" -p tcp -j KOOLPROXY
    # ipset 黑名单模式
    [ "$koolproxy_mode" == "2" ] && iptables -t nat -I PREROUTING "$PR_NU" -p tcp -m set --match-set black_koolproxy dst -j KOOLPROXY
}

on_post() {
    local koolproxy_mode
    local koolproxy_acl_default
    json_load "$INPUT_JSON"
    json_get_var koolproxy_mode "mode"
    json_get_var koolproxy_acl_default "acl"
    uci -q batch <<-EOT
set koolproxy.main.mode=$koolproxy_mode
set koolproxy.main.acl=$koolproxy_acl_default
EOT

    if [ "$koolproxy_mode" == "0" ]; then
        # stop it
        set_lock
        remove_nat_start
        flush_nat
        stop_koolproxy
        unset_lock

        on_get
    else
        # restart it
        remove_nat_start
        flush_nat
        stop_koolproxy
        # now start
        detect_cert
        start_koolproxy
        creat_ipset
        add_white_black_ip
        load_nat
        write_nat_start

        on_get
    fi
}

on_get() {
    local koolproxy_mode
    local koolproxy_acl_default
    config_load koolproxy
    config_get koolproxy_mode main mode
    config_get koolproxy_acl_default main acl

    status=`pidof koolproxy`

    echo '{"status":"'${status}'","mode":"'$koolproxy_mode'","acl":"'$koolproxy_acl_default'"}'
}

case $ACTION in
start)
    # boot it only, not include iptables
    load_uci_env
    set_lock
    detect_cert
    start_koolproxy
    unset_lock
    ;;
restart)
    load_uci_env
    remove_nat_start
    flush_nat
    stop_koolproxy
    # now start
    detect_cert
    start_koolproxy
    creat_ipset
    add_white_black_ip
    load_nat
    write_nat_start
    ;;
post)
    on_post
    ;;
get)
    on_get
    ;;
installed)
    app_init_cfg '{"koolproxy":[{"_id":"main","mode":"0","acl":"1"}]}'
    mkdir -p /koolshare/apps/koolproxy/bin
    cp -rf $APP_ROOT/rdata/* $APP_ROOT/bin/
    ;;
status)
    ;;
stop)
    load_uci_env
    set_lock
    remove_nat_start
    flush_nat
    stop_koolproxy
    unset_lock
    ;;
*)
    load_uci_env
    set_lock
    flush_nat
    creat_ipset
    add_white_black_ip
    load_nat
    unset_lock
    ;;
esac

