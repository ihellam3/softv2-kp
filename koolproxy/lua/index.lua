local nixio = require "nixio"
local ksutil = require "luci.ksutil"

module("luci.controller.apps.koolproxy.index", package.seeall)

function index()
	entry({"apps", "koolproxy"}, call("action_index"))
end

function action_index()
    ksutil.shell_action("koolproxy")
end
