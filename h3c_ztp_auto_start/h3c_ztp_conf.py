import comware

# mac=comware.CLI('display  interface GigabitEthernet 1/0 | in IP.packet')
# dev_mac=mac.get_output()
# x=dev_mac[1].split(':')[2].strip()
comware.CLI('system-view ;\
    line aux 0 ;\
    authen none ;\
    user-role network-admin ;\
    int g1/0 ;ip address dhcp-alloc ;\
    ssh server  enable ;\
    local-user python class manage ;\
    password simple h3c@123456 ;\
    service-type ssh telnet terminal ;\
    authorization-attribute user-role network-admin ;\
    line vty 0 63 ;\
    authentication-mode scheme ;\
    user-role network-admin')