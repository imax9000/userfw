project(userfw_dummynet C)

declare_userfw_module(dummynet dummynet.c dummynet.h)

find_file(IP_FW_PRIVATE_H 
	NAMES netinet/ipfw/ip_fw_private.h
		netpfil/ipfw/ip_fw_private.h)

configure_file(ip_fw_private.h.in ip_fw_private.h)
