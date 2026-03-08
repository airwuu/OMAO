tshark -l -i [NETWORK_INTERFACE] -T ek \
-e frame.protocols \
-e eth.src -e eth.dst \
-e ip.src -e ip.dst \
-e tcp.dstport -e udp.dstport \
-e tls.handshake.ja3 \
-e dhcp.hw.mac_addr -e dhcp.option.hostname
