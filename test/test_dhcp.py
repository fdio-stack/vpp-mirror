#!/usr/bin/env python

import unittest
import socket

from framework import VppTestCase, VppTestRunner

from scapy.layers.l2 import Ether, getmacbyip
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6, in6_getnsmac, in6_mactoifaceid
from scapy.layers.dhcp import DHCP, BOOTP, DHCPTypes
from scapy.layers.dhcp6 import DHCP6, DHCP6_Solicit, DHCP6_RelayForward, \
    DHCP6_RelayReply, DHCP6_Advertise, DHCP6OptRelayMsg, DHCP6OptIfaceId, \
    DHCP6OptStatusCode, DHCP6OptVSS, DHCP6OptClientLinkLayerAddr
from socket import AF_INET, AF_INET6
from scapy.utils import inet_pton, inet_ntop
from scapy.utils6 import in6_ptop

DHCP4_CLIENT_PORT = 68
DHCP4_SERVER_PORT = 67
DHCP6_CLIENT_PORT = 547
DHCP6_SERVER_PORT = 546


def mk_ll_addr(mac):

    euid = in6_mactoifaceid(mac)
    addr = "fe80::" + euid
    return addr


class TestDHCP(VppTestCase):
    """ DHCP Test Case """

    def setUp(self):
        super(TestDHCP, self).setUp()

        # create 3 pg interfaces
        self.create_pg_interfaces(range(4))

        # pg0 and 1 are IP configured in VRF 0 and 1.
        # pg2 and 3 are non IP-configured in VRF 0 and 1
        table_id = 0
        for i in self.pg_interfaces[:2]:
            i.admin_up()
            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            table_id += 1

        table_id = 0
        for i in self.pg_interfaces[2:]:
            i.admin_up()
            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            table_id += 1

    def send_and_assert_no_replies(self, intf, pkts, remark):
        intf.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        for i in self.pg_interfaces:
            i.assert_nothing_captured(remark=remark)

    def validate_relay_options(self, pkt, intf, ip_addr, fib_id, oui):
        dhcp = pkt[DHCP]
        found = 0
        data = []

        for i in dhcp.options:
            if type(i) is tuple:
                if i[0] == "relay_agent_Information":
                    #
                    # There are two sb-options present - each of length 6.
                    #
                    data = i[1]
                    if oui != 0:
                        self.assertEqual(len(data), 24)
                    else:
                        self.assertEqual(len(data), 12)

                    #
                    # First sub-option is ID 1, len 4, then encoded
                    #  sw_if_index. This test uses low valued indicies
                    # so [2:4] are 0.
                    # The ID space is VPP internal - so no matching value
                    # scapy
                    #
                    self.assertEqual(ord(data[0]), 1)
                    self.assertEqual(ord(data[1]), 4)
                    self.assertEqual(ord(data[2]), 0)
                    self.assertEqual(ord(data[3]), 0)
                    self.assertEqual(ord(data[4]), 0)
                    self.assertEqual(ord(data[5]), intf._sw_if_index)

                    #
                    # next sub-option is the IP address of the client side
                    # interface.
                    # sub-option ID=5, length (of a v4 address)=4
                    #
                    claddr = socket.inet_pton(AF_INET, ip_addr)

                    self.assertEqual(ord(data[6]), 5)
                    self.assertEqual(ord(data[7]), 4)
                    self.assertEqual(data[8], claddr[0])
                    self.assertEqual(data[9], claddr[1])
                    self.assertEqual(data[10], claddr[2])
                    self.assertEqual(data[11], claddr[3])

                    if oui != 0:
                        # sub-option 151 encodes the 3 byte oui
                        # and the 4 byte fib_id
                        self.assertEqual(ord(data[12]), 151)
                        self.assertEqual(ord(data[13]), 8)
                        self.assertEqual(ord(data[14]), 1)
                        self.assertEqual(ord(data[15]), 0)
                        self.assertEqual(ord(data[16]), 0)
                        self.assertEqual(ord(data[17]), oui)
                        self.assertEqual(ord(data[18]), 0)
                        self.assertEqual(ord(data[19]), 0)
                        self.assertEqual(ord(data[20]), 0)
                        self.assertEqual(ord(data[21]), fib_id)

                        # VSS control sub-option
                        self.assertEqual(ord(data[22]), 152)
                        self.assertEqual(ord(data[23]), 0)

                    found = 1
        self.assertTrue(found)

        return data

    def verify_dhcp_offer(self, pkt, intf):
        ether = pkt[Ether]
        self.assertEqual(ether.dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(ether.src, intf.local_mac)

        ip = pkt[IP]
        self.assertEqual(ip.dst, "255.255.255.255")
        self.assertEqual(ip.src, intf.local_ip4)

        udp = pkt[UDP]
        self.assertEqual(udp.dport, DHCP4_CLIENT_PORT)
        self.assertEqual(udp.sport, DHCP4_SERVER_PORT)

        dhcp = pkt[DHCP]
        is_offer = False
        for o in dhcp.options:
            if type(o) is tuple:
                if o[0] == "message-type" \
                   and DHCPTypes[o[1]] == "offer":
                    is_offer = True
        self.assertTrue(is_offer)

        data = self.validate_relay_options(pkt, intf, intf.local_ip4, 0, 0)

    def verify_dhcp_discover(self, pkt, intf, src_intf=None, fib_id=0, oui=0):
        ether = pkt[Ether]
        self.assertEqual(ether.dst, intf.remote_mac)
        self.assertEqual(ether.src, intf.local_mac)

        ip = pkt[IP]
        self.assertEqual(ip.dst, intf.remote_ip4)
        self.assertEqual(ip.src, intf.local_ip4)

        udp = pkt[UDP]
        self.assertEqual(udp.dport, DHCP4_SERVER_PORT)
        self.assertEqual(udp.sport, DHCP4_CLIENT_PORT)

        dhcp = pkt[DHCP]

        is_discover = False
        for o in dhcp.options:
            if type(o) is tuple:
                if o[0] == "message-type" \
                   and DHCPTypes[o[1]] == "discover":
                    is_discover = True
        self.assertTrue(is_discover)

        data = self.validate_relay_options(pkt, src_intf,
                                           src_intf.local_ip4,
                                           fib_id, oui)
        return data

    def verify_dhcp6_solicit(self, pkt, intf,
                             peer_ip, peer_mac,
                             fib_id=0,
                             oui=0):
        ether = pkt[Ether]
        self.assertEqual(ether.dst, intf.remote_mac)
        self.assertEqual(ether.src, intf.local_mac)

        ip = pkt[IPv6]
        self.assertEqual(in6_ptop(ip.dst), in6_ptop(intf.remote_ip6))
        self.assertEqual(in6_ptop(ip.src), in6_ptop(intf.local_ip6))

        udp = pkt[UDP]
        self.assertEqual(udp.dport, DHCP6_CLIENT_PORT)
        self.assertEqual(udp.sport, DHCP6_SERVER_PORT)

        relay = pkt[DHCP6_RelayForward]
        self.assertEqual(in6_ptop(relay.peeraddr), in6_ptop(peer_ip))
        oid = pkt[DHCP6OptIfaceId]
        cll = pkt[DHCP6OptClientLinkLayerAddr]
        self.assertEqual(cll.optlen, 8)
        self.assertEqual(cll.lltype, 1)
        self.assertEqual(cll.clladdr, peer_mac)

        if fib_id != 0:
            vss = pkt[DHCP6OptVSS]
            self.assertEqual(vss.optlen, 8)
            self.assertEqual(vss.type, 1)
            # the OUI and FIB-id are really 3 and 4 bytes resp.
            # but the tested range is small
            self.assertEqual(ord(vss.data[0]), 0)
            self.assertEqual(ord(vss.data[1]), 0)
            self.assertEqual(ord(vss.data[2]), oui)
            self.assertEqual(ord(vss.data[3]), 0)
            self.assertEqual(ord(vss.data[4]), 0)
            self.assertEqual(ord(vss.data[5]), 0)
            self.assertEqual(ord(vss.data[6]), fib_id)

        # the relay message should be an encoded Solicit
        msg = pkt[DHCP6OptRelayMsg]
        sol = DHCP6_Solicit()
        self.assertEqual(msg.optlen, len(str(sol)))
        self.assertEqual(str(sol), (str(msg[1]))[:msg.optlen])

    def verify_dhcp6_advert(self, pkt, intf, peer):
        ether = pkt[Ether]
        self.assertEqual(ether.dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(ether.src, intf.local_mac)

        ip = pkt[IPv6]
        self.assertEqual(in6_ptop(ip.dst), in6_ptop(peer))
        self.assertEqual(in6_ptop(ip.src), in6_ptop(intf.local_ip6))

        udp = pkt[UDP]
        self.assertEqual(udp.dport, DHCP6_SERVER_PORT)
        self.assertEqual(udp.sport, DHCP6_CLIENT_PORT)

        # not sure why this is not decoding
        # adv = pkt[DHCP6_Advertise]

    def test_dhcp_proxy(self):
        """ DHCPv4 Proxy """

        #
        # Verify no response to DHCP request without DHCP config
        #
        p_disc_vrf0 = (Ether(dst="ff:ff:ff:ff:ff:ff",
                             src=self.pg2.remote_mac) /
                       IP(src="0.0.0.0", dst="255.255.255.255") /
                       UDP(sport=DHCP4_CLIENT_PORT,
                           dport=DHCP4_SERVER_PORT) /
                       BOOTP(op=1) /
                       DHCP(options=[('message-type', 'discover'), ('end')]))
        pkts_disc_vrf0 = [p_disc_vrf0]
        p_disc_vrf1 = (Ether(dst="ff:ff:ff:ff:ff:ff",
                             src=self.pg3.remote_mac) /
                       IP(src="0.0.0.0", dst="255.255.255.255") /
                       UDP(sport=DHCP4_CLIENT_PORT,
                           dport=DHCP4_SERVER_PORT) /
                       BOOTP(op=1) /
                       DHCP(options=[('message-type', 'discover'), ('end')]))
        pkts_disc_vrf1 = [p_disc_vrf0]

        self.send_and_assert_no_replies(self.pg2, pkts_disc_vrf0,
                                        "DHCP with no configuration")
        self.send_and_assert_no_replies(self.pg3, pkts_disc_vrf1,
                                        "DHCP with no configuration")

        #
        # Enable DHCP proxy in VRF 0
        #
        server_addr = self.pg0.remote_ip4n
        src_addr = self.pg0.local_ip4n

        self.vapi.dhcp_proxy_config(server_addr,
                                    src_addr,
                                    rx_table_id=0)

        #
        # Discover packets from the client are dropped because there is no
        # IP address configured on the client facing interface
        #
        self.send_and_assert_no_replies(self.pg2, pkts_disc_vrf0,
                                        "Discover DHCP no relay address")

        #
        # Inject a response from the server
        #  dropped, because there is no IP addrees on the
        #  client interfce to fill in the option.
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_SERVER_PORT) /
             BOOTP(op=1) /
             DHCP(options=[('message-type', 'offer'), ('end')]))
        pkts = [p]

        self.send_and_assert_no_replies(self.pg2, pkts,
                                        "Offer DHCP no relay address")

        #
        # configure an IP address on the client facing interface
        #
        self.pg2.config_ip4()

        #
        # Try again with a discover packet
        # Rx'd packet should be to the server address and from the configured
        # source address
        # UDP source ports are unchanged
        # we've no option 82 config so that should be absent
        #
        self.pg2.add_stream(pkts_disc_vrf0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        rx = rx[0]

        option_82 = self.verify_dhcp_discover(rx, self.pg0, src_intf=self.pg2)

        #
        # Create an DHCP offer reply from the server with a correctly formatted
        # option 82. i.e. send back what we just captured
        # The offer, sent mcast to the client, still has option 82.
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_SERVER_PORT) /
             BOOTP(op=1) /
             DHCP(options=[('message-type', 'offer'),
                           ('relay_agent_Information', option_82),
                           ('end')]))
        pkts = [p]

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        rx = rx[0]

        self.verify_dhcp_offer(rx, self.pg2)

        #
        # Bogus Option 82:
        #
        # 1. not our IP address = not checked by VPP? so offer is replayed
        #    to client
        bad_ip = option_82[0:8] + chr(33) + option_82[9:]

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_SERVER_PORT) /
             BOOTP(op=1) /
             DHCP(options=[('message-type', 'offer'),
                           ('relay_agent_Information', bad_ip),
                           ('end')]))
        pkts = [p]
        self.send_and_assert_no_replies(self.pg0, pkts,
                                        "DHCP offer option 82 bad address")

        # 2. Not a sw_if_index VPP knows
        bad_if_index = option_82[0:2] + chr(33) + option_82[3:]

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_SERVER_PORT) /
             BOOTP(op=1) /
             DHCP(options=[('message-type', 'offer'),
                           ('relay_agent_Information', bad_if_index),
                           ('end')]))
        pkts = [p]
        self.send_and_assert_no_replies(self.pg0, pkts,
                                        "DHCP offer option 82 bad if index")

        #
        # Send a DHCP request in VRF 1. should be dropped.
        #
        self.send_and_assert_no_replies(self.pg3, pkts_disc_vrf1,
                                        "DHCP with no configuration VRF 1")

        #
        # Delete the DHCP config in VRF 0
        # Should now drop requests.
        #
        self.vapi.dhcp_proxy_config(server_addr,
                                    src_addr,
                                    rx_table_id=0,
                                    is_add=0)

        self.send_and_assert_no_replies(self.pg2, pkts_disc_vrf0,
                                        "DHCP config removed VRF 0")
        self.send_and_assert_no_replies(self.pg3, pkts_disc_vrf1,
                                        "DHCP config removed VRF 1")

        #
        # Add DHCP config for VRF 1
        #
        server_addr = self.pg1.remote_ip4n
        src_addr = self.pg1.local_ip4n
        self.vapi.dhcp_proxy_config(server_addr,
                                    src_addr,
                                    rx_table_id=1,
                                    server_table_id=1)

        #
        # Confim DHCP requests ok in VRF 1.
        #  - dropped on IP config on client interface
        #
        self.send_and_assert_no_replies(self.pg3, pkts_disc_vrf1,
                                        "DHCP config removed VRF 1")

        #
        # configure an IP address on the client facing interface
        #
        self.pg3.config_ip4()

        self.pg3.add_stream(pkts_disc_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        rx = rx[0]
        self.verify_dhcp_discover(rx, self.pg1, src_intf=self.pg3)

        #
        # Add VSS config
        #  table=1, fib=id=1, oui=4
        self.vapi.dhcp_proxy_set_vss(1, 1, 4)

        self.pg3.add_stream(pkts_disc_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        rx = rx[0]
        self.verify_dhcp_discover(rx, self.pg1, src_intf=self.pg3,
                                  fib_id=1, oui=4)

        #
        # Remove the VSS config
        #  relayed DHCP has default vlaues in the option.
        #
        self.vapi.dhcp_proxy_set_vss(1, 1, 4, is_add=0)

        self.pg3.add_stream(pkts_disc_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        rx = rx[0]
        self.verify_dhcp_discover(rx, self.pg1, src_intf=self.pg3)

        #
        # remove DHCP config to cleanup
        #
        self.vapi.dhcp_proxy_config(server_addr,
                                    src_addr,
                                    rx_table_id=1,
                                    server_table_id=11,
                                    is_add=0)

        self.send_and_assert_no_replies(self.pg2, pkts_disc_vrf0,
                                        "DHCP cleanup VRF 0")
        self.send_and_assert_no_replies(self.pg3, pkts_disc_vrf1,
                                        "DHCP cleanup VRF 1")

    def test_dhcp6_proxy(self):
        """ DHCPv6 Proxy"""
        #
        # Verify no response to DHCP request without DHCP config
        #
        dhcp_solicit_dst = "ff02::1:2"
        dhcp_solicit_src_vrf0 = mk_ll_addr(self.pg2.remote_mac)
        dhcp_solicit_src_vrf1 = mk_ll_addr(self.pg3.remote_mac)
        server_addr_vrf0 = self.pg0.remote_ip6n
        src_addr_vrf0 = self.pg0.local_ip6n
        server_addr_vrf1 = self.pg1.remote_ip6n
        src_addr_vrf1 = self.pg1.local_ip6n

        dmac = in6_getnsmac(inet_pton(socket.AF_INET6, dhcp_solicit_dst))
        p_solicit_vrf0 = (Ether(dst=dmac, src=self.pg2.remote_mac) /
                          IPv6(src=dhcp_solicit_src_vrf0,
                               dst=dhcp_solicit_dst) /
                          UDP(sport=DHCP6_SERVER_PORT,
                              dport=DHCP6_CLIENT_PORT) /
                          DHCP6_Solicit())
        pkts_solicit_vrf0 = [p_solicit_vrf0]
        p_solicit_vrf1 = (Ether(dst=dmac, src=self.pg3.remote_mac) /
                          IPv6(src=dhcp_solicit_src_vrf1,
                               dst=dhcp_solicit_dst) /
                          UDP(sport=DHCP6_SERVER_PORT,
                              dport=DHCP6_CLIENT_PORT) /
                          DHCP6_Solicit())
        pkts_solicit_vrf1 = [p_solicit_vrf1]

        self.send_and_assert_no_replies(self.pg2, pkts_solicit_vrf0,
                                        "DHCP with no configuration")
        self.send_and_assert_no_replies(self.pg3, pkts_solicit_vrf1,
                                        "DHCP with no configuration")

        #
        # DHCPv6 config in VRF 0.
        # Packets still dropped because the client facing interface has no
        # IPv6 config
        #
        self.vapi.dhcp_proxy_config(server_addr_vrf0,
                                    src_addr_vrf0,
                                    rx_table_id=0,
                                    server_table_id=0,
                                    is_ipv6=1)

        self.send_and_assert_no_replies(self.pg2, pkts_solicit_vrf0,
                                        "DHCP with no configuration")
        self.send_and_assert_no_replies(self.pg3, pkts_solicit_vrf1,
                                        "DHCP with no configuration")

        #
        # configure an IP address on the client facing interface
        #
        self.pg2.config_ip6()

        #
        # Now the DHCP requests are relayed to the server
        #
        self.pg2.add_stream(pkts_solicit_vrf0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        rx = rx[0]
        self.verify_dhcp6_solicit(rx, self.pg0,
                                  dhcp_solicit_src_vrf0,
                                  self.pg2.remote_mac)

        #
        # Exception cases for rejected relay responses
        #

        # 1 - not a relay reply
        p_adv_vrf0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                      IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_Advertise())
        pkts_adv_vrf0 = [p_adv_vrf0]
        self.send_and_assert_no_replies(self.pg2, pkts_adv_vrf0,
                                        "DHCP6 not a relay reply")

        # 2 - no relay message option
        p_adv_vrf0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                      IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_RelayReply() /
                      DHCP6_Advertise())
        pkts_adv_vrf0 = [p_adv_vrf0]
        self.send_and_assert_no_replies(self.pg2, pkts_adv_vrf0,
                                        "DHCP not a relay message")

        # 3 - no circuit ID
        p_adv_vrf0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                      IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_RelayReply() /
                      DHCP6OptRelayMsg(optlen=0) /
                      DHCP6_Advertise())
        pkts_adv_vrf0 = [p_adv_vrf0]
        self.send_and_assert_no_replies(self.pg2, pkts_adv_vrf0,
                                        "DHCP6 no circuit ID")
        # 4 - wrong circuit ID
        p_adv_vrf0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                      IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_RelayReply() /
                      DHCP6OptIfaceId(optlen=4, ifaceid='\x00\x00\x00\x05') /
                      DHCP6OptRelayMsg(optlen=0) /
                      DHCP6_Advertise())
        pkts_adv_vrf0 = [p_adv_vrf0]
        self.send_and_assert_no_replies(self.pg2, pkts_adv_vrf0,
                                        "DHCP6 wrong circuit ID")

        #
        # Send the relay response (the advertisement)
        #   - no peer address
        p_adv_vrf0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                      IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_RelayReply() /
                      DHCP6OptIfaceId(optlen=4, ifaceid='\x00\x00\x00\x03') /
                      DHCP6OptRelayMsg(optlen=0) /
                      DHCP6_Advertise(trid=1) /
                      DHCP6OptStatusCode(statuscode=0))
        pkts_adv_vrf0 = [p_adv_vrf0]

        self.pg0.add_stream(pkts_adv_vrf0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        rx = rx[0]
        self.verify_dhcp6_advert(rx, self.pg2, "::")

        #
        # Send the relay response (the advertisement)
        #   - with peer address
        p_adv_vrf0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                      IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_RelayReply(peeraddr=dhcp_solicit_src_vrf0) /
                      DHCP6OptIfaceId(optlen=4, ifaceid='\x00\x00\x00\x03') /
                      DHCP6OptRelayMsg(optlen=0) /
                      DHCP6_Advertise(trid=1) /
                      DHCP6OptStatusCode(statuscode=0))
        pkts_adv_vrf0 = [p_adv_vrf0]

        self.pg0.add_stream(pkts_adv_vrf0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        rx = rx[0]
        self.verify_dhcp6_advert(rx, self.pg2, dhcp_solicit_src_vrf0)

        #
        # Add all the config for VRF 1
        #
        self.vapi.dhcp_proxy_config(server_addr_vrf1,
                                    src_addr_vrf1,
                                    rx_table_id=1,
                                    server_table_id=1,
                                    is_ipv6=1)
        self.pg3.config_ip6()

        #
        # VRF 1 solicit
        #
        self.pg3.add_stream(pkts_solicit_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        rx = rx[0]
        self.verify_dhcp6_solicit(rx, self.pg1,
                                  dhcp_solicit_src_vrf1,
                                  self.pg3.remote_mac)

        #
        # VRF 1 Advert
        #
        p_adv_vrf1 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                      IPv6(dst=self.pg1.local_ip6, src=self.pg1.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_RelayReply(peeraddr=dhcp_solicit_src_vrf1) /
                      DHCP6OptIfaceId(optlen=4, ifaceid='\x00\x00\x00\x04') /
                      DHCP6OptRelayMsg(optlen=0) /
                      DHCP6_Advertise(trid=1) /
                      DHCP6OptStatusCode(statuscode=0))
        pkts_adv_vrf1 = [p_adv_vrf1]

        self.pg1.add_stream(pkts_adv_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg3.get_capture(1)
        rx = rx[0]
        self.verify_dhcp6_advert(rx, self.pg3, dhcp_solicit_src_vrf1)

        #
        # Add VSS config
        #  table=1, fib=id=1, oui=4
        self.vapi.dhcp_proxy_set_vss(1, 1, 4, is_ip6=1)

        self.pg3.add_stream(pkts_solicit_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        rx = rx[0]
        self.verify_dhcp6_solicit(rx, self.pg1,
                                  dhcp_solicit_src_vrf1,
                                  self.pg3.remote_mac,
                                  fib_id=1,
                                  oui=4)

        #
        # Remove the VSS config
        #  relayed DHCP has default vlaues in the option.
        #
        self.vapi.dhcp_proxy_set_vss(1, 1, 4, is_ip6=1, is_add=0)

        self.pg3.add_stream(pkts_solicit_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        rx = rx[0]
        self.verify_dhcp6_solicit(rx, self.pg1,
                                  dhcp_solicit_src_vrf1,
                                  self.pg3.remote_mac)

        #
        # Cleanup
        #
        self.vapi.dhcp_proxy_config(server_addr_vrf1,
                                    src_addr_vrf1,
                                    rx_table_id=1,
                                    server_table_id=1,
                                    is_ipv6=1,
                                    is_add=0)
        self.vapi.dhcp_proxy_config(server_addr_vrf1,
                                    src_addr_vrf1,
                                    rx_table_id=0,
                                    server_table_id=0,
                                    is_ipv6=1,
                                    is_add=0)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
