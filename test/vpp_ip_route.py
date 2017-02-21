"""
  IP Routes

  object abstractions for representing IP routes in VPP
"""

import socket
from vpp_object import *

# from vnet/vnet/mpls/mpls_types.h
MPLS_IETF_MAX_LABEL = 0xfffff
MPLS_LABEL_INVALID = MPLS_IETF_MAX_LABEL + 1


class VppRoutePath(object):

    def __init__(
            self,
            nh_addr,
            nh_sw_if_index,
            nh_table_id=0,
            labels=[],
            nh_via_label=MPLS_LABEL_INVALID,
            is_ip6=0):
        self.nh_itf = nh_sw_if_index
        self.nh_table_id = nh_table_id
        self.nh_via_label = nh_via_label
        self.nh_labels = labels
        if is_ip6:
            self.nh_addr = socket.inet_pton(socket.AF_INET6, nh_addr)
        else:
            self.nh_addr = socket.inet_pton(socket.AF_INET, nh_addr)


class VppMRoutePath(VppRoutePath):

    def __init__(self, nh_sw_if_index, flags):
        super(VppMRoutePath, self).__init__("0.0.0.0",
                                            nh_sw_if_index)
        self.nh_i_flags = flags


class VppIpRoute(VppObject):
    """
    IP Route
    """

    def __init__(self, test, dest_addr,
                 dest_addr_len, paths, table_id=0, is_ip6=0, is_local=0):
        self._test = test
        self.paths = paths
        self.dest_addr_len = dest_addr_len
        self.table_id = table_id
        self.is_ip6 = is_ip6
        self.is_local = is_local
        if is_ip6:
            self.dest_addr = socket.inet_pton(socket.AF_INET6, dest_addr)
        else:
            self.dest_addr = socket.inet_pton(socket.AF_INET, dest_addr)

    def add_vpp_config(self):
        if self.is_local:
            self._test.vapi.ip_add_del_route(
                self.dest_addr,
                self.dest_addr_len,
                socket.inet_pton(socket.AF_INET6, "::"),
                0xffffffff,
                is_local=1,
                table_id=self.table_id,
                is_ipv6=self.is_ip6)
        else:
            for path in self.paths:
                self._test.vapi.ip_add_del_route(
                    self.dest_addr,
                    self.dest_addr_len,
                    path.nh_addr,
                    path.nh_itf,
                    table_id=self.table_id,
                    next_hop_out_label_stack=path.nh_labels,
                    next_hop_n_out_labels=len(
                        path.nh_labels),
                    next_hop_via_label=path.nh_via_label,
                    is_ipv6=self.is_ip6)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        if self.is_local:
            self._test.vapi.ip_add_del_route(
                self.dest_addr,
                self.dest_addr_len,
                socket.inet_pton(socket.AF_INET6, "::"),
                0xffffffff,
                is_local=1,
                is_add=0,
                table_id=self.table_id,
                is_ipv6=self.is_ip6)
        else:
            for path in self.paths:
                self._test.vapi.ip_add_del_route(self.dest_addr,
                                                 self.dest_addr_len,
                                                 path.nh_addr,
                                                 path.nh_itf,
                                                 table_id=self.table_id,
                                                 is_add=0)

    def query_vpp_config(self):
        dump = self._test.vapi.ip_fib_dump()
        for e in dump:
            if self.dest_addr == e.address \
               and self.dest_addr_len == e.address_length \
               and self.table_id == e.table_id:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s/%d"
                % (self.table_id,
                   socket.inet_ntop(socket.AF_INET, self.dest_addr),
                   self.dest_addr_len))


class VppIpMRoute(VppObject):
    """
    IP Multicast Route
    """

    def __init__(self, test, src_addr, grp_addr,
                 grp_addr_len, e_flags, paths, table_id=0, is_ip6=0):
        self._test = test
        self.paths = paths
        self.grp_addr_len = grp_addr_len
        self.table_id = table_id
        self.e_flags = e_flags
        self.is_ip6 = is_ip6

        if is_ip6:
            self.grp_addr = socket.inet_pton(socket.AF_INET6, grp_addr)
            self.src_addr = socket.inet_pton(socket.AF_INET6, src_addr)
        else:
            self.grp_addr = socket.inet_pton(socket.AF_INET, grp_addr)
            self.src_addr = socket.inet_pton(socket.AF_INET, src_addr)

    def add_vpp_config(self):
        for path in self.paths:
            self._test.vapi.ip_mroute_add_del(self.src_addr,
                                              self.grp_addr,
                                              self.grp_addr_len,
                                              self.e_flags,
                                              path.nh_itf,
                                              path.nh_i_flags,
                                              table_id=self.table_id,
                                              is_ipv6=self.is_ip6)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        for path in self.paths:
            self._test.vapi.ip_mroute_add_del(self.src_addr,
                                              self.grp_addr,
                                              self.grp_addr_len,
                                              self.e_flags,
                                              path.nh_itf,
                                              path.nh_i_flags,
                                              table_id=self.table_id,
                                              is_add=0,
                                              is_ipv6=self.is_ip6)

    def update_entry_flags(self, flags):
        self.e_flags = flags
        self._test.vapi.ip_mroute_add_del(self.src_addr,
                                          self.grp_addr,
                                          self.grp_addr_len,
                                          self.e_flags,
                                          0xffffffff,
                                          0,
                                          table_id=self.table_id,
                                          is_ipv6=self.is_ip6)

    def update_path_flags(self, itf, flags):
        for path in self.paths:
            if path.nh_itf == itf:
                path.nh_i_flags = flags
                break
        self._test.vapi.ip_mroute_add_del(self.src_addr,
                                          self.grp_addr,
                                          self.grp_addr_len,
                                          self.e_flags,
                                          path.nh_itf,
                                          path.nh_i_flags,
                                          table_id=self.table_id,
                                          is_ipv6=self.is_ip6)

    def query_vpp_config(self):
        dump = self._test.vapi.ip_fib_dump()
        for e in dump:
            if self.grp_addr == e.address \
               and self.grp_addr_len == e.address_length \
               and self.table_id == e.table_id:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        if self.is_ip6:
            return ("%d:(%s,%s/%d)"
                    % (self.table_id,
                       socket.inet_ntop(socket.AF_INET6, self.src_addr),
                       socket.inet_ntop(socket.AF_INET6, self.grp_addr),
                       self.grp_addr_len))
        else:
            return ("%d:(%s,%s/%d)"
                    % (self.table_id,
                       socket.inet_ntop(socket.AF_INET, self.src_addr),
                       socket.inet_ntop(socket.AF_INET, self.grp_addr),
                       self.grp_addr_len))


class VppMFibSignal(object):
    def __init__(self, test, route, interface, packet):
        self.route = route
        self.interface = interface
        self.packet = packet
        self.test = test

    def compare(self, signal):
        self.test.assertEqual(self.interface, signal.sw_if_index)
        self.test.assertEqual(self.route.table_id, signal.table_id)
        self.test.assertEqual(self.route.grp_addr_len,
                              signal.grp_address_len)
        for i in range(self.route.grp_addr_len / 8):
            self.test.assertEqual(self.route.grp_addr[i],
                                  signal.grp_address[i])
        if (self.route.grp_addr_len > 32):
            for i in range(4):
                self.test.assertEqual(self.route.src_addr[i],
                                      signal.src_address[i])


class VppMplsIpBind(VppObject):
    """
    MPLS to IP Binding
    """

    def __init__(self, test, local_label, dest_addr, dest_addr_len,
                 table_id=0, ip_table_id=0):
        self._test = test
        self.dest_addr = socket.inet_pton(socket.AF_INET, dest_addr)
        self.dest_addr_len = dest_addr_len
        self.local_label = local_label
        self.table_id = table_id
        self.ip_table_id = ip_table_id

    def add_vpp_config(self):
        self._test.vapi.mpls_ip_bind_unbind(self.local_label,
                                            self.dest_addr,
                                            self.dest_addr_len,
                                            table_id=self.table_id,
                                            ip_table_id=self.ip_table_id)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.mpls_ip_bind_unbind(self.local_label,
                                            self.dest_addr,
                                            self.dest_addr_len,
                                            is_bind=0)

    def query_vpp_config(self):
        dump = self._test.vapi.mpls_fib_dump()
        for e in dump:
            if self.local_label == e.label \
               and self.eos_bit == e.eos_bit \
               and self.table_id == e.table_id:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s binds %d:%s/%d"
                % (self.table_id,
                   self.local_label,
                   self.ip_table_id,
                   socket.inet_ntop(socket.AF_INET, self.dest_addr),
                   self.dest_addr_len))


class VppMplsRoute(VppObject):
    """
    MPLS Route/LSP
    """

    def __init__(self, test, local_label, eos_bit, paths, table_id=0):
        self._test = test
        self.paths = paths
        self.local_label = local_label
        self.eos_bit = eos_bit
        self.table_id = table_id

    def add_vpp_config(self):
        for path in self.paths:
            self._test.vapi.mpls_route_add_del(
                self.local_label,
                self.eos_bit,
                1,
                path.nh_addr,
                path.nh_itf,
                table_id=self.table_id,
                next_hop_out_label_stack=path.nh_labels,
                next_hop_n_out_labels=len(
                    path.nh_labels),
                next_hop_via_label=path.nh_via_label,
                next_hop_table_id=path.nh_table_id)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        for path in self.paths:
            self._test.vapi.mpls_route_add_del(self.local_label,
                                               self.eos_bit,
                                               1,
                                               path.nh_addr,
                                               path.nh_itf,
                                               table_id=self.table_id,
                                               is_add=0)

    def query_vpp_config(self):
        dump = self._test.vapi.mpls_fib_dump()
        for e in dump:
            if self.local_label == e.label \
               and self.eos_bit == e.eos_bit \
               and self.table_id == e.table_id:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s/%d"
                % (self.table_id,
                   self.local_label,
                   20+self.eos_bit))
