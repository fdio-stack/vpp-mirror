# Copyright (c) 2016 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CFLAGS = -Wall

nobase_include_HEADERS =

# lib_LTLIBRARIES = liburiclient.la

# liburiclient_la_SOURCES = uriclient.c
# nobase_include_HEADERS += uriclient.h

bin_PROGRAMS = uri_udp_test2

#uritest_SOURCES = uritest.c
#uritest_LDADD = -lvlibmemoryclient -lvlibapi -lsvm \
#	-lvppinfra -lpthread -lm -lrt

#uri_udp_test_SOURCES = uri_udp_test.c
#uri_udp_test_LDADD = -lvlibmemoryclient -lvlibapi -lsvm \
#	-lvppinfra -lpthread -lm -lrt

uri_udp_test2_SOURCES = uri_udp_test2.c
uri_udp_test2_LDADD = -lvlibmemoryclient -lvlibapi -lsvm \
	-lvppinfra -lpthread -lm -lrt

lib_LTLIBRARIES = libvpp_commapi.la

libvpp_commapi_la_SOURCES = vpp_commapi.c
nobase_include_HEADERS += vpp_commapi.h
libvpp_commapi_la_LIBADD =  -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra -lpthread -lm -lrt -ldl


bin_PROGRAMS += server1
server1_SOURCES = server1.c
server1_LDADD = libvpp_commapi.la
#server1_LDFLAGS = -static

bin_PROGRAMS += client
client_SOURCES = client.c
client_LDADD = libvpp_commapi.la
#server1_LDFLAGS = -static
