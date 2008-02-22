#
# Ramon - A RMON2 Network Monitoring Agent
# Copyright (C) 2003, 2004, 2005, 2007, 2008  Ricardo Nabinger Sanchez
#
# This file is part of Ramon, a network monitoring agent which implements
# the MIB proposed in RFC-2021.
#
# Ramon is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.
#
# Ramon is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along
# with program; see the file COPYING. If not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

#
# This is the group for default installations ('make install').
#
NOSUID_GRP	= wheel

#
# This is the group which will be used if you launch 'make install.suid'.
# Add this group or change this to reflect the one you selected, then put
# users into it (if you didn't it already).
#
SUID_GRP	= rmon2

#
# These variables describe where to look for dependencies.  You should adjust
# them accordingly to your system installation in case of compilation errors
# or if you were asked to.
#

FLEX		= /usr/include
LIBPCAP		= /usr/include
NETSNMP		= /usr/local/include
PTHREAD		= /usr/include


# These are the environmental variables that control where things will be
# installed
INSTALL_LIB	= /usr/lib
INSTALL_ETC	= /etc/rmon2


#
# And finally these (to the end of file) are best left alone.
#

VERSAO		= 0.3.0

CONF_DIR	= etc
SRC_DIR		= src
INCLUDE_DIR	= include
MODULE_DIR	= module


CC		= gcc
CFLAGS		= -Wall
LDFLAGS		= -L/usr/lib -L/usr/local/lib

DOX		= doxygen

ifeq ($(debug),yes)
# debug requested - remove optimizations
CFLAGS		+= -W -O0 -g
else
# normal compile
CFLAGS		= -O2
endif

# test for arch-specific optimizations
ifneq ($(arch),)
CFLAGS		+= -march=$(arch)
endif

# if testing version, we won't need some flags
ifeq ($(test),yes)
MODULE_LFLAGS	=
else
MODULE_LFLAGS	= -fPIC -shared
endif

#
# should we use timefilter or keep it always zero?
#
ifeq ($(timefilter),yes)
CFLAGS		+= -DUSE_TIMEFILTER
else
CFLAGS		+= -UUSE_TIMEFILTER
endif


#
# should we remove support for PTSL?
#
ifeq ($(ptsl),yes)
CFLAGS		+= -DPTSL
TRASSER_OBJ	= $(SRC_DIR)/servidor.o \
		  $(SRC_DIR)/tracos.o \
		  $(SRC_DIR)/trassery.o \
		  $(SRC_DIR)/trasserl.o \
		  $(SRC_DIR)/trasserlib.o
else
CFLAGS		+= -UPTSL
TRASSER_OBJ	=
endif


CFLAGS_OUTROS	= -I$(INCLUDE_DIR)

FLEX_LINK	= -L$(FLEX) -ll

PTH_LINK	= -L$(PTHREAD) -lpthread
PTH_FLAGS	= -D_REENTRANT
PCAP_LINK	= -L$(LIBPCAP) -lpcap

SNMP_HEADERS	= -I$(NETSNMP)
SNMP_LINK	= `net-snmp-config --agent-libs`

APP_CFLAGS	= $(CFLAGS)
APP_LIBS	= $(PTH_LINK) $(PCAP_LINK) $(FLEX_LINK)

MODULE_CFLAGS	= $(CFLAGS) $(SNMP_HEADERS) -I$(INCLUDE_DIR) -I$(MODULE_DIR)
MODULE_LIBS	= $(PTH_LINK) $(PCAP_LINK) $(SNMP_LINK)
MODULE_OBJ	= $(MODULE_DIR)/rmon2.o \
                  $(MODULE_DIR)/protocolDir_scalar.o \
                  $(MODULE_DIR)/protocolDir.o \
                  $(MODULE_DIR)/protocolDist.o \
		  $(MODULE_DIR)/nlHost.o \
		  $(MODULE_DIR)/alHost.o \
		  $(MODULE_DIR)/nlMatrix.o \
		  $(MODULE_DIR)/alMatrix.o \
		  $(SRC_DIR)/alhost.o \
		  $(SRC_DIR)/almatrix_DS.o \
		  $(SRC_DIR)/almatrix_SD.o \
		  $(SRC_DIR)/hlhost.o \
		  $(SRC_DIR)/hlmatrix.o \
                  $(SRC_DIR)/log.o \
                  $(SRC_DIR)/nlhost.o \
		  $(SRC_DIR)/nlmatrix_DS.o \
		  $(SRC_DIR)/nlmatrix_SD.o \
                  $(SRC_DIR)/protocoldir.o \
                  $(SRC_DIR)/protocoldist.o \
		  $(SRC_DIR)/settings.o \
		  $(SRC_DIR)/sysuptime.o \
		  $(SRC_DIR)/conversor.o

APP_OBJECTS	= $(SRC_DIR)/alhost.o \
                  $(SRC_DIR)/almatrix_SD.o \
                  $(SRC_DIR)/almatrix_DS.o \
                  $(SRC_DIR)/hlhost.o \
                  $(SRC_DIR)/hlmatrix.o \
                  $(SRC_DIR)/log.o \
                  $(SRC_DIR)/nlhost.o \
                  $(SRC_DIR)/nlmatrix_SD.o \
                  $(SRC_DIR)/nlmatrix_DS.o \
                  $(SRC_DIR)/protocoldir.o \
                  $(SRC_DIR)/protocoldist.o \
                  $(SRC_DIR)/conversor.o \
		  $(SRC_DIR)/settings.o \
                  $(SRC_DIR)/sysuptime.o \
		  $(SRC_DIR)/rmon2_main.o

#
# This instructs make to not try implicit rules for these targets, reducing
# (a lot!) make's debug-enabled output
#
.PHONY: all app checkdep clean client default dep_pcap dep_snmp distclean doc help install install.suid Makefile module naormon test testar_suid uninstall

#
# In case no target is specified, this will behave like the default one
# (because it is the first).
#
default: module

all: app module client doc

help:
	@echo "Available rules (* is the default rule if you don't specify any):"
	@echo "  all		- compiles everything"
	@echo "  app		- compiles the stand-alone version (for debugging)"
	@echo "  checkdep	- check system dependencies"
	@echo "  clean		- cleans up compilation files"
	@echo "  client	- compiles the client application (for PTSL extension)"
	@echo "  distclean	- full clean (removes binaries also)"
	@echo "  doc		- generates source documentation with doxygen"
	@echo "  install	- installs the agent at standard location"
	@echo "  install.suid	- like install, with setuid bit (security danger)"
	@echo "* module 	- compiles the Net-SNMP RMON2 agent module"
	@echo "  uninstall	- removes the installed agent, from standard location"
	@echo ""

test: $(MODULE_OBJ)

checkdep: dep_pcap dep_snmp

dep_pcap:
	@[ -r $(LIBPCAP)/pcap.h ] || \
	( echo "error: libpcap could not be found under '$(LIBPCAP)'" && \
	echo "Please edit the file Makefile and adjust the variable 'LIBPCAP'" && \
	echo "in order to reflect the installation prefix of libpcap." && false )

dep_snmp:
	@[ -r $(NETSNMP)/net-snmp/net-snmp-config.h ] || \
	( echo "error: Net-SNMP could not be found under '$(NETSNMP)'" ; \
	echo "Please edit the file Makefile and adjust the variable 'NETSNMP'" ; \
	echo "in order to reflect the installation prefix of Net-SNMP." ; false )

clean:
	rm -f $(SRC_DIR)/*.o $(TESTS_DIR)/*.o $(MODULE_DIR)/*.o
	rm -f $(SRC_DIR)/trassery.c $(SRC_DIR)/trasserl.c $(SRC_DIR)/y.output
	rm -f $(SRC_DIR)/y.tab.h $(SRC_DIR)/y.tab.c


#
#	module: rule to build the RMON2 agent and the Net-SNMP module
#
module: checkdep client $(MODULE_OBJ) $(TRASSER_OBJ)
	$(CC) $(MODULE_CFLAGS) $(LDFLAGS) $(MODULE_LFLAGS) -o $(MODULE_DIR)/rmon2-$(VERSAO).so $(MODULE_OBJ) $(TRASSER_OBJ) $(FLEX_LINK) $(MODULE_LIBS)


#
#	Targets which don't need special build options
#
$(MODULE_DIR)/%.o: $(MODULE_DIR)/%.c
	$(CC) $(CFLAGS) $(MODULE_CFLAGS) -c $< -o $@

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@


#
#	Targets which require additional stuff to build
#
$(MODULE_DIR)/protocolDir.o: $(MODULE_DIR)/protocolDir.c
	$(CC) $(CFLAGS) $(MODULE_CFLAGS) -D_REENTRANT -c $*.c -o $@

$(MODULE_DIR)/protocolDist.o: $(MODULE_DIR)/protocolDist.c
	$(CC) $(CFLAGS) $(MODULE_CFLAGS) -D_REENTRANT -c $*.c -o $@

$(SRC_DIR)/conversor.o: $(SRC_DIR)/conversor.c
	$(CC) $(CFLAGS) $(PTH_FLAGS) -I$(INCLUDE_DIR) -I$(LIBPCAP) -c $*.c -o $@

$(SRC_DIR)/rmon2_main.o: $(SRC_DIR)/rmon2_main.c
	$(CC) $(CFLAGS) -D_REENTRANT -I$(INCLUDE_DIR) -c $*.c -o $@

$(SRC_DIR)/servidor.o: $(SRC_DIR)/servidor.c
	$(CC) $(CFLAGS) -D_REENTRANT -I$(INCLUDE_DIR) -c $*.c -o $@


# Trasser stuff
$(SRC_DIR)/trassery.o: $(SRC_DIR)/trasser.y
	yacc -dvt $(SRC_DIR)/trasser.y
	cp y.tab.c $(SRC_DIR)/trassery.c
	mv y.tab.c $(SRC_DIR)/
	mv y.tab.h $(SRC_DIR)/
	mv y.output $(SRC_DIR)/
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $*.c -o $@

$(SRC_DIR)/trasserl.o: $(SRC_DIR)/trasser.l
	flex -l $(SRC_DIR)/trasser.l
	mv lex.yy.c $(SRC_DIR)/trasserl.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $*.c -o $@

#
#	app: rule that builds a stand-alone agent, mainly used for tests and
#	debugging.
#
app: dep_pcap client $(APP_OBJECTS) $(TRASSER_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(SRC_DIR)/rmon2 $(APP_OBJECTS) $(TRASSER_OBJ) $(APP_LIBS)

client: $(SRC_DIR)/client.o $(SRC_DIR)/log.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(SRC_DIR)/client $(SRC_DIR)/client.o $(SRC_DIR)/log.o

# Simple rule to generate the (somewhat outdated) documentation
doc:
	$(DOX) Doxyfile

# regras para compilar $(OUTROS_OBJECTS)
naormon: checkdep $(OUTROS_OBJECTS)


distclean:
	rm -f $(SRC_DIR)/*.o
	rm -f $(SRC_DIR)/trassery.c $(SRC_DIR)/trasserl.c $(SRC_DIR)/y.output $(SRC_DIR)/y.tab.h
	rm -f $(SRC_DIR)/rmon2 $(SRC_DIR)/client $(SRC_DIR)/y.tab.c
	rm -f $(TESTS_DIR)/*.o
	rm -f $(MODULE_DIR)/*.o $(MODULE_DIR)/rmon2-*.so
	rm -rf doc/html doc/latex


install:
	mkdir -p $(INSTALL_ETC)
	if [ ! -f $(INSTALL_ETC)/rmon2.conf ]; then \
		install -g $(NOSUID_GRP) -o root \
		-m 0644 $(CONF_DIR)/rmon2.conf $(INSTALL_ETC); \
		fi
	if [ ! -f $(INSTALL_ETC)/protocoldir.conf ]; then \
		install -g $(NOSUID_GRP) -o root \
		-m 0644 $(CONF_DIR)/protocoldir.conf $(INSTALL_ETC); \
		fi
	install -g $(NOSUID_GRP) -o root -m 0750 $(MODULE_DIR)/rmon2-$(VERSAO).so $(INSTALL_LIB)
	ln -sf $(INSTALL_LIB)/rmon2-$(VERSAO).so $(INSTALL_LIB)/rmon2.so


# Check if the group required for suid install exists.
testar_suid:
	@fgrep "$(SUID_GRP):" /etc/group > /dev/null || \
	echo "Please create the group '$(SUID_GRP)' first, or change the authorized group in this Makefile." ; \
	false

#
#	If needed, the RMON2 agent can be installed with suid set, so users
# 	belonging to the group $(SUID_GRP) will be able to start the agent.
#
install.suid: testar_suid
	mkdir -p $(INSTALL_ETC)
	chown root:$(SUID_GRP) $(INSTALL_ETC)
	if [ ! -f $(INSTALL_ETC)/rmon2.conf ]; then \
		install -g $(SUID_GRP) -o root \
		-m 0640 $(CONF_DIR)/rmon2.conf $(INSTALL_ETC); \
		fi
	if [ ! -f $(INSTALL_ETC)/protocoldir.conf ]; then \
		install -g $(SUID_GRP) -o root \
		-m 0640 $(CONF_DIR)/protocoldir.conf $(INSTALL_ETC); \
		fi
	install -g $(SUID_GRP) -o root -m 4710 $(MODULE_DIR)/rmon2-$(VERSAO).so $(INSTALL_LIB)
	ln -sf $(INSTALL_LIB)/rmon2-$(VERSAO).so $(INSTALL_LIB)/rmon2.so
	@echo -e "\nNow you should set a similar permission to the snmpd executable."
	@echo "Suggestion:"
	@echo "    chown root:$(SUID_GRP) `which snmpd`"
	@echo "    chmod 4710 `which snmpd`"

uninstall:
	rm -f $(INSTALL_LIB)/rmon2.so
	rm -f $(INSTALL_LIB)/rmon2-$(VERSAO).so
	rm -f $(INSTALL_ETC)/rmon2.conf
	rm -f $(INSTALL_ETC)/protocoldir.conf
	rmdir $(INSTALL_ETC)

