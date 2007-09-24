/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2005 Ricardo Nabinger Sanchez
 *
 * This file is part of Ramon, a network monitoring agent which implements
 * the MIB proposed in RFC-2021.
 *
 * Ramon is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Ramon is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with program; see the file COPYING. If not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/** \file pkt_sniffer.c
 *
 *  This file contains the code for the packet sniffer, which captures packets
 *  on network interfaces.  It also obsoletes the ``conversor.c'' module.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <pthread.h>


/*
 *  local defines
 */
/** \brief The maximum number of network interfaces we'll be prepared to sniff */
#define MAX_INTERFACES	4
/** \brief Number of slots in the buffer to hold packets */
#define MAX_PACKETS	1024
/** \brief How many bytes (from layer 2) of the packet we should sniff */
#define PACKET_SIZE	68
/** \brief Desired socket buffer (rmem_max) to pass to SO_RCVBUF */
#define RECEIVE_BUFFER	524288


/*
 *  global variables
 */
/** \brief The packet buffer */
unsigned char	packet_buffer[MAX_PACKETS][PACKET_SIZE];
/** \brief Threads, each one for each network interface we expect to sniff from */
pthread_t	thr_sniffer[MAX_INTERFACES] = {0,};
/** \brief Sockets, one for each thread */
int		sck_sniffer[MAX_INTERFACES] = {0,};


/** \brief Creates a thread to sniff packets from a given interface.
 *
 *  This function is used when a network interface will be sniffed.
 *
 *  \param  if_name A string (like "eth0") with the interface to open.
 */
int
sniffer_open_interface_by_name(char *if_name)
{
	struct ifreq    ifr;
	int		    ifindex;
	int		    ifname_len;
	short	    ifflags;
	unsigned char   choose;

	/* try to pick up a thread slot */
	for (choose = 0; choose < MAX_INTERFACES; choose++) {
		if (thr_sniffer[choose] == 0) {
			break;
		}
	}
	if (choose == MAX_INTERFACES) {
		fprintf(stderr, "sniffer: too many interfaces, can't open more\n");
		return ERROR_FULL;
	}

	/* get a socket */
	sck_sniffer[choose] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (sck_sniffer[choose] == -1) {
		perror("sniffer.socket");
		return ERROR_IO;
	}

	/* try to use larger receive buffers */
	ifname_len = RECEIVE_BUFFER;
	if (setsockopt(sck_sniffer[choose], SOL_SOCKET, SO_RCVBUF, &ifname_len,
				sizeof(ifname_len)) == -1) {
		perror("sniffer.so_rcvbuf");
		fprintf(stderr, "sniffer: could not enlarge receive buffer to %d\n", ifname_len);
	}

	/* try to bind it to the interface if_name */
	ifname_len = strlen(if_name);
	if (setsockopt(sck_sniffer[choose], SOL_SOCKET, SO_BINDTODEVICE, if_name,
				ifname_len) == -1) {
		perror("sniffer.so_bindtodevice");
		return ERROR_IO;
	}

	/* get interface flags and set IFF_PROMISC */
	strcpy(ifr.ifr_name, if_name);
	if (ioctl(sck_sniffer[choose], SIOGIFFLAGS, &ifr) == -1) {
		perror("sniffer.siogifflags");
		return ERROR_IO;
	}
	ifr.if_flags |= IFF_PROMISC;
	if (ioctl(sck_sniffer[choose], SIOSIFFLAGS, &ifr) == -1) {
		perror("sniffer.siosifflags");
		return ERROR_IO;
	}

	/* find out interface index -- needed by protocolDist */
	if (ioctl(sck_sniffer[choose], SIOGIFINDEX, &ifr) == -1) {
		perror("sniffer.siogifindex");
		return ERROR_IO;
	}
	ifindex = ifr.ifr_ifindex;

	/* TODO: enable interface in protocolDistControl */

	/* TODO: start sniffing packets */
}

