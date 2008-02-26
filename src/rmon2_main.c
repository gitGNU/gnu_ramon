/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2004, 2008 Ricardo Nabinger Sanchez
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "configuracao.h"

#include <pthread.h>

#include "globals.h"
#include "exit_codes.h"

#ifdef PTSL
#include <netinet/in.h>
#include "stateful.h"
#include "pedb.h"
#include "servidor.h"
#endif

#include "pedb.h"
#include "conversor.h"
#include "protocoldir.h"
#include "sysuptime.h"
#include "log.h"


int main()
{
	pthread_t	captura;
#if PTSL
	pthread_t	servidor;
#endif

	if (init_sysuptime() != SUCCESS) {
		Fatal("error while initializing uptime accounting");
	}

	if (init_protocoldir(NULL) != SUCCESS) {
		Fatal("error while initializing protocolDir group");
	}

	if (init_sniffer() != SUCCESS) {
		Fatal("error while initializing packet sniffer");
	}

	if (pthread_create(&captura, NULL, captura_processa_pacote, NULL) != 0) {
		Fatal("could not create packet sniffer thread");
	}

#if PTSL
	if (pthread_create(&servidor, NULL, server_start, NULL)) {
		Fatal("could not create server thread");
	}
#endif

	/* Lock on threads. */
	pthread_join(captura, NULL);
#if PTSL
	pthread_join(servidor, NULL);
#endif

	Fatal("unexpected thread termination");
	return 1;
}

