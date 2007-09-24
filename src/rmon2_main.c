/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2004 Ricardo Nabinger Sanchez
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

static char error_color_string[] = "\033[1;41;37m";
static char reset_color_string[] = "\033[0m";

int main()
{
	pthread_t	captura;
	pthread_t	servidor;

	if (init_sysuptime() != SUCCESS) {
		fprintf(stderr, "%srmon2_main.c: error while initializing uptime accounting%s\n",
				error_color_string, reset_color_string);
		abort();
	}

	if (init_protocoldir(NULL) != SUCCESS) {
		fprintf(stderr, "%srmon2_main.c: error while initializing protocolDir group%s\n",
				error_color_string, reset_color_string);
		abort();
	}

	if (conv_inicializa() != SUCCESS) {
		fprintf(stderr, "%srmon2_main.c: error while initializing packet sniffer%s\n",
				error_color_string, reset_color_string);
		abort();
	}

	if (pthread_create(&captura, NULL, captura_processa_pacote, NULL) != 0) {
		fprintf(stderr, "%srmon2_main.c: could not create packet sniffer thread%s\n",
				error_color_string, reset_color_string);
		abort();
	}

#if PTSL
	if (pthread_create(&servidor, NULL, server_start, NULL)) {
		fprintf(stderr, "%srmon2_main.c: could not create server thread%s\n",
				error_color_string, reset_color_string);
		abort();
	}
#endif

	/*
	 *	It is not expected reaching here
	 */
	pthread_join(captura, NULL);
	pthread_join(servidor, NULL);

	fprintf(stderr, "%srmon2_main.c: unexpected KIA thread%s\n",
			error_color_string, reset_color_string);

	return -1;
}

