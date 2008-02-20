/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2004, 2008  Ricardo Nabinger Sanchez
 * Copyright (C) 2004  Diego Wentz Antunes
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

/** \file client.c
 *  This is a simple TCP client which communicates with the PTSL server.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "globals.h"
#include "log.h"
//#include "debug.h"


/*
 *  constants here
 */
/** \brief Enumeration of server command types */
enum en_server_commands {CMD_INSTALL, CMD_RUN, CMD_PAUSE, CMD_STOP, CMD_REMOVE, CMD_WRONG};


/*
 *  forward prototypes
 */
static int resolve_command(char *command_string);
static void print_usage();


int
main(int argc, char *argv[])
{
	char			buffer[1024];
	struct sockaddr_in	server_addr;
	int			buflen;
	int			socket_tcp;
	unsigned int		blocks = 0;
	FILE			*file;

	if (argc < 2) {
		print_usage();
		return 127;
	}

	/* acquire socket */
	socket_tcp = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_tcp == -1) {
		perror("socket");
		abort();
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVER_PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	memset(server_addr.sin_zero, '\0', 8);

	/* connect to server */
	if (connect(socket_tcp, (struct sockaddr *)&server_addr,
				sizeof(server_addr)) == -1) {
		perror("connect");
		abort();
	}

	switch (resolve_command(argv[1])) {
		case CMD_INSTALL:
			/* check arguments count */
			if (argc != 7) {
				Debug("too few parameters to `install' command");
				print_usage();
				return 127;
			}

			/* open PTSL file */
			file = fopen(argv[2], "r");
			if (file == NULL) {
				Debug("could not open file `%s'\n", argv[2]);
				perror("fopen");
				abort();
			}

			/* format and send command */
			buflen = sprintf(buffer, "%s#%s#%s#%s#%s#", argv[1],
					argv[3], argv[4], argv[5], argv[6]);
			if (send(socket_tcp, buffer, buflen, 0) == -1) {
				Debug("`%s' failed\n", argv[1]);
				perror("send");
				abort();
			}

			/* make room for expected answer */
			memset(buffer, '\0', sizeof("SEND_PTSL_"));

			/* wait for server response */
			if (recv(socket_tcp, buffer, sizeof(buffer), 0) == -1) {
				perror("recv");
				abort();
			}

			/* check it */
			if (strcasecmp(buffer, "SEND PTSL") != 0)
				Fatal("`%s' failed\n", argv[1]);


			/* send the file */
			buflen = fread(buffer, 1, sizeof(buffer), file);
			if (buflen == -1) {
				Debug("error while reading from file");
				perror("fread");
				return 126;
			}

			while (buflen > 0) {
				if (send(socket_tcp, buffer, buflen, 0) == -1)
					Fatal("error while sending block %u\n",
							blocks);
				buflen = fread(buffer, 1, sizeof(buffer), file);
				blocks++;
			}

			/* send end-of-file alert */
			buflen = sprintf(buffer, "END.");
			if (send(socket_tcp, buffer, buflen, 0) == -1)
				Fatal("error while sending `END.' message");

			/* make room for expected message */
			memset(buffer, '\0', sizeof("OK_"));

			/* wait for server response */
			if (recv(socket_tcp, buffer, sizeof(buffer), 0) == -1) {
				perror("recv");
				abort();
			}

			/* check it */
			if (strcasecmp(buffer, "OK") == 0) {
				Debug("`%s %s as ptsl_id:%s' suceeded", argv[1],
						argv[2], argv[3]);
			}
			else
				Fatal("`%s' failed", argv[1]);

			break;

		case CMD_RUN:
			/* fall-through */
		case CMD_PAUSE:
			/* fall-through */
		case CMD_STOP:
			/* fall-through */
		case CMD_REMOVE:
			buflen = sprintf(buffer, "%s#%s#", argv[1], argv[2]);
			if (send(socket_tcp, buffer, buflen, 0) == -1) {
				Debug("`%s %s' failed", argv[1], argv[2]);
				perror("send");
				abort();
			}

			if (recv(socket_tcp, buffer, sizeof(buffer), 0) == -1) {
				perror("recv");
				abort();
			}

			if (strcasecmp(buffer, "OK") == 0)
				Debug("`%s %s' suceeded", argv[1], argv[2]);
			break;

		default:
			print_usage();
			return 127;
	}

	return 0;
}



/** \brief Resolves a string command into an enum type
 *
 *  This function takes the only argument \c command_string and tries to
 *  resolve it to one of the supported command types.
 *
 *  \retval CMD_INSTALL
 *  \retval CMD_RUN
 *  \retval CMD_PAUSE
 *  \retval CMD_STOP
 *  \retval CMD_REMOVE
 *  \retval ERROR_PARAMETER in case of error
 */
static int
resolve_command(char *command_string)
{
	if (strcasecmp(command_string, "install") == 0) {
		return CMD_INSTALL;
	}

	if (strcasecmp(command_string, "run") == 0) {
		return CMD_RUN;
	}

	if (strcasecmp(command_string, "pause") == 0) {
		return CMD_PAUSE;
	}

	if (strcasecmp(command_string, "stop") == 0) {
		return CMD_STOP;
	}

	if (strcasecmp(command_string, "remove") == 0) {
		return CMD_REMOVE;
	}

	return CMD_WRONG;
}


/** \brief This only prints usage instructions.
*/
static void
print_usage()
{
	fprintf(stderr, "client: not enough parameters\n\n"
			"  client install <PTSL file> ptsl_id 'owner string'"
			"	'language string' 'description string'\n"
			"  client run|pause|stop|remove ptsl_id\n");
}
