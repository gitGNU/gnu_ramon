/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2004 Ricardo Nabinger Sanchez, Diego Wentz Antunes
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

/** \file servidor.c
 *  This is a simple TCP server to enable the agent to install, remove or do
 *  other likely operations on PTSL definitions.
 *
 *  The server receives commands, process and executes them, if they seem to
 *  be correct.  For the moment, there's no security checks.  This is only
 *  needed to run the stateful packet inspection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#include "globals.h"
#include "stateful.h"
#include "protocoldir.h"
#include "exit_codes.h"
#include "pedb.h"
#include "tracos.h"
//#include "debug.h"

#define SERVER_QUEUE	16
#define SERVER_BUFFER	1024

extern int  yyparse();
extern FILE *yyin;


/*
 *  constants here
 */
/** \brief ANSI color code for critical messages */
static const char error_color_string[] = "\033[1;41;37m";
/** \brief ANSI color code for color reset */
static const char reset_color_string[] = "\033[0m";
/** \brief Enumeration of server command types */
enum en_server_commands {CMD_INSTALL, CMD_RUN, CMD_PAUSE, CMD_STOP, CMD_REMOVE};


/*
 *  global variables here
 */


/*
 *  forward prototype declarations here
 */
void * server_start();
static int server_execute(int peer, char *command);
static int server_resolve_command(char *command_string);


/** \brief The main server function
 *
 *  This function is the server's main function, which handles clients and
 *  executes their commands.  There may happen 2 types of errors:
 *
 *  \li hard errors, which are (still) non-recoverable and fatal
 *  \li soft errors, which are client-related, and do not harm the agent
 */
void *
server_start()
{
	char		buffer[SERVER_BUFFER];
	struct sockaddr_in	server_addr;
	struct sockaddr_in	client_addr;
	int			client_addr_len;
	int			socket_main;
	int			socket_client;
	int			buflen;

	/* acquire socket */
	socket_main = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_main == -1) {
		fprintf(stderr, "%sserver: TCP socket() failed%s\n",
				error_color_string, reset_color_string);
		abort();
	}

	/* ask SO_REUSEADDR */
	buflen = 1;
	if (setsockopt(socket_main, SOL_SOCKET, SO_REUSEADDR, &buflen, sizeof(buflen)) == -1) {
#ifdef DEBUG_SERVER
		fprintf(stderr, "server: not allowed to set SO_REUSEADDR, continuing anyway.\n");
#endif
		perror("server: setsockopt");
	}

	/* prepare binding */
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVER_PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	memset(server_addr.sin_zero, '\0', 8);

	if (bind(socket_main, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		fprintf(stderr, "%sserver: TCP bind() failed%s\n",
				error_color_string, reset_color_string);
		abort();
	}

	/* ready to accept */
	if (listen(socket_main, SERVER_QUEUE) == -1) {
		fprintf(stderr, "%sserver: TCP listen() failed%s\n",
				error_color_string, reset_color_string);
		abort();
	}

	/* forever ... */
	while (1) {
		memset(buffer, '\0', SERVER_BUFFER);
		client_addr_len = sizeof(client_addr);
		socket_client = accept(socket_main, (struct sockaddr *)&client_addr, &client_addr_len);
		if (socket_client == -1) {
			fprintf(stderr, "%sserver: TCP accept() failed, shutting down client%s\n",
					error_color_string, reset_color_string);
			shutdown(socket_client, SHUT_RDWR);
			continue;
		}

		buflen = recv(socket_client, buffer, sizeof(buffer), 0);
		if (buflen == -1) {
			fprintf(stderr, "%sserver: TCP recv() failed, shutting down client%s\n",
					error_color_string, reset_color_string);
			shutdown(socket_client, SHUT_RDWR);
			continue;
		}

		/* wait for processing */
		if (server_execute(socket_client, buffer) == SUCCESS) {
			buflen = sprintf(buffer, "OK");
		}
		else {
			buflen = sprintf(buffer, "ERROR");
			fprintf(stderr, "%sserver: bad command, shutting down client%s\n",
					error_color_string, reset_color_string);
		}

		if (send(socket_client, buffer, buflen, 0) == -1) {
			fprintf(stderr, "%sserver: TCP send() failed, shutting down client%s\n",
					error_color_string, reset_color_string);
		}

		shutdown(socket_client, SHUT_RDWR);
	}

	/* happy compiler! */
	return NULL;
}


/** \brief Executes a command over a PTSL definition sent by a remote client
 *
 *  This function parses and executes a command to operate over a PTSL definition,
 *  which may be install, run, pause, stop or remove.
 *
 *  \param  peer    Initialized socket to communicate with the remote peer
 *  \param  command The command sent by the peer
 *
 *  \retval SUCCESS		If everything went OK, and the command could be executed
 *  \retval ERROR_PARAMETER	If a bad parameter was passed by the peer
 *  \retval ERROR_IO		If an error occurs while transmitting/receiving/saving data
 *  \retval ERROR_NEEDCODING	Guess what. :)
 */
static int
server_execute(int peer, char *command_string)
{
	char    local_buffer[2048];
	int	    buflen;
	char    *command;
	char    *ptsl_id;
	char    *owner;
	char    *lang;
	char    *descr;
	FILE    *file;

	command = strtok(command_string, "#\n");
	ptsl_id = strtok(NULL, "#\n");

	switch (server_resolve_command(command)) {
		case CMD_INSTALL:
			owner = strtok(NULL, "#\n");
			lang  = strtok(NULL, "#\n");
			descr = strtok(NULL, "#\n");

			if (tracos_localiza_por_id(atoi(ptsl_id))) {
				/* Ooops, already installed with this ID */
				return ERROR_ALREADYEXISTS;
			}

			file = fopen(ptsl_id, "w+");
			if (file == NULL) {
				fprintf(stderr, "%sserver: error while creating file `%s'%s\n",
						error_color_string, ptsl_id, reset_color_string);
			}

			buflen = sprintf(local_buffer, "SEND PTSL");
			if (send(peer, local_buffer, buflen, 0) == -1) {
				fprintf(stderr, "%sserver: could not send to peer%s\n",
						error_color_string, reset_color_string);
				return ERROR_IO;
			}

			/*
			 *	now we wait for data and write to the file.
			 *	in each iteration, we check the last 4 bytes of the buffer,
			 *	looking for ``EOF.'' which signals the end of file.
			 *	EOF. should not be written to file
			 */
			while (1) {
				buflen = recv(peer, local_buffer, sizeof(local_buffer), 0);
				if (buflen <= 0) {
#ifdef DEBUG_SERVER
					fprintf(stderr, "%sserver: error while receiving data%s\n",
							error_color_string, reset_color_string);
#endif
					fclose(file);
					return ERROR_IO;
				}

				if (buflen >= 4) {
					if ((local_buffer[buflen - 4] == 'E') && (local_buffer[buflen - 3] == 'N') &&
							(local_buffer[buflen - 2] == 'D') && (local_buffer[buflen - 1] == '.')) {
						fwrite(local_buffer, (buflen - 4), 1, file);
						fflush(file);
						rewind(file);
						yyin = file;

						if (yyparse() == 0) {
							if (pdir_traco_corrige_ultimo_id(atoi(ptsl_id)) == SUCCESS) {
								fclose(file);
								return SUCCESS;
							}
#ifdef DEBUG_SERVER
							fprintf(stderr, "%sserver: failed to fix ptsl_id:%d%s\n",
									error_color_string, atoi(ptsl_id), reset_color_string);
#endif
						}
#ifdef DEBUG_SERVER
						else {
							fprintf(stderr, "%sserver: parser error%s\n",
									error_color_string, reset_color_string);
						}
#endif

						fclose(file);
						return TRACE_PARSERERROR;
					}
				}

				fwrite(local_buffer, buflen, 1, file);
			}
			break;

		case CMD_RUN:
			if (pdir_traco_run(atoi(ptsl_id)) != SUCCESS) {
#ifdef DEBUG_SERVER
				fprintf(stderr, "server: failed to run ptsl_id:%d\n", atoi(ptsl_id));
#endif
				return ERROR_PARAMETER;
			}
#ifdef DEBUG_SERVER
			else {
				fprintf(stderr, "server: run ptsl_id:%d OK\n", atoi(ptsl_id));
			}
#endif
			return SUCCESS;
			break;

		case CMD_PAUSE:
			fprintf(stderr, "server: PAUSE not implemented yet :(\n");
			return ERROR_NEEDCODING;
			break;

		case CMD_STOP:
			fprintf(stderr, "server: STOP not implemented yet :(\n");
			return ERROR_NEEDCODING;
			break;

		case CMD_REMOVE:
			fprintf(stderr, "server: REMOVE not implemented yet :(\n");
			return ERROR_NEEDCODING;
			break;

		default:
#ifdef DEBUG_SERVER
			fprintf(stderr, "%sserver: bad command `%s'%s\n", error_color_string,
					command, reset_color_string);
#endif
			return ERROR_PARAMETER;
	}

	return SUCCESS;
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
server_resolve_command(char *command_string)
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

	return ERROR_PARAMETER;
}

