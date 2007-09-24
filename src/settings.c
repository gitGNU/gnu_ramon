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

#include <stdio.h>
#include <string.h>

char *
conf_get_interface() {
	/* FIXME: this is UGLY */
	FILE	*file = fopen("/etc/rmon2/rmon2.conf", "r");
	char	linha[96] = {0,};
	char	*token;

	while (fgets(linha, 96, file) != NULL) {
		token = strtok(linha, "\n\r\t ");
		if (token == NULL)
			continue;
		if (strcmp(token, "interface") != 0)
			continue;

		token = strtok(NULL, "\n\r\t ");
		token = strtok(NULL, "\n\r\t ");

		fclose(file);
		return strdup(token);
	}

	return NULL;
}

