/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2008  Ricardo Nabinger Sanchez
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
 *
 * $Id$
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"

void
debug(const char *file, const int line, const char *str, ...)
{
	char	buffer[1024];
	va_list	varargs;

	snprintf(buffer, sizeof(buffer), "[%s:%d]  %s\n", file, line, str);
	va_start(varargs, str);
	vfprintf(stderr, buffer, varargs);
	va_end(varargs);
}


void
error(const char *file, const int line, const char *str, ...)
{
	char	buffer[1024];
	va_list	varargs;

	snprintf(buffer, sizeof(buffer), "[%s:%d]  error: %s\n", file, line, str);
	va_start(varargs, str);
	vfprintf(stderr, buffer, varargs);
	va_end(varargs);

	exit(EXIT_FAILURE);
}


void
fatal(const char *file, const int line, const char *str, ...)
{
	va_list varargs;

	va_start(varargs, str);
	debug(file, line, str, varargs);
	va_end(varargs);

	abort();
}
