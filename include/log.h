/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2008 Ricardo Nabinger Sanchez  <rnsanchez@wait4.org>
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

#ifndef __LOG_H__
#define __LOG_H__

#define Debug(...) \
	do {									\
		fprintf(stderr, "ramon (%s:%d): ", __func__, __LINE__);		\
		fprintf(stderr, __VA_ARGS__);					\
		fprintf(stderr, "\n");						\
	} while (0)

#define Fatal(...) \
	do {									\
		fprintf(stderr, "ramon (%s:%d): ", __func__, __LINE__);		\
		fprintf(stderr, __VA_ARGS__);					\
		fprintf(stderr, "\n");						\
		abort();							\
	} while (0)

#endif	/* __LOG_H__ */
