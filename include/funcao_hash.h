/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2003 Ricardo Nabinger Sanchez
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

/* requires include/primo.h */
#ifndef __PRIMO_H
#error header 'include/primo.h' must be included BEFORE us
#endif

/*
 *  this is a macro version of the hash function in use:
 *
 *	hash(c,i) = ((c % P) + i * ((c % P_menos_2) + 1) % P
 *
 *  It is 15 to 387% faster than the 'static uint32_t' implementation,
 *  and much more stable (results are computed with very low CPU use
 *  variation).  The maximum speed can be reached by enabling arch-specific
 *  optimizations, such as 'make ARCH=athlon-tbird'.  It also is somewhat
 *  optimized for pipelining.
 */
#define HASH(chave,i,resultado) \
	{ \
		register uint32_t desl; \
		register uint32_t base; \
		desl = (chave % Pmenos2); \
		base = (chave % PRIMO); \
		desl++; \
		base += i; \
		desl *= base; \
		resultado = desl % PRIMO; \
	}

