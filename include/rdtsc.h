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

/*
 * Function:
 * RDTSC reads a Pentium internal 64 bit register which is being incremented
 * from 0000 0000 0000 0000 at every CPU internal clockcycle. Note that this
 * gives a clockcycle-accurate timer with a range of more than 8800 years at
 * 66 Mhz...
 * The instruction places the counter in the EDX:EAX register pair.
 *
 * http://tamerlan.it.nsc.ru/~michael/x86/86bugs/bugs048.htm
 */

/*
 *  Thanks Felipe W. Damasio for this macro
 */
#define rdtsc(ticks) \
	__asm__ volatile (".byte 0x0f, 0x31" : "=A" (ticks));

