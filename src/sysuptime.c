/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2003, 2005 Ricardo Nabinger Sanchez
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

/** \file sysuptime.c
 *  \brief Initialization and retrieval of system uptime timestamps
 *
 *  This module contains functions to initialize (synchronize) the system
 *  uptime counter and also to retrieve uptime timestamps, both in
 *  centiseconds (as required by the RMON2-MIB) and milliseconds (needed by
 *  ID-Trace)
 */

#include <stdio.h>
#include <stdint.h>

#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#endif

#include "rdtsc.h"
#include "sysuptime.h"
#include "configuracao.h"
#include "exit_codes.h"


/** \brief Persistent variable used only to obtain processor ticks. */
static uint64_t		to_store_rdtsc;

/** \brief Persistent variable which stores the processor ticks synchronized to
 *  system uptime (as read from \c /proc/uptime), in reciprocal form (multiply
 *  is faster than divide).
 */
static float		base_cputicks_inverse;
/** \brief Persistent variable which holds current processor ticks in floating
 *  point format.
 */
static float		last_cputicks;		/* avoid dynamic memory allocation */

/** \brief Uptime read from \c /proc/uptime */
static float		base_uptime;
/** \brief Persistent variable used to calculate system uptime and then return.
 *
 *  Used to calculate system uptime from processor ticks, using a simple formula:
 *  \f[ lastcputicks * basecputicksinverse \f]
 *  Which is a simplified (and faster) than this equivalent formula:
 *  \f[ lastcputicks * \frac{1}{basecputicks} \f]
 */
static float		last_uptime;

/** \brief Initializes the uptime counter.
 *
 *  Synchronizes the uptime counter with the systems', reading the
 *  proc node `/proc/uptime' in GNU/Linux environments, or asking
 *  the kernel for the uptime in FreeBSD environments.
 *
 *  \retval SUCCESS if everything went well
 *  \retval ERROR_IO if there was any error which inhibited the uptime
 *		initialization
 */
int
init_sysuptime()
{
	uint64_t    base_cputicks_64;
	float	    raw_uptime;

#ifdef __linux__
	FILE	    *f_ptr = fopen("/proc/uptime", "r");
	if ((f_ptr == NULL) || (fscanf(f_ptr, "%f", &raw_uptime) != 1)) {
		return ERROR_IO;
	}
	fclose(f_ptr);
#endif
#ifdef __FreeBSD__
	int mib[2] = {CTL_KERN, KERN_BOOTTIME};
	int len = sizeof(struct timeval);
	struct timeval uptime = {.tv_sec = 0, .tv_usec = 0};
	struct timeval now = {.tv_sec = 0, .tv_usec = 0};
	if (sysctl(mib, 2, &uptime, &len, NULL, 0) == -1) {
		return ERROR_IO;
	}
	gettimeofday(&now, NULL);
	raw_uptime = ((float)(now.tv_sec) + (float)(now.tv_usec / 1000000.0)) -
		((float)(uptime.tv_sec) + (float)(uptime.tv_usec / 1000000.0));
#endif

	/* evitar distanciamento entre uptime e cpu_ticks */
	rdtsc(base_cputicks_64);

	/* to avoid a further SIGFPE, and be faster */
	base_cputicks_inverse = base_cputicks_64;
	base_cputicks_inverse = 1.0 / base_cputicks_inverse;

	/* adjust integer uptime */
	base_uptime = raw_uptime * 100;

	return SUCCESS;
}


/** \brief Returns system uptime in centiseconds.
 *
 *  Calculates and returns system uptime in centiseconds.
 *  \return Centiseconds since system boot-up.
 */
unsigned long
sysuptime()
{
	rdtsc(to_store_rdtsc);
	last_cputicks = (float)to_store_rdtsc;
	last_uptime = base_uptime * last_cputicks * base_cputicks_inverse;

	return last_uptime;
}


/** \brief Returns system uptime in miliseconds.
 *
 *  Calculates and returns system uptime in milliseconds.
 *  \return Milliseconds since system boot-up.
 */
unsigned long
sysuptime_mili()
{
	rdtsc(to_store_rdtsc);
	last_cputicks = (float)to_store_rdtsc;
	last_uptime = 10 * base_uptime * last_cputicks * base_cputicks_inverse;

	return last_uptime;
}

