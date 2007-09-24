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

/** \file rmon2.c
 *  \brief Main RMON2 initializer -- dispatches all sub modules initialization
 *  functions.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "rmon2.h"

#include "sysuptime.h"
#include "protocolDir_scalar.h"
#include "protocolDir.h"
#include "protocolDist.h"
#include "nlHost.h"
#include "alHost.h"
#include "nlMatrix.h"
#include "alMatrix.h"
#include "exit_codes.h"

/**
 *  \brief RMON2 main initialization dispatcher
 *
 *  This function manages the initialization of the RMON2 agent,
 *  calling other init functions.  After Net-SNMP starts, it will
 *  call this function.
 *  \see init_protocolDir_scalar, init_protocolDir
 *  \attention Some of the functions called call another initialization
 *  functions.
 */
void init_rmon2()
{
    /*
     *	here we call initialization functions
     */
    if (init_sysuptime() != SUCCESS) {
	snmp_log(LOG_ERR, "rmon2: error while initializing time accounting\n");
	return;
    }

    init_protocolDir_scalar();
    init_protocolDir();
    init_protocolDist();
    init_nlHost();
    init_alHost();
    init_nlMatrix();
    init_alMatrix();

    snmp_log(LOG_INFO, "rmon2: initialized.\n");
}

