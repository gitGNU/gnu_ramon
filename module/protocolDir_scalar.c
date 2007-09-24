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
 * Note: this file originally auto-generated by mib2c using
 *        : mib2c.scalar.conf,v 1.5 2002/07/18 14:18:52 dts12 Exp $
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "protocolDir_scalar.h"

#include "protocoldir.h"
#include "exit_codes.h"


/** Initializes the protocolDir_scalar module */
void
init_protocolDir_scalar(void)
{
    static oid protocolDirLastChange_oid[] = { 1, 3, 6, 1, 2, 1, 16, 11, 1, 0 };

    DEBUGMSGTL(("protocolDir_scalar", "Initializing\n"));

    netsnmp_register_read_only_instance(netsnmp_create_handler_registration
                                        ("protocolDirLastChange",
                                         get_protocolDirLastChange,
                                         protocolDirLastChange_oid,
                                         OID_LENGTH(protocolDirLastChange_oid),
                                         HANDLER_CAN_RONLY));
}


int
get_protocolDirLastChange(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info *reqinfo,
                          netsnmp_request_info *requests)
{
    /*
     * We are never called for a GETNEXT if it's registered as a
     * "instance", as it's "magically" handled for us.
     */

    /*
     * a instance handler also only hands us one request at a time, so
     * we don't need to loop over a list of requests; we'll only get one.
     */
    unsigned long last;

    switch (reqinfo->mode) {
	case MODE_GET:
	    last = pdir_busca_lastchange();
	    snmp_set_var_typed_value(requests->requestvb, ASN_TIMETICKS,
				     (u_char *)&last, sizeof(last));
	    break;


	default:
	    /*
	     * we should never get here, so this is a really bad error
	     */
	    return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

