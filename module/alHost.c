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
 *        : mib2c.iterate.conf,v 5.5 2002/12/16 22:50:18 hardaker Exp $
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "alHost.h"

#include "alhost.h"
#include "exit_codes.h"


/** Initialize the alHostTable table by defining its contents and how it's structured */
void
initialize_table_alHostTable(void)
{
    static oid alHostTable_oid[] = { 1, 3, 6, 1, 2, 1, 16, 16, 1 };
    netsnmp_table_registration_info *table_info;
    netsnmp_handler_registration    *my_handler;
    netsnmp_iterator_info	    *iinfo;

    /*
     * create the table structure itself
     */
    table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);

    /*
     * if your table is read only, it's easiest to change the
     * HANDLER_CAN_RWRITE definition below to HANDLER_CAN_RONLY
     */
    my_handler = netsnmp_create_handler_registration("alHostTable",
                                                     alHostTable_handler,
                                                     alHostTable_oid,
                                                     OID_LENGTH(alHostTable_oid),
                                                     HANDLER_CAN_RONLY);

    if (!my_handler || !table_info || !iinfo)
        return;                 /* mallocs failed */

    /***************************************************
     * Setting up the table's definition
     */
    netsnmp_table_helper_add_indexes(table_info,
				     ASN_INTEGER,	/* index: hlHostControlIndex */
                                     ASN_TIMETICKS,     /* index: alHostTimeMark */
                                     ASN_INTEGER,       /* index: protocolDirLocalIndex */
                                     ASN_OCTET_STR,     /* index: nlHostAddress */
                                     ASN_INTEGER,       /* index: protocolDirLocalIndex */
                                     0);

    table_info->min_column = 2;
    table_info->max_column = 6;

    /*
     * iterator access routines
     */
    iinfo->get_first_data_point = alHostTable_get_first_data_point;
    iinfo->get_next_data_point = alHostTable_get_next_data_point;

    iinfo->table_reginfo = table_info;

    /***************************************************
     * registering the table with the master agent
     */
    DEBUGMSGTL(("initialize_table_alHostTable",
                "Registering table alHostTable as a table iterator\n"));
    netsnmp_register_table_iterator(my_handler, iinfo);

    snmp_log(LOG_INFO, "success: alHost initialized\n");
}


/** Initializes the alHost module */
void
init_alHost(void)
{

    /*
     * here we initialize all the tables we're planning on supporting
     */
    initialize_table_alHostTable();
}


/** returns the first data point within the alHostTable table data.

    Set the my_loop_context variable to the first data point structure
    of your choice (from which you can find the next one).  This could
    be anything from the first node in a linked list, to an integer
    pointer containing the beginning of an array variable.

    Set the my_data_context variable to something to be returned to
    you later that will provide you with the data to return in a given
    row.  This could be the same pointer as what my_loop_context is
    set to, or something different.

    The put_index_data variable contains a list of snmp variable
    bindings, one for each index in your table.  Set the values of
    each appropriately according to the data matching the first row
    and return the put_index_data variable at the end of the function.
*/
netsnmp_variable_list *
alHostTable_get_first_data_point(void **my_loop_context,
                                 void **my_data_context,
                                 netsnmp_variable_list *put_index_data,
                                 netsnmp_iterator_info *mydata)
{
    netsnmp_variable_list   *vptr;
    uint32_t		    indice;
    uint32_t		    hlindex, al_tmark, pdir_nl, nl_addr, pdir_al;

    if (alhost_tabela_prepara(&indice) != SUCCESS) {
	/* no elements */
	return NULL;
    }

    if (alhost_helper(indice, &hlindex, &al_tmark, &pdir_nl, &nl_addr, &pdir_al) != SUCCESS) {
	/* hmm, invalid element */
	return NULL;
    }

    *my_loop_context = (void *)indice;
    *my_data_context = (void *)indice;

    vptr = put_index_data;

    snmp_set_var_value(vptr, (u_char *)&hlindex, sizeof(hlindex));

    vptr = vptr->next_variable;
    snmp_set_var_value(vptr, (u_char *)&al_tmark, sizeof(al_tmark));

    vptr = vptr->next_variable;
    snmp_set_var_value(vptr, (u_char *)&pdir_nl, sizeof(pdir_nl));

    vptr = vptr->next_variable;
    snmp_set_var_value(vptr, (u_char *)&nl_addr, sizeof(nl_addr));

    vptr = vptr->next_variable;
    snmp_set_var_value(vptr, (u_char *)&pdir_al, sizeof(pdir_al));

    vptr = vptr->next_variable;

    return put_index_data;
}


/** functionally the same as alHostTable_get_first_data_point, but
   my_loop_context has already been set to a previous value and should
   be updated to the next in the list.  For example, if it was a
   linked list, you might want to cast it and the return
   my_loop_context->next.  The my_data_context pointer should be set
   to something you need later and the indexes in put_index_data
   updated again. */

netsnmp_variable_list *
alHostTable_get_next_data_point(void **my_loop_context,
                                void **my_data_context,
                                netsnmp_variable_list *put_index_data,
                                netsnmp_iterator_info *mydata)
{
    netsnmp_variable_list   *vptr;
    uint32_t		    indice;
    uint32_t		    hlindex, al_tmark, pdir_nl, nl_addr, pdir_al;

    if (alhost_tabela_proximo(&indice) != SUCCESS) {
	/* no elements */
	return NULL;
    }

    if (alhost_helper(indice, &hlindex, &al_tmark, &pdir_nl, &nl_addr, &pdir_al) != SUCCESS) {
	/* hmm, invalid element */
	return NULL;
    }

    *my_loop_context = (void *)indice;
    *my_data_context = (void *)indice;

    vptr = put_index_data;

    snmp_set_var_value(vptr, (u_char *)&hlindex, sizeof(hlindex));

    vptr = vptr->next_variable;
    snmp_set_var_value(vptr, (u_char *)&al_tmark, sizeof(al_tmark));

    vptr = vptr->next_variable;
    snmp_set_var_value(vptr, (u_char *)&pdir_nl, sizeof(pdir_nl));

    vptr = vptr->next_variable;
    snmp_set_var_value(vptr, (u_char *)&nl_addr, sizeof(nl_addr));

    vptr = vptr->next_variable;
    snmp_set_var_value(vptr, (u_char *)&pdir_al, sizeof(pdir_al));

    vptr = vptr->next_variable;

    return put_index_data;
}


/** handles requests for the alHostTable table, if anything else needs to be done */
int
alHostTable_handler(netsnmp_mib_handler *handler,
                    netsnmp_handler_registration *reginfo,
                    netsnmp_agent_request_info *reqinfo,
                    netsnmp_request_info *requests)
{

    netsnmp_request_info	*request;
    netsnmp_table_request_info	*table_info;
    netsnmp_variable_list	*var;
    uint32_t			indice;
    uint32_t			valor;

    for (request = requests; request; request = request->next) {
        var = request->requestvb;
        if (request->processed != 0)
            continue;

        /*
         * perform anything here that you need to do before each
         * request is processed.
         */

        /*
         * the following extracts the my_data_context pointer set in
         * the loop functions above.  You can then use the results to
         * help return data for the columns of the alHostTable table in question
         */
	indice = (uint32_t)netsnmp_extract_iterator_context(request);

        if (alhost_testa(indice) != SUCCESS) {
            if (reqinfo->mode == MODE_GET) {
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
                continue;
            }
            /*
             * XXX: no row existed, if you support creation and this is a
             * set, start dealing with it here, else continue
             */

	    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_NOCREATION);
	    return SNMP_ERR_NOCREATION;
        }

        /*
         * extracts the information about the table from the request
         */
        table_info = netsnmp_extract_table_info(request);
        /*
         * table_info->colnum contains the column number requested
         */
        /*
         * table_info->indexes contains a linked list of snmp variable
         * bindings for the indexes of the table.  Values in the list
         * have been set corresponding to the indexes of the
         * request
         */
        if (table_info == NULL) {
            continue;
        }

        switch (reqinfo->mode) {
            /*
             * the table_iterator helper should change all GETNEXTs
             * into GETs for you automatically, so you don't have to
             * worry about the GETNEXT case.  Only GETs and SETs need
             * to be dealt with here
             */
        case MODE_GET:
            switch (table_info->colnum) {
            case COLUMN_ALHOSTINPKTS:
		if (alhost_busca_inpkts(indice, &valor) != SUCCESS) {
		    netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
		    return SNMP_ERR_NOSUCHNAME;
		}
                snmp_set_var_typed_value(var, ASN_GAUGE, (u_char *)&valor, sizeof(valor));
                break;

            case COLUMN_ALHOSTOUTPKTS:
		if (alhost_busca_outpkts(indice, &valor) != SUCCESS) {
		    netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
		    return SNMP_ERR_NOSUCHNAME;
		}
                snmp_set_var_typed_value(var, ASN_GAUGE, (u_char *)&valor, sizeof(valor));
                break;

            case COLUMN_ALHOSTINOCTETS:
		if (alhost_busca_inoctets(indice, &valor) != SUCCESS) {
		    netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
		    return SNMP_ERR_NOSUCHNAME;
		}
                snmp_set_var_typed_value(var, ASN_GAUGE, (u_char *)&valor, sizeof(valor));
                break;

            case COLUMN_ALHOSTOUTOCTETS:
		if (alhost_busca_outoctets(indice, &valor) != SUCCESS) {
		    netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
		    return SNMP_ERR_NOSUCHNAME;
		}
                snmp_set_var_typed_value(var, ASN_GAUGE, (u_char *)&valor, sizeof(valor));
                break;

            case COLUMN_ALHOSTCREATETIME:
		if (alhost_busca_createtime(indice, &valor) != SUCCESS) {
		    netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
		    return SNMP_ERR_NOSUCHNAME;
		}
                snmp_set_var_typed_value(var, ASN_TIMETICKS, (u_char *)&valor, sizeof(valor));
                break;

            default:
                /*
                 * We shouldn't get here
                 */
                snmp_log(LOG_ERR,
                         "problem encountered in alHostTable_handler: unknown column\n");
            }
            break;

        case MODE_SET_RESERVE1:
            /*
             * set handling...
             */

        default:
            snmp_log(LOG_ERR,
                     "problem encountered in alHostTable_handler: unsupported mode\n");
        }
    }
    return SNMP_ERR_NOERROR;
}
