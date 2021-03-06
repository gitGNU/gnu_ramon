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
#include "probeConfig.h"
#include "exit_codes.h"

/** Initialize the trapDestTable table by defining its contents and how it's structured */
void
initialize_table_trapDestTable(void)
{
    static oid      trapDestTable_oid[] = { 1, 3, 6, 1, 2, 1, 16, 19, 13 };
    netsnmp_table_registration_info *table_info;
    netsnmp_handler_registration *my_handler;
    netsnmp_iterator_info *iinfo;

    /*
     * create the table structure itself
     */
    table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);

    /*
     * if your table is read only, it's easiest to change the
     * HANDLER_CAN_RWRITE definition below to HANDLER_CAN_RONLY
     */
    my_handler = netsnmp_create_handler_registration("trapDestTable",
                                                     trapDestTable_handler,
                                                     trapDestTable_oid,
                                                     OID_LENGTH
                                                     (trapDestTable_oid),
                                                     HANDLER_CAN_RWRITE);

    if (!my_handler || !table_info || !iinfo)
        return;                 /* mallocs failed */

    /***************************************************
     * Setting up the table's definition
     */
    netsnmp_table_helper_add_indexes(table_info, ASN_INTEGER,   /* index: trapDestIndex */
                                     0);

    table_info->min_column = 2;
    table_info->max_column = 6;

    /*
     * iterator access routines
     */
    iinfo->get_first_data_point = trapDestTable_get_first_data_point;
    iinfo->get_next_data_point = trapDestTable_get_next_data_point;

    iinfo->table_reginfo = table_info;

    /***************************************************
     * registering the table with the master agent
     */
    DEBUGMSGTL(("initialize_table_trapDestTable",
                "Registering table trapDestTable as a table iterator\n"));
    netsnmp_register_table_iterator(my_handler, iinfo);
}

/** Initialize the serialConnectionTable table by defining its contents and how it's structured */
void
initialize_table_serialConnectionTable(void)
{
    static oid      serialConnectionTable_oid[] =
        { 1, 3, 6, 1, 2, 1, 16, 19, 14 };
    netsnmp_table_registration_info *table_info;
    netsnmp_handler_registration *my_handler;
    netsnmp_iterator_info *iinfo;

    /*
     * create the table structure itself
     */
    table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);

    /*
     * if your table is read only, it's easiest to change the
     * HANDLER_CAN_RWRITE definition below to HANDLER_CAN_RONLY
     */
    my_handler =
        netsnmp_create_handler_registration("serialConnectionTable",
                                            serialConnectionTable_handler,
                                            serialConnectionTable_oid,
                                            OID_LENGTH
                                            (serialConnectionTable_oid),
                                            HANDLER_CAN_RWRITE);

    if (!my_handler || !table_info || !iinfo)
        return;                 /* mallocs failed */

    /***************************************************
     * Setting up the table's definition
     */
    netsnmp_table_helper_add_indexes(table_info, ASN_INTEGER,   /* index: serialConnectIndex */
                                     0);

    table_info->min_column = 2;
    table_info->max_column = 9;

    /*
     * iterator access routines
     */
    iinfo->get_first_data_point =
        serialConnectionTable_get_first_data_point;
    iinfo->get_next_data_point = serialConnectionTable_get_next_data_point;

    iinfo->table_reginfo = table_info;

    /***************************************************
     * registering the table with the master agent
     */
    DEBUGMSGTL(("initialize_table_serialConnectionTable",
                "Registering table serialConnectionTable as a table iterator\n"));
    netsnmp_register_table_iterator(my_handler, iinfo);
}

/** Initialize the serialConfigTable table by defining its contents and how it's structured */
void
initialize_table_serialConfigTable(void)
{
    static oid      serialConfigTable_oid[] =
        { 1, 3, 6, 1, 2, 1, 16, 19, 10 };
    netsnmp_table_registration_info *table_info;
    netsnmp_handler_registration *my_handler;
    netsnmp_iterator_info *iinfo;

    /*
     * create the table structure itself
     */
    table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);

    /*
     * if your table is read only, it's easiest to change the
     * HANDLER_CAN_RWRITE definition below to HANDLER_CAN_RONLY
     */
    my_handler = netsnmp_create_handler_registration("serialConfigTable",
                                                     serialConfigTable_handler,
                                                     serialConfigTable_oid,
                                                     OID_LENGTH
                                                     (serialConfigTable_oid),
                                                     HANDLER_CAN_RWRITE);

    if (!my_handler || !table_info || !iinfo)
        return;                 /* mallocs failed */

    /***************************************************
     * Setting up the table's definition
     */
    netsnmp_table_helper_add_indexes(table_info, ASN_INTEGER,   /* index: ifIndex */
                                     0);

    table_info->min_column = 1;
    table_info->max_column = 9;

    /*
     * iterator access routines
     */
    iinfo->get_first_data_point = serialConfigTable_get_first_data_point;
    iinfo->get_next_data_point = serialConfigTable_get_next_data_point;

    iinfo->table_reginfo = table_info;

    /***************************************************
     * registering the table with the master agent
     */
    DEBUGMSGTL(("initialize_table_serialConfigTable",
                "Registering table serialConfigTable as a table iterator\n"));
    netsnmp_register_table_iterator(my_handler, iinfo);
}

/** Initialize the netConfigTable table by defining its contents and how it's structured */
void
initialize_table_netConfigTable(void)
{
    static oid      netConfigTable_oid[] =
        { 1, 3, 6, 1, 2, 1, 16, 19, 11 };
    netsnmp_table_registration_info *table_info;
    netsnmp_handler_registration *my_handler;
    netsnmp_iterator_info *iinfo;

    /*
     * create the table structure itself
     */
    table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);

    /*
     * if your table is read only, it's easiest to change the
     * HANDLER_CAN_RWRITE definition below to HANDLER_CAN_RONLY
     */
    my_handler = netsnmp_create_handler_registration("netConfigTable",
                                                     netConfigTable_handler,
                                                     netConfigTable_oid,
                                                     OID_LENGTH
                                                     (netConfigTable_oid),
                                                     HANDLER_CAN_RWRITE);

    if (!my_handler || !table_info || !iinfo)
        return;                 /* mallocs failed */

    /***************************************************
     * Setting up the table's definition
     */
    netsnmp_table_helper_add_indexes(table_info, ASN_INTEGER,   /* index: ifIndex */
                                     0);

    table_info->min_column = 1;
    table_info->max_column = 3;

    /*
     * iterator access routines
     */
    iinfo->get_first_data_point = netConfigTable_get_first_data_point;
    iinfo->get_next_data_point = netConfigTable_get_next_data_point;

    iinfo->table_reginfo = table_info;

    /***************************************************
     * registering the table with the master agent
     */
    DEBUGMSGTL(("initialize_table_netConfigTable",
                "Registering table netConfigTable as a table iterator\n"));
    netsnmp_register_table_iterator(my_handler, iinfo);
}

/** Initializes the probeConfig module */
void
init_probeConfig(void)
{

    /*
     * here we initialize all the tables we're planning on supporting
     */
    initialize_table_trapDestTable();
    initialize_table_serialConnectionTable();
    initialize_table_serialConfigTable();
    initialize_table_netConfigTable();
}

/** returns the first data point within the trapDestTable table data.

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
trapDestTable_get_first_data_point(void **my_loop_context,
                                   void **my_data_context,
                                   netsnmp_variable_list * put_index_data,
                                   netsnmp_iterator_info *mydata)
{

    netsnmp_variable_list *vptr;

    *my_loop_context = /* XXX */ ;
    *my_data_context = /* XXX */ ;

    vptr = put_index_data;

    snmp_set_var_value(vptr, (u_char *) /* XXX: trapDestIndex data */ ,
                       /* XXX: length of trapDestIndex data */ );
    vptr = vptr->next_variable;

    return put_index_data;
}

/** functionally the same as trapDestTable_get_first_data_point, but
   my_loop_context has already been set to a previous value and should
   be updated to the next in the list.  For example, if it was a
   linked list, you might want to cast it and the return
   my_loop_context->next.  The my_data_context pointer should be set
   to something you need later and the indexes in put_index_data
   updated again. */

netsnmp_variable_list *
trapDestTable_get_next_data_point(void **my_loop_context,
                                  void **my_data_context,
                                  netsnmp_variable_list * put_index_data,
                                  netsnmp_iterator_info *mydata)
{

    netsnmp_variable_list *vptr;

    *my_loop_context = /* XXX */ ;
    *my_data_context = /* XXX */ ;

    vptr = put_index_data;

    snmp_set_var_value(vptr, (u_char *) /* XXX: trapDestIndex data */ ,
                       /* XXX: length of trapDestIndex data */ );
    vptr = vptr->next_variable;

    return put_index_data;
}

/** handles requests for the trapDestTable table, if anything else needs to be done */
int
trapDestTable_handler(netsnmp_mib_handler *handler,
                      netsnmp_handler_registration *reginfo,
                      netsnmp_agent_request_info *reqinfo,
                      netsnmp_request_info *requests)
{

    netsnmp_request_info *request;
    netsnmp_table_request_info *table_info;
    netsnmp_variable_list *var;

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
         * help return data for the columns of the trapDestTable table in question
         */
        /*
         * XXX
         */  = ( /* XXX */ *)netsnmp_extract_iterator_context(request);
        if ( /* XXX */  == NULL) {
            if (reqinfo->mode == MODE_GET) {
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHINSTANCE);
                continue;
            }
            /*
             * XXX: no row existed, if you support creation and this is a
             * set, start dealing with it here, else continue
             */
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
            case COLUMN_TRAPDESTCOMMUNITY:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_TRAPDESTPROTOCOL:
                snmp_set_var_typed_value(var, ASN_INTEGER,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_TRAPDESTADDRESS:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_TRAPDESTOWNER:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_TRAPDESTSTATUS:
                snmp_set_var_typed_value(var, ASN_INTEGER,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            default:
                /*
                 * We shouldn't get here
                 */
                snmp_log(LOG_ERR,
                         "problem encountered in trapDestTable_handler: unknown column\n");
            }
            break;

        case MODE_SET_RESERVE1:
            /*
             * set handling...
             */

        default:
            snmp_log(LOG_ERR,
                     "problem encountered in trapDestTable_handler: unsupported mode\n");
        }
    }
    return SNMP_ERR_NOERROR;
}

/** returns the first data point within the serialConnectionTable table data.

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
serialConnectionTable_get_first_data_point(void **my_loop_context,
                                           void **my_data_context,
                                           netsnmp_variable_list *
                                           put_index_data,
                                           netsnmp_iterator_info *mydata)
{

    netsnmp_variable_list *vptr;

    *my_loop_context = /* XXX */ ;
    *my_data_context = /* XXX */ ;

    vptr = put_index_data;

    snmp_set_var_value(vptr,
                       (u_char *) /* XXX: serialConnectIndex data */ ,
                       /* XXX: length of serialConnectIndex data */ );
    vptr = vptr->next_variable;

    return put_index_data;
}

/** functionally the same as serialConnectionTable_get_first_data_point, but
   my_loop_context has already been set to a previous value and should
   be updated to the next in the list.  For example, if it was a
   linked list, you might want to cast it and the return
   my_loop_context->next.  The my_data_context pointer should be set
   to something you need later and the indexes in put_index_data
   updated again. */

netsnmp_variable_list *
serialConnectionTable_get_next_data_point(void **my_loop_context,
                                          void **my_data_context,
                                          netsnmp_variable_list *
                                          put_index_data,
                                          netsnmp_iterator_info *mydata)
{

    netsnmp_variable_list *vptr;

    *my_loop_context = /* XXX */ ;
    *my_data_context = /* XXX */ ;

    vptr = put_index_data;

    snmp_set_var_value(vptr,
                       (u_char *) /* XXX: serialConnectIndex data */ ,
                       /* XXX: length of serialConnectIndex data */ );
    vptr = vptr->next_variable;

    return put_index_data;
}

/** handles requests for the serialConnectionTable table, if anything else needs to be done */
int
serialConnectionTable_handler(netsnmp_mib_handler *handler,
                              netsnmp_handler_registration *reginfo,
                              netsnmp_agent_request_info *reqinfo,
                              netsnmp_request_info *requests)
{

    netsnmp_request_info *request;
    netsnmp_table_request_info *table_info;
    netsnmp_variable_list *var;

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
         * help return data for the columns of the serialConnectionTable table in question
         */
        /*
         * XXX
         */  = ( /* XXX */ *)netsnmp_extract_iterator_context(request);
        if ( /* XXX */  == NULL) {
            if (reqinfo->mode == MODE_GET) {
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHINSTANCE);
                continue;
            }
            /*
             * XXX: no row existed, if you support creation and this is a
             * set, start dealing with it here, else continue
             */
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
            case COLUMN_SERIALCONNECTDESTIPADDRESS:
                snmp_set_var_typed_value(var, ASN_IPADDRESS,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALCONNECTTYPE:
                snmp_set_var_typed_value(var, ASN_INTEGER,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALCONNECTDIALSTRING:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALCONNECTSWITCHCONNECTSEQ:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALCONNECTSWITCHDISCONNECTSEQ:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALCONNECTSWITCHRESETSEQ:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALCONNECTOWNER:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALCONNECTSTATUS:
                snmp_set_var_typed_value(var, ASN_INTEGER,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            default:
                /*
                 * We shouldn't get here
                 */
                snmp_log(LOG_ERR,
                         "problem encountered in serialConnectionTable_handler: unknown column\n");
            }
            break;

        case MODE_SET_RESERVE1:
            /*
             * set handling...
             */

        default:
            snmp_log(LOG_ERR,
                     "problem encountered in serialConnectionTable_handler: unsupported mode\n");
        }
    }
    return SNMP_ERR_NOERROR;
}

/** returns the first data point within the serialConfigTable table data.

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
serialConfigTable_get_first_data_point(void **my_loop_context,
                                       void **my_data_context,
                                       netsnmp_variable_list *
                                       put_index_data,
                                       netsnmp_iterator_info *mydata)
{

    netsnmp_variable_list *vptr;

    *my_loop_context = /* XXX */ ;
    *my_data_context = /* XXX */ ;

    vptr = put_index_data;

    snmp_set_var_value(vptr, (u_char *) /* XXX: ifIndex data */ ,
                       /* XXX: length of ifIndex data */ );
    vptr = vptr->next_variable;

    return put_index_data;
}

/** functionally the same as serialConfigTable_get_first_data_point, but
   my_loop_context has already been set to a previous value and should
   be updated to the next in the list.  For example, if it was a
   linked list, you might want to cast it and the return
   my_loop_context->next.  The my_data_context pointer should be set
   to something you need later and the indexes in put_index_data
   updated again. */

netsnmp_variable_list *
serialConfigTable_get_next_data_point(void **my_loop_context,
                                      void **my_data_context,
                                      netsnmp_variable_list *
                                      put_index_data,
                                      netsnmp_iterator_info *mydata)
{

    netsnmp_variable_list *vptr;

    *my_loop_context = /* XXX */ ;
    *my_data_context = /* XXX */ ;

    vptr = put_index_data;

    snmp_set_var_value(vptr, (u_char *) /* XXX: ifIndex data */ ,
                       /* XXX: length of ifIndex data */ );
    vptr = vptr->next_variable;

    return put_index_data;
}

/** handles requests for the serialConfigTable table, if anything else needs to be done */
int
serialConfigTable_handler(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info *reqinfo,
                          netsnmp_request_info *requests)
{

    netsnmp_request_info *request;
    netsnmp_table_request_info *table_info;
    netsnmp_variable_list *var;

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
         * help return data for the columns of the serialConfigTable table in question
         */
        /*
         * XXX
         */  = ( /* XXX */ *)netsnmp_extract_iterator_context(request);
        if ( /* XXX */  == NULL) {
            if (reqinfo->mode == MODE_GET) {
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHINSTANCE);
                continue;
            }
            /*
             * XXX: no row existed, if you support creation and this is a
             * set, start dealing with it here, else continue
             */
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
            case COLUMN_SERIALMODE:
                snmp_set_var_typed_value(var, ASN_INTEGER,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALPROTOCOL:
                snmp_set_var_typed_value(var, ASN_INTEGER,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALTIMEOUT:
                snmp_set_var_typed_value(var, ASN_INTEGER,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALMODEMINITSTRING:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALMODEMHANGUPSTRING:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALMODEMCONNECTRESP:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALMODEMNOCONNECTRESP:
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALDIALOUTTIMEOUT:
                snmp_set_var_typed_value(var, ASN_INTEGER,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_SERIALSTATUS:
                snmp_set_var_typed_value(var, ASN_INTEGER,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            default:
                /*
                 * We shouldn't get here
                 */
                snmp_log(LOG_ERR,
                         "problem encountered in serialConfigTable_handler: unknown column\n");
            }
            break;

        case MODE_SET_RESERVE1:
            /*
             * set handling...
             */

        default:
            snmp_log(LOG_ERR,
                     "problem encountered in serialConfigTable_handler: unsupported mode\n");
        }
    }
    return SNMP_ERR_NOERROR;
}

/** returns the first data point within the netConfigTable table data.

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
netConfigTable_get_first_data_point(void **my_loop_context,
                                    void **my_data_context,
                                    netsnmp_variable_list * put_index_data,
                                    netsnmp_iterator_info *mydata)
{

    netsnmp_variable_list *vptr;

    *my_loop_context = /* XXX */ ;
    *my_data_context = /* XXX */ ;

    vptr = put_index_data;

    snmp_set_var_value(vptr, (u_char *) /* XXX: ifIndex data */ ,
                       /* XXX: length of ifIndex data */ );
    vptr = vptr->next_variable;

    return put_index_data;
}

/** functionally the same as netConfigTable_get_first_data_point, but
   my_loop_context has already been set to a previous value and should
   be updated to the next in the list.  For example, if it was a
   linked list, you might want to cast it and the return
   my_loop_context->next.  The my_data_context pointer should be set
   to something you need later and the indexes in put_index_data
   updated again. */

netsnmp_variable_list *
netConfigTable_get_next_data_point(void **my_loop_context,
                                   void **my_data_context,
                                   netsnmp_variable_list * put_index_data,
                                   netsnmp_iterator_info *mydata)
{

    netsnmp_variable_list *vptr;

    *my_loop_context = /* XXX */ ;
    *my_data_context = /* XXX */ ;

    vptr = put_index_data;

    snmp_set_var_value(vptr, (u_char *) /* XXX: ifIndex data */ ,
                       /* XXX: length of ifIndex data */ );
    vptr = vptr->next_variable;

    return put_index_data;
}

/** handles requests for the netConfigTable table, if anything else needs to be done */
int
netConfigTable_handler(netsnmp_mib_handler *handler,
                       netsnmp_handler_registration *reginfo,
                       netsnmp_agent_request_info *reqinfo,
                       netsnmp_request_info *requests)
{

    netsnmp_request_info *request;
    netsnmp_table_request_info *table_info;
    netsnmp_variable_list *var;

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
         * help return data for the columns of the netConfigTable table in question
         */
        /*
         * XXX
         */  = ( /* XXX */ *)netsnmp_extract_iterator_context(request);
        if ( /* XXX */  == NULL) {
            if (reqinfo->mode == MODE_GET) {
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHINSTANCE);
                continue;
            }
            /*
             * XXX: no row existed, if you support creation and this is a
             * set, start dealing with it here, else continue
             */
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
            case COLUMN_NETCONFIGIPADDRESS:
                snmp_set_var_typed_value(var, ASN_IPADDRESS,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_NETCONFIGSUBNETMASK:
                snmp_set_var_typed_value(var, ASN_IPADDRESS,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            case COLUMN_NETCONFIGSTATUS:
                snmp_set_var_typed_value(var, ASN_INTEGER,
                                         (u_char *) /* XXX: column data */
                                         , /* XXX: column data length */ );
                break;

            default:
                /*
                 * We shouldn't get here
                 */
                snmp_log(LOG_ERR,
                         "problem encountered in netConfigTable_handler: unknown column\n");
            }
            break;

        case MODE_SET_RESERVE1:
            /*
             * set handling...
             */

        default:
            snmp_log(LOG_ERR,
                     "problem encountered in netConfigTable_handler: unsupported mode\n");
        }
    }
    return SNMP_ERR_NOERROR;
}
