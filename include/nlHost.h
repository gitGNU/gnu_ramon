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
#ifndef NLHOST_H
#define NLHOST_H

/*
 * function declarations
 */
void init_nlHost(void);
void initialize_table_hlHostControlTable(void);
Netsnmp_Node_Handler hlHostControlTable_handler;

Netsnmp_First_Data_Point hlHostControlTable_get_first_data_point;
Netsnmp_Next_Data_Point hlHostControlTable_get_next_data_point;
void initialize_table_nlHostTable(void);
Netsnmp_Node_Handler nlHostTable_handler;

Netsnmp_First_Data_Point nlHostTable_get_first_data_point;
Netsnmp_Next_Data_Point nlHostTable_get_next_data_point;

/*
 * column number definitions for table hlHostControlTable
 */
#define COLUMN_HLHOSTCONTROLINDEX		1
#define COLUMN_HLHOSTCONTROLDATASOURCE		2
#define COLUMN_HLHOSTCONTROLNLDROPPEDFRAMES	3
#define COLUMN_HLHOSTCONTROLNLINSERTS		4
#define COLUMN_HLHOSTCONTROLNLDELETES		5
#define COLUMN_HLHOSTCONTROLNLMAXDESIREDENTRIES	6
#define COLUMN_HLHOSTCONTROLALDROPPEDFRAMES	7
#define COLUMN_HLHOSTCONTROLALINSERTS		8
#define COLUMN_HLHOSTCONTROLALDELETES		9
#define COLUMN_HLHOSTCONTROLALMAXDESIREDENTRIES	10
#define COLUMN_HLHOSTCONTROLOWNER		11
#define COLUMN_HLHOSTCONTROLSTATUS		12

/*
 * column number definitions for table nlHostTable
 */
#define COLUMN_NLHOSTTIMEMARK			1
#define COLUMN_NLHOSTADDRESS			2
#define COLUMN_NLHOSTINPKTS			3
#define COLUMN_NLHOSTOUTPKTS			4
#define COLUMN_NLHOSTINOCTETS			5
#define COLUMN_NLHOSTOUTOCTETS			6
#define COLUMN_NLHOSTOUTMACNONUNICASTPKTS	7
#define COLUMN_NLHOSTCREATETIME			8
#endif                          /* NLHOST_H */
