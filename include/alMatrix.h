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
 * : mib2c.iterate.conf,v 5.5 2002/12/16 22:50:18 hardaker Exp $
 */
#ifndef ALMATRIX_H
#define ALMATRIX_H

/*
 * function declarations
 */
void init_alMatrix(void);
void initialize_table_alMatrixSDTable(void);
Netsnmp_Node_Handler alMatrixSDTable_handler;

Netsnmp_First_Data_Point alMatrixSDTable_get_first_data_point;
Netsnmp_Next_Data_Point alMatrixSDTable_get_next_data_point;
void initialize_table_alMatrixTopNControlTable(void);
Netsnmp_Node_Handler alMatrixTopNControlTable_handler;

Netsnmp_First_Data_Point alMatrixTopNControlTable_get_first_data_point;
Netsnmp_Next_Data_Point alMatrixTopNControlTable_get_next_data_point;
void initialize_table_alMatrixTopNTable(void);
Netsnmp_Node_Handler alMatrixTopNTable_handler;

Netsnmp_First_Data_Point alMatrixTopNTable_get_first_data_point;
Netsnmp_Next_Data_Point alMatrixTopNTable_get_next_data_point;
void initialize_table_alMatrixDSTable(void);
Netsnmp_Node_Handler alMatrixDSTable_handler;

Netsnmp_First_Data_Point alMatrixDSTable_get_first_data_point;
Netsnmp_Next_Data_Point alMatrixDSTable_get_next_data_point;

/*
 * column number definitions for table alMatrixSDTable
 */
#define COLUMN_ALMATRIXSDTIMEMARK	1
#define COLUMN_ALMATRIXSDPKTS		2
#define COLUMN_ALMATRIXSDOCTETS		3
#define COLUMN_ALMATRIXSDCREATETIME	4

/*
 * column number definitions for table alMatrixTopNControlTable
 */
#define COLUMN_ALMATRIXTOPNCONTROLINDEX			1
#define COLUMN_ALMATRIXTOPNCONTROLMATRIXINDEX		2
#define COLUMN_ALMATRIXTOPNCONTROLRATEBASE		3
#define COLUMN_ALMATRIXTOPNCONTROLTIMEREMAINING		4
#define COLUMN_ALMATRIXTOPNCONTROLGENERATEDREPORTS	5
#define COLUMN_ALMATRIXTOPNCONTROLDURATION		6
#define COLUMN_ALMATRIXTOPNCONTROLREQUESTEDSIZE		7
#define COLUMN_ALMATRIXTOPNCONTROLGRANTEDSIZE		8
#define COLUMN_ALMATRIXTOPNCONTROLSTARTTIME		9
#define COLUMN_ALMATRIXTOPNCONTROLOWNER			10
#define COLUMN_ALMATRIXTOPNCONTROLSTATUS		11

/*
 * column number definitions for table alMatrixTopNTable
 */
#define COLUMN_ALMATRIXTOPNINDEX			1
#define COLUMN_ALMATRIXTOPNPROTOCOLDIRLOCALINDEX	2
#define COLUMN_ALMATRIXTOPNSOURCEADDRESS		3
#define COLUMN_ALMATRIXTOPNDESTADDRESS			4
#define COLUMN_ALMATRIXTOPNAPPPROTOCOLDIRLOCALINDEX	5
#define COLUMN_ALMATRIXTOPNPKTRATE			6
#define COLUMN_ALMATRIXTOPNREVERSEPKTRATE		7
#define COLUMN_ALMATRIXTOPNOCTETRATE			8
#define COLUMN_ALMATRIXTOPNREVERSEOCTETRATE		9

/*
 * column number definitions for table alMatrixDSTable
 */
#define COLUMN_ALMATRIXDSTIMEMARK	1
#define COLUMN_ALMATRIXDSPKTS		2
#define COLUMN_ALMATRIXDSOCTETS		3
#define COLUMN_ALMATRIXDSCREATETIME	4
#endif                          /* ALMATRIX_H */
