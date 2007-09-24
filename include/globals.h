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

/* \file globals.h
 * \brief Handy include file to access global definitions which don't have
 * hard dependencies (ie, crossed data structures, ...).
 */

/*
 *  Filter types
 */
#define	FLT_RESERV	0   /** not used (yet) */
#define FLT_BITCT	1   /** BitCounter filter */
#define	FLT_FIELDCT	2   /** FieldCounter filter */
#define FLT_NOOFFSET	3   /** NoOffset filter */
#define FLT_VARBITCT	4   /** BitCounter filter with variable */
#define	FLT_VARFIELDCT	5   /** FieldCounter filter with variable */
#define FLT_VARNOOFFSET	6   /** NoOffset filter with variable */

/*
 *  Packet direction for the filters
 */
#if FROM_CLIENT || FROM_SERVER || FROM_ANY
#error "includes not fixed yet.  fix it."
#else
#define	FROM_CLIENT 1	/** packet comes from client */
#define FROM_SERVER 2	/** packet comes from server */
#define FROM_ANY    3	/** don't care about direction */
#endif


/*
 *  Filter encapsulation types
 */
#define OFF_ENLACE	0   /* link-layer filter */
#define OFF_REDE	1   /* network-layer filter */
#define OFF_TRANSPORTE	2   /* transport-layer filter */
#define	OFF_APLICACAO	3   /* application-layer filter */


/*
 *  The TCP port the PTSL server listens to
 */
#define SERVER_PORT	10321

