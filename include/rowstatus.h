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

#ifndef __ROWSTATUS_H
#define __ROWSTATUS_H

#define ROWSTATUS_INVALID	    0	/* this is NOT standardized */

#define ROWSTATUS_ACTIVE	    1
#define ROWSTATUS_NOT_IN_SERVICE    2
#define ROWSTATUS_NOT_READY	    3
#define ROWSTATUS_CREATE_AND_GO	    4
#define ROWSTATUS_CREATE_AND_WAIT   5
#define ROWSTATUS_DESTROY	    6

#endif /* __ROWSTATUS_H */
