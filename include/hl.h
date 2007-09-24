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

#ifndef __HL_H
#define __HL_H

typedef struct HlHostControlEntry_st {
	int		rowstatus;

	uint32_t	nl_droppedframes;
	uint32_t	nl_inserts;
	uint32_t	nl_deletes;
	int32_t		nl_maxentries;	//	-1..(2^31)-1

	uint32_t	al_droppedframes;
	uint32_t	al_inserts;
	uint32_t	al_deletes;
	int32_t		al_maxentries;	//	-1..(2^31)-1

	char		*owner;
} hlhost_t;


typedef	struct	HlMatrixControlEntry_st {
	int		rowstatus;

	uint32_t	nl_droppedframes;
	uint32_t	nl_inserts;
	uint32_t	nl_deletes;
	int32_t		nl_maxentries;	//	-1..(2^31)-1

	uint32_t	al_droppedframes;
	uint32_t	al_inserts;
	uint32_t	al_deletes;
	int32_t		al_maxentries;	//	-1..(2^31)-1

	char		*owner;
} hlmatrix_t;

#endif /* __HL_H */

