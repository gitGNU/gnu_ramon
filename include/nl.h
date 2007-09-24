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

/* requer <time.h>, <netinet/in.h>, <stdint.h> */

#ifndef __NL_H
#define __NL_H

#include "pedb.h"

/*
 * hlHostControlIndex, nlHostTimeMark, protocolDirLocalIndex, nlHostAddress
 */
typedef	struct	NlHostEntry_st {
	in_addr_t	address;

	unsigned int	localindex;
	unsigned int	hlhost_index;

	uint32_t	in_pkts;
	uint32_t	in_octets;
	uint32_t	out_pkts;
	uint32_t	out_octets;
	uint32_t	out_macbroadcast_pkts;

	unsigned long	timemark;
	unsigned long	create_time;
} nlhost_t;


/*
 * NlMatrix SD:
 * hlMatrixControlIndex, nlMatrixSDTimeMark, protocolDirLocalIndex,
 * nlMatrixSDSourceAddress, nlMatrixSDDestAddress
 *
 * NlMatrix DS:
 * hlMatrixControlIndex, nlMatrixDSTimeMark, protocolDirLocalIndex,
 * nlMatrixDSDestAddress, nlMatrixDSSourceAddress
 */
typedef	struct	NlMatrix_st {
	in_addr_t	source_addr;
	in_addr_t	destin_addr;

	unsigned int	localindex;
	unsigned int	hlmatrix_index;

	uint32_t	pkts;
	uint32_t	octets;

	unsigned long	timemark;
	unsigned long	create_time;
} nlmatrix_t;

#endif /* __NL_H */
