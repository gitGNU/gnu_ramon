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

#ifndef __AL_H
#define __AL_H

/*
 *  hlHostControlIndex, alHostTimeMark, protocolDirLocalIndex, nlHostAddress,
 *  protocolDirLocalIndex
 *
 *  hlhost.timemark.nlhost->localindex.nlhost->address.localindex
 */

typedef struct AlHost_st {
    /* 2 itens para verificacao na hash */
    in_addr_t	    nlhost_address;
    uint32_t	    portas;	    // porta origem << 16 | porta destino

    unsigned int    localindex_app;
    unsigned int    localindex_net;
    unsigned int    hlhost_index;

    /* pacotes/bytes recebidos e enviados */
    uint32_t	    in_pkts;
    uint32_t	    in_octets;
    uint32_t	    out_pkts;
    uint32_t	    out_octets;

    unsigned long   timemark;
    unsigned long   create_time;
} alhost_t;


/*
 * AlMatrix SD
 *  hlMatrixControlIndex, alMatrixSDTimeMark, protocolDirLocalIndex,
 *  nlMatrixSDSourceAddress, nlMatrixSDDestAddress, protocolDirLocalIndex
 *
 * AlMatrix DS
 *  hlMatrixControlIndex, alMatrixDSTimeMark, protocolDirLocalIndex,
 *  nlMatrixDSDestAddress, nlMatrixDSSourceAddress, protocolDirLocalIndex
 */
typedef struct AlMatrix_st {
    uint32_t	    portas;
    in_addr_t	    source_addr;
    in_addr_t	    destin_addr;

    unsigned int    localindex_net;
    unsigned int    localindex_app;
    unsigned int    interface;

    uint32_t	    pkts;
    uint32_t	    octets;

    unsigned long   timemark;
    unsigned long   create_time;
} almatrix_t;

#endif /* __AL_H */

