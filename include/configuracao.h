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
 * Should extra verifications be performed?
 */
#define HUNT_BUGS   1

/* protocolDir */
#define PDIR_CONF "/etc/rmon2/protocoldir.conf"	    /* arquivo hardcoded */

/* protocolDist */
#define PDIST_DEBUG 0

/* nlHost */
#define VETOR_PROFUNDIDADES_NLHOST	0
#define VETOR_PROFUNDIDADES_NLMATRIX_DS	0
#define VETOR_PROFUNDIDADES_NLMATRIX_SD	0
#define DEBUG_HLMATRIX			0
#define DEBUG_NLMATRIX_SD   		0
#define DEBUG_NLMATRIX_DS		0
#define DEBUG_HLHOST			0
#define DEBUG_NLHOST			0

/* alHost */
/* coletar dados sobre a profundidade nas tabelas hash? */
#define VETOR_PROFUNDIDADES_ALHOST	0
#define DEBUG_ALHOST			0
#define DEBUG_ALMATRIX_DS		0
#define DEBUG_ALMATRIX_SD		0


/* conversor */
/* exibir informacoes de processamento do pacote? */
#define DEBUGMSG_PROC_PACOTE		0
/* exibir informacoes curtas sobre o pacote? */
#define DEBUGMSG_INFO_PACOTE		0
#define FILA_DEBUG			0

/* fazer verificações em busca de erros? */
#define PLEASE_CHECK_FOR_ERRORS		1

#define MEDIR_DESEMPENHO		0

