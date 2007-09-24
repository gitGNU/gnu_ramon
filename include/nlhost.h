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

#ifndef __NLHOST_H
#define __NLHOST_H

#include "nl.h"

typedef	struct {
	unsigned long	nlhost_timemark;
	unsigned int	hlhost_control_index;
	unsigned int	pdir_localindex;
	in_addr_t	nlhost_address;
} nlhost_helper_t;


unsigned int nlhost_quantidade();
int nlhost_insereAtualiza(pedb_t *dados);
int nlhost_remove_pdir(const uint32_t pdir_localindex);

void nlhost_hashStats();

int nlhost_helper(const uint32_t indice, uint32_t *hlcindex,
	uint32_t *nl_tmark, uint32_t *p_lindex, uint32_t *nl_address);

int nlhost_tabela_prepara(uint32_t *ptr);
int nlhost_tabela_proximo(uint32_t *ptr);
int nlhost_tabela_testa(const uint32_t indice);

int nlhost_busca_inpkts(const uint32_t indice, uint32_t *ptr);
int nlhost_busca_outpkts(const uint32_t indice, uint32_t *ptr);
int nlhost_busca_inoctets(const uint32_t indice, uint32_t *ptr);
int nlhost_busca_outoctets(const uint32_t indice, uint32_t *ptr);
int nlhost_busca_outmacnonunicast(const uint32_t indice, uint32_t *ptr);
int nlhost_busca_createtime(const uint32_t indice, uint32_t *ptr);

#endif /* __NLHOST_H */
