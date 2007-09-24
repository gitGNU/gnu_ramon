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

#ifndef __ALHOST_H
#define __ALHOST_H

#include <netinet/in.h>
#include "al.h"
#include "pedb.h"


unsigned int alhost_quantidade();
int alhost_insereAtualiza(pedb_t *dados);
int alhost_remove_pdir(const unsigned int pdir_localindex);

int alhost_helper(const unsigned int indice, uint32_t *hlcindex,
		uint32_t *al_tmark, uint32_t *plindex_nl, uint32_t *nl_address,
		uint32_t *plindex_al);

int alhost_tabela_prepara(unsigned int *ptr);
int alhost_tabela_proximo(unsigned int *ptr);
int alhost_testa(const unsigned int indice);

int alhost_busca_inpkts(const unsigned int indice, uint32_t *ptr);
int alhost_busca_outpkts(const unsigned int indice, uint32_t *ptr);
int alhost_busca_inoctets(const unsigned int indice, uint32_t *ptr);
int alhost_busca_outoctets(const unsigned int indice, uint32_t *ptr);
int alhost_busca_createtime(const unsigned int indice, uint32_t *ptr);

#endif /* __ALHOST_H */
