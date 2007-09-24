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

#ifndef __NLMATRIX_SD_H
#define __NLMATRIX_SD_H

#include "nl.h"

unsigned int nlmatrix_SD_quantidade();
int nlmatrix_SD_insereAtualiza(pedb_t *dados);
void nlmatrix_SD_hashStats();

int nlmatrix_sd_helper(const unsigned int indice, uint32_t tripa[]);

int nlmatrix_sd_tabela_prepara(unsigned int *ptr);
int nlmatrix_sd_tabela_proximo(unsigned int *ptr);
int nlmatrix_sd_testa(const unsigned int indice);

int nlmatrix_sd_busca_pkts(const unsigned int indice, uint32_t *ptr);
int nlmatrix_sd_busca_octets(const unsigned int indice, uint32_t *ptr);
int nlmatrix_sd_busca_createtime(const unsigned int indice, uint32_t *ptr);

#endif /* __NLMATRIX_SD_H */
