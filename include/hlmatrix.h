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

#ifndef __HLMATRIX_H
#define __HLMATRIX_H

#include "hl.h"

unsigned int hlmatrix_quantidade();

int hlmatrix_insere(const unsigned int interface, char *owner);
int hlmatrix_getRowstatus(const unsigned int interface);
int hlmatrix_setRowstatus(const unsigned int interface, const int novo_status);

int hlmatrix_getNlDroppedFrames(const unsigned int interface, uint32_t *retorna);
int hlmatrix_getNlInserts(const unsigned int interface, uint32_t *retorna);
int hlmatrix_getNlDeletes(const unsigned int interface, uint32_t *retorna);
int hlmatrix_getNlMaxentries(const unsigned int interface, int32_t *retorna);

int hlmatrix_getAlDroppedFrames(const unsigned int interface, uint32_t *retorna);
int hlmatrix_getAlInserts(const unsigned int interface, uint32_t *retorna);
int hlmatrix_getAlDeletes(const unsigned int interface, uint32_t *retorna);
int hlmatrix_getAlMaxentries(const unsigned int interface, int32_t *retorna);

int hlmatrix_atualizaNlInserts(const unsigned int interface);
int hlmatrix_atualizaNlDeletes(const unsigned int interface);
int hlmatrix_atualizaNlDroppedFrames(const unsigned int interface, const uint32_t drops);

int hlmatrix_atualizaAlInserts(const unsigned int interface);
int hlmatrix_atualizaAlDeletes(const unsigned int interface);
int hlmatrix_atualizaAlDroppedFrames(const unsigned int interface, const uint32_t drops);

int hlmatrix_busca_owner(const unsigned int indice, char *ptr,
	const unsigned int maximo);
int hlmatrix_define_owner(const unsigned int interface, char *string);

int hlmatrix_setNlmax(const unsigned int interface, const int32_t max);
int hlmatrix_setAlmax(const unsigned int interface, const int32_t max);

int hlmatrix_tabela_prepara(unsigned int *ptr);
int hlmatrix_tabela_proximo(unsigned int *ptr);

#endif /* __HLMATRIX_H */
