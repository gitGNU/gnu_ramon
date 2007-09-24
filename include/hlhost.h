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

#ifndef __HLHOST_H
#define __HLHOST_H

#include "hl.h"

unsigned int hlhost_quantidade();
int hlhost_insere(const unsigned int interface, char *owner);

int hlhost_getRowstatus(const unsigned int interface);
int hlhost_setRowstatus(const unsigned int interface, const int novo_status);

int hlhost_getNlDroppedFrames(const unsigned int interface, uint32_t *retorna);
int hlhost_getNlInserts(const unsigned int interface, uint32_t *retorna);
int hlhost_getNlDeletes(const unsigned int interface, uint32_t *retorna);
int hlhost_getNlMaxentries(const unsigned int interface, int *retorna);

int hlhost_getAlDroppedFrames(const unsigned int interface, uint32_t *retorna);
int hlhost_getAlInserts(const unsigned int interface, uint32_t *retorna);
int hlhost_getAlDeletes(const unsigned int interface, uint32_t *retorna);
int hlhost_getAlMaxentries(const unsigned int interface, int *retorna);

int hlhost_atualizaNlInserts(const unsigned int interface);
int hlhost_atualizaNlDeletes(const unsigned int interface);
int hlhost_atualizaNlDroppedFrames(const unsigned int interface, const uint32_t drops);

int hlhost_atualizaAlDeletes(const unsigned int interface);
int hlhost_atualizaAlInserts(const unsigned int interface);
int hlhost_atualizaAlDroppedFrames(const unsigned int interface, const uint32_t drops);

int hlhost_busca_owner(const unsigned int indice, char *ptr,
	const unsigned int maximo);
int hlhost_define_owner(const unsigned int interface, const char *_owner);

int hlhost_setNlmax(const unsigned int interface, const int max);
int hlhost_setAlmax(const unsigned int interface, const int max);

int hlhost_tabela_prepara(unsigned int *ptr);
int hlhost_tabela_proximo(unsigned int *ptr);
int hlhost_tabela_testa(const unsigned int interface);

#endif /* __HLHOST_H */
