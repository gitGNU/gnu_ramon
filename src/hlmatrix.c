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

/***********************************************
  HlMatrix
 **********************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <string.h>

#include "rowstatus.h"
#include "hlmatrix.h"

#include "configuracao.h"
#include "exit_codes.h"

/* local defines */
#define HLMATRIX_TAM	4


/* tabela pré-inicializada com tudo zerado */
static hlmatrix_t   tabela[HLMATRIX_TAM] = {{0, }, };

static unsigned int quantidade = 0;

/* indexes list */
#undef  QUERO_REMOVER
#define	QUERO_PRIMEIRO	1
#define QUERO_PROXIMO   1
#include "lista_indices.h"


unsigned int hlmatrix_quantidade()
{
	return quantidade;
}


int hlmatrix_insere(const unsigned int interface, char *owner)
{
	if (interface < HLMATRIX_TAM) {
		if (tabela[interface].rowstatus != 0) {
			/* a interface já foi ativada */
#if DEBUG_HLMATRIX
			fprintf(stderr, "hlmatrix: impossível ativar interface #%u (status=%d)\n",
					interface, tabela[interface].rowstatus);
#endif
			return ERROR_ISACTIVE;
		}

		tabela[interface].owner = strdup(owner);
		tabela[interface].rowstatus = ROWSTATUS_ACTIVE;

		if (lista_insere(interface) != SUCCESS) {
			fprintf(stderr, "hlmatrix: erro ao tentar inserir interface %u na lista\n",
					interface);
		}

		quantidade++;

#if DEBUG_HLMATRIX
		fprintf(stderr, "hlmatrix: ativando interface #%u, owner='%s'\n",
				interface, owner);
#endif
		return SUCCESS;
	}

	return ERROR_NOSUCHENTRY;
}


int hlmatrix_getRowstatus(const int unsigned interface)
{
	if (interface < HLMATRIX_TAM) {
		if (tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			return tabela[interface].rowstatus;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_setRowstatus(const unsigned int interface, const int novo_status)
{
	if (interface < HLMATRIX_TAM) {
		if (tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			tabela[interface].rowstatus = novo_status;
			return ERROR_NOSUCHENTRY;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return SUCCESS;
	}
}


/* leituras - Nl */
int hlmatrix_getNlDroppedFrames(const unsigned int interface, uint32_t *retorna)
{
	if ((interface < HLMATRIX_TAM) &&
			(tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = tabela[interface].nl_droppedframes;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_getNlInserts(const unsigned int interface, uint32_t *retorna)
{
	if ((interface < HLMATRIX_TAM) &&
			(tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = tabela[interface].nl_inserts;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_getNlDeletes(const unsigned int interface, uint32_t *retorna)
{
	if ((interface < HLMATRIX_TAM) &&
			(tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = tabela[interface].nl_deletes;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_getNlMaxentries(const unsigned int interface, int32_t *retorna)
{
	if ((interface < HLMATRIX_TAM) &&
			(tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = tabela[interface].nl_maxentries;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/* leituras - Al */
int hlmatrix_getAlDroppedFrames(const unsigned int interface, uint32_t *retorna)
{
	if ((interface < HLMATRIX_TAM) &&
			(tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = tabela[interface].al_droppedframes;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_getAlInserts(const unsigned int interface, uint32_t *retorna)
{
	if ((interface < HLMATRIX_TAM) &&
			(tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = tabela[interface].al_inserts;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_getAlDeletes(const unsigned int interface, uint32_t *retorna)
{
	if ((interface < HLMATRIX_TAM) &&
			(tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = tabela[interface].al_deletes;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_getAlMaxentries(const unsigned int interface, int *retorna)
{
	if ((interface < HLMATRIX_TAM) &&
			(tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = tabela[interface].al_maxentries;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/* atualizações */
int hlmatrix_atualizaNlInserts(const unsigned int interface)
{
	if (interface < HLMATRIX_TAM) {
		if (tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			tabela[interface].nl_inserts++;
			return SUCCESS;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_atualizaNlDeletes(const unsigned int interface)
{
	if (interface < HLMATRIX_TAM) {
		if (tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			tabela[interface].nl_deletes++;
			return SUCCESS;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_atualizaNlDroppedFrames(const unsigned int interface, const uint32_t drops)
{
	if (interface < HLMATRIX_TAM) {
		tabela[interface].nl_droppedframes = drops;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_atualizaAlInserts(const unsigned int interface)
{
	if (interface < HLMATRIX_TAM) {
		if (tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			tabela[interface].al_inserts++;
			return SUCCESS;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_atualizaAlDeletes(const unsigned int interface)
{
	if (interface < HLMATRIX_TAM) {
		if (tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			tabela[interface].al_deletes++;
			return SUCCESS;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_atualizaAlDroppedFrames(const unsigned int interface, const uint32_t drops)
{
	if (interface < HLMATRIX_TAM) {
		if (tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			tabela[interface].al_droppedframes = drops;
			return SUCCESS;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
 *  copy entry's owner to the buffer pointer 'ptr' received, 'maximo' sized
 */
int hlmatrix_busca_owner(const unsigned int indice, char *ptr,
		const unsigned int maximo)
{
	unsigned int tamanho;

	if ((indice < HLMATRIX_TAM) &&
			(tabela[indice].rowstatus == ROWSTATUS_ACTIVE)) {
		tamanho = strlen(tabela[indice].owner);

		if ((tamanho + 1) > maximo) {
			/* buffer too small */
			return 0;
		}

		strncpy(ptr, tabela[indice].owner, tamanho);
		ptr[tamanho] = '\0';

		return tamanho;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_define_owner(const unsigned int interface, char *string)
{
	size_t  tamanho;
	char    *salva_ptr;

	if (interface < HLMATRIX_TAM) {
		if (tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			salva_ptr = tabela[interface].owner;

			tamanho = strlen(string);
			tabela[interface].owner = malloc(tamanho + 1);
			if (tabela[interface].owner == NULL) {
				/* restoring... */
				tabela[interface].owner = salva_ptr;
				return ERROR_MALLOC;
			}

			strncpy(tabela[interface].owner, string, tamanho);
			tabela[interface].owner[tamanho] = '\0';

			return SUCCESS;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_setNlmax(const unsigned int interface, const int32_t max)
{
	if (interface < HLMATRIX_TAM) {
		if (tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			tabela[interface].nl_maxentries = max;
			return SUCCESS;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlmatrix_setAlmax(const unsigned int interface, const int32_t max)
{
	if (interface < HLMATRIX_TAM) {
		if (tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			tabela[interface].al_maxentries = max;
			return SUCCESS;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
 *  functions to prepare and traverse the index list
 */
int hlmatrix_tabela_prepara(unsigned int *ptr)
{
	if (lista_primeiro() == SUCCESS) {
		*ptr = lista_atual->indice;
		return SUCCESS;
	}
	else {
		return ERROR_INDEXLIST;
	}
}


int hlmatrix_tabela_proximo(unsigned int *ptr)
{
	if (lista_proximo() == SUCCESS) {
		*ptr = lista_atual->indice;
		return SUCCESS;
	}
	else {
		return ERROR_INDEXLIST;
	}
}

