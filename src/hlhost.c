/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2003, 2008  Ricardo Nabinger Sanchez
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
  HlHost
 **********************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <string.h>

#include "configuracao.h"
#include "exit_codes.h"

#include "rowstatus.h"
#include "hlhost.h"
#include "log.h"


/* local defines */
#define HLHOST_TAM  4


/* tabela pré-inicializada com tudo zerado */
static hlhost_t	    hlhost_tabela[HLHOST_TAM] = {{0, }, };
static unsigned int hlh_quantidade = 0;


/* lista de indices */
#define	QUERO_PRIMEIRO	1
#define QUERO_PROXIMO	1
#undef	QUERO_REMOVER
#include "lista_indices.h"


unsigned int hlhost_quantidade()
{
	return hlh_quantidade;
}


int hlhost_insere(const unsigned int interface, char *owner)
{
	size_t tamanho;

	if (interface < HLHOST_TAM) {
		if (hlhost_tabela[interface].rowstatus != 0) {
			/* a interface já foi ativada */
#if DEBUG_HLHOST == 1
			Debug("impossível ativar interface #%u (status=%d)\n",
					interface,
					hlhost_tabela[interface].rowstatus);
#endif
			return ERROR_ISACTIVE;
		}

		tamanho = strlen(owner);
		hlhost_tabela[interface].owner = malloc(tamanho + 1);
		strncpy(hlhost_tabela[interface].owner, owner, tamanho);
		hlhost_tabela[interface].owner[tamanho] = '\0';

		hlhost_tabela[interface].rowstatus = ROWSTATUS_ACTIVE;
		hlh_quantidade++;

#if DEBUG_HLHOST == 1
		Debug("ativando interface #%d, owner='%s'\n",
				interface, owner);
#endif

		/* inserir na lista de indices */
		lista_insere(interface);

		return SUCCESS;
	}

	return ERROR_NOSUCHENTRY;
}


int hlhost_getRowstatus(const unsigned int interface)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		if (hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			return hlhost_tabela[interface].rowstatus;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlhost_setRowstatus(const unsigned int interface, const int novo_status)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		if ((novo_status != ROWSTATUS_ACTIVE) &&
				(novo_status != ROWSTATUS_NOT_IN_SERVICE) &&
				(novo_status != ROWSTATUS_NOT_READY) &&
				(novo_status != ROWSTATUS_CREATE_AND_GO) &&
				(novo_status != ROWSTATUS_CREATE_AND_WAIT) &&
				(novo_status != ROWSTATUS_DESTROY)) {
			return ERROR_EVILVALUE;
		}
		else {
			hlhost_tabela[interface].rowstatus = novo_status;
			return SUCCESS;
		}
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/* leituras - Nl */
int hlhost_getNlDroppedFrames(const unsigned int interface, uint32_t *retorna)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = hlhost_tabela[interface].nl_droppedframes;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlhost_getNlInserts(const unsigned int interface, uint32_t *retorna)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = hlhost_tabela[interface].nl_inserts;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlhost_getNlDeletes(const unsigned int interface, uint32_t *retorna)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = hlhost_tabela[interface].nl_deletes;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlhost_getNlMaxentries(const unsigned int interface, int *retorna)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = hlhost_tabela[interface].nl_maxentries;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/* leituras - Al */
int hlhost_getAlDroppedFrames(const unsigned int interface, uint32_t *retorna)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = hlhost_tabela[interface].al_droppedframes;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlhost_getAlInserts(const unsigned int interface, uint32_t *retorna)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = hlhost_tabela[interface].al_inserts;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlhost_getAlDeletes(const unsigned int interface, uint32_t *retorna)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = hlhost_tabela[interface].al_deletes;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlhost_getAlMaxentries(const unsigned int interface, int *retorna)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		*retorna = hlhost_tabela[interface].al_maxentries;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/* atualizações */
int hlhost_atualizaNlInserts(const unsigned int interface)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		if (hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			hlhost_tabela[interface].nl_inserts++;
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


int hlhost_atualizaNlDeletes(const unsigned int interface)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		if (hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			hlhost_tabela[interface].nl_deletes++;
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


int hlhost_atualizaNlDroppedFrames(const unsigned int interface, const uint32_t drops)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		hlhost_tabela[interface].nl_droppedframes = drops;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlhost_atualizaAlInserts(const unsigned int interface)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		if (hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			hlhost_tabela[interface].al_inserts++;
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


int hlhost_atualizaAlDeletes(const unsigned int interface)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		if (hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			hlhost_tabela[interface].al_deletes++;
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


int hlhost_atualizaAlDroppedFrames(const unsigned int interface, const uint32_t drops)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		if (hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			hlhost_tabela[interface].al_droppedframes = drops;
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
int hlhost_busca_owner(const unsigned int indice, char *ptr,
		const unsigned int maximo)
{
	unsigned int tamanho;

	if ((indice < HLHOST_TAM) &&
			(hlhost_tabela[indice].rowstatus == ROWSTATUS_ACTIVE)) {
		tamanho = strlen(hlhost_tabela[indice].owner);

		if ((tamanho + 1) > maximo) {
			/* buffer too small */
			return 0;
		}

		strncpy(ptr, hlhost_tabela[indice].owner, tamanho);
		ptr[tamanho] = '\0';

		return tamanho;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int hlhost_define_owner(const unsigned int interface, const char *_owner)
{
	size_t  tamanho;
	char    *char_ptr;

	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		/* better safe than sorrow */
		tamanho = strlen(_owner);
		char_ptr = hlhost_tabela[interface].owner;

		hlhost_tabela[interface].owner = malloc(tamanho + 1);
		if (hlhost_tabela[interface].owner != NULL) {
			free(char_ptr);
			strncpy(hlhost_tabela[interface].owner, _owner, tamanho);
			hlhost_tabela[interface].owner[tamanho] = '\0';
			return SUCCESS;
		}
		else {
			/* restore things up */
			hlhost_tabela[interface].owner = char_ptr;
			return ERROR_MALLOC;
		}
	}
	else {
		return ERROR_ISINACTIVE;
	}
}


int hlhost_setNlmax(const unsigned int interface, const int max)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		if (hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			hlhost_tabela[interface].nl_maxentries = max;
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


int hlhost_setAlmax(const unsigned int interface, const int max)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		if (hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE) {
			hlhost_tabela[interface].al_maxentries = max;
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
 *  prepara a tabela para percorrimento
 */
int hlhost_tabela_prepara(unsigned int *ptr)
{
	if (lista_primeiro() == SUCCESS) {
		*ptr = lista_atual->indice;
		return SUCCESS;
	}
	else {
		return ERROR_INDEXLIST;
	}
}


/*
 *  retorna o proximo elemento
 */
int hlhost_tabela_proximo(unsigned int *ptr)
{
	if (lista_proximo() == SUCCESS) {
		*ptr = lista_atual->indice;
		return SUCCESS;
	}
	else {
		return ERROR_INDEXLIST;
	}
}


/*
 *  verifica se o indice desejado é acessivel
 */
int hlhost_tabela_testa(const unsigned int interface)
{
	if ((interface < HLHOST_TAM) &&
			(hlhost_tabela[interface].rowstatus == ROWSTATUS_ACTIVE)) {
		return SUCCESS;
	}
	else {
		return ERROR_ISINACTIVE;
	}
}

