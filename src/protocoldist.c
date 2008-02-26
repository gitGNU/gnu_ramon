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

/* protocolDist
 *
 *   control: vetor [1..MAX] (desperdiça a posição [0])
 *   stats: hash, lista de indices
 */

#include <stdint.h>	/* inteiros ISO C99 */
#include <stdlib.h>	/* malloc, free */
#include <stdio.h>	/* ? */
#include <string.h>	/* strncpy */
#include <sys/types.h>

#include "configuracao.h"
#include "exit_codes.h"

#include "primo.h"
#include "funcao_hash.h"

#if PTSL
#include <netinet/in.h>
#include "stateful.h"
#endif

#include "protocoldist.h"
#include "protocoldir.h"
#include "sysuptime.h"

#include "rowstatus.h"
#include "log.h"

/* local defines */
#define PDISTSTATS_MAX	65536
#define PDISTSTATS_TAM	PRIMO
#define PDISTCNTRL_TAM	4


/* os vetores das tabelas */
static pdistcontrol_t	*cntrl_table[PDISTCNTRL_TAM] = {NULL, };
static pdist_stats_t	*stats_hashtable[PDISTSTATS_TAM] = {NULL, };

/* informações sobre as tabelas */
static unsigned int	cntrl_quantidade = 0;
static unsigned int	stats_quantidade = 0;
static unsigned int	stats_profundidade = 0;


/* agora incluir a lista encadeada */
#define QUERO_REMOVER	1
#define QUERO_PROXIMO	1
#define QUERO_PRIMEIRO	1
#include "lista_indices.h"


/* ProtocolDist CONTROL *******************************************************/
unsigned int pdist_control_busca_quantidade()
{
	return cntrl_quantidade;
}


/*
 *  returns the maximum entries number, required for traversal
 */
unsigned int pdist_control_busca_maximo()
{
	return PDISTCNTRL_TAM;
}


/*
   apenas testa se uma entrada é acessível
   */
int pdist_control_testa(const unsigned int indice)
{
	if (indice < PDISTCNTRL_TAM) {
		if (cntrl_table[indice] != NULL) {
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


int pdist_control_busca_status(const unsigned int indice)
{
	if (indice < PDISTCNTRL_TAM) {
		if (cntrl_table[indice] != NULL) {
			return cntrl_table[indice]->status;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int pdist_control_busca_index(const unsigned int indice)
{
	if (indice < PDISTCNTRL_TAM) {
		if (cntrl_table[indice] != NULL) {
			return cntrl_table[indice]->index;
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
   coloca a quantidade de pacotes descartados pelo agente através do ponteiro
   uint_ptr, o retorno é semelhante às outras funções (código de erro).
   */
int pdist_control_busca_droppedframes(const unsigned int indice, uint32_t *uint_ptr)
{
	if (indice < PDISTCNTRL_TAM) {
		if (cntrl_table[indice] != NULL) {
			*uint_ptr = cntrl_table[indice]->dropped_frames;
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
   coloca o create time da interface através do ponteiro uint_ptr, o retorno é
   semelhante às outras funções (código de erro).
   */
int pdist_control_busca_createtime(const unsigned int indice, uint32_t *uint_ptr)
{
	if (indice < PDISTCNTRL_TAM) {
		if (cntrl_table[indice] != NULL) {
			*uint_ptr = cntrl_table[indice]->create_time;
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
 *  copy entry's owner string to the pointer to char pointer received
 */
int pdist_control_busca_owner(const unsigned int indice, char *ptr,
		const unsigned int maximo)
{
	unsigned int tamanho;

	if (indice < PDISTCNTRL_TAM) {
		if (cntrl_table[indice] != NULL) {
			tamanho = strlen(cntrl_table[indice]->owner);

			if ((tamanho + 1) > maximo) {
				/* buffer too small */
				return 0;
			}

			strncpy(ptr, cntrl_table[indice]->owner, tamanho);
			ptr[tamanho] = '\0';

			return tamanho;
		}
		else {
			return ERROR_ISINACTIVE;
		}
	}
	else {
		return ERROR_EVILVALUE;
	}
}


/*
   Altera o dono de uma entrada, cuidando para que o dono antigo não seja perdido
   durante a alocação de memória. Se um erro ocorrer durante a alocação de memória,
   o dono antigo é recolocado (por não ter sido desalocado).
   */
int pdist_control_define_owner(const unsigned int indice, const char *owner_ptr)
{
	char    *salva_ptr;
	int	    tamanho;

	if (indice < PDISTCNTRL_TAM) {
		if (cntrl_table[indice] != NULL) {
			salva_ptr = cntrl_table[indice]->owner;

			/* alocar espaço para o novo */
			tamanho = strlen(owner_ptr);
			cntrl_table[indice]->owner = malloc(tamanho + 1);
			if (cntrl_table[indice]->owner == NULL) {
				/* restaurar */
				cntrl_table[indice]->owner = salva_ptr;

				return ERROR_MALLOC;
			}
			else {
				free(salva_ptr);
			}

			strncpy(cntrl_table[indice]->owner, owner_ptr, tamanho);
			cntrl_table[indice]->owner[tamanho] = '\0';

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
   altera o status de uma entrada, verificando a validade desse status desejado
   */
int pdist_control_define_status(const unsigned int indice, const int novo_status)
{
	if (indice < PDISTCNTRL_TAM) {
		if (cntrl_table[indice] != NULL) {
			/* entrada existe, verificar status passado */
			if ((novo_status != ROWSTATUS_ACTIVE) &&
					(novo_status != ROWSTATUS_NOT_IN_SERVICE) &&
					(novo_status != ROWSTATUS_NOT_READY) &&
					(novo_status != ROWSTATUS_CREATE_AND_GO) &&
					(novo_status != ROWSTATUS_CREATE_AND_WAIT) &&
					(novo_status != ROWSTATUS_DESTROY)) {
				return ERROR_EVILVALUE;
			}

			cntrl_table[indice]->status = novo_status;

			/* FIXME: status != ROWSTATUS_ACTIVE, demolir */

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
   remove uma entrada da tabela control, mas antes removendo todos os elementos
   dependentes na tabela stats.
   */
int pdist_control_remove(const unsigned int vitima)
{
	unsigned int    remocoes_stats = 0;
	unsigned int    indice_stats = 0;

	/* verificar se a entrada existe */
	if ((vitima < PDISTCNTRL_TAM ) && (cntrl_table[vitima] == NULL)) {
		return ERROR_NOSUCHENTRY;
	}

	while (1) {
		while ((indice_stats < PRIMO) || ((stats_hashtable[indice_stats] != NULL) &&
					(stats_hashtable[indice_stats]->control_index != vitima))) {
			indice_stats++;
		}

		if (indice_stats < PRIMO) {
			/* encontrado */
			lista_remove_indice(indice_stats);
			free(stats_hashtable[indice_stats]);
			stats_hashtable[indice_stats] = NULL;
			stats_quantidade--;
			remocoes_stats++;
		}
		else {
			/* percorreu toda a tabela - interromper o 'while (1)' */
			break;
		}
	}

	/* agora é seguro remover a entrada na control */
	free(cntrl_table[vitima]);
	cntrl_table[vitima] = NULL;
	cntrl_quantidade--;

#if PDIST_DEBUG
	Debug("1 interface e %u entradas removidas", remocoes_stats);
#endif

	return SUCCESS;
}


int pdist_control_insere(const unsigned int interface, const uint32_t drp_frames,
		char const *own)
{
	int owner_tam = strlen(own);

	if ((interface < PDISTCNTRL_TAM) && (cntrl_table[interface] == NULL)) {
		cntrl_table[interface] = malloc(sizeof(pdistcontrol_t));

		if (cntrl_table[interface] != NULL) {
			/* ok, memória alocada */
			cntrl_table[interface]->index = interface;
			cntrl_table[interface]->dropped_frames = drp_frames;
			cntrl_table[interface]->create_time = sysuptime();
			cntrl_table[interface]->status = ROWSTATUS_ACTIVE;

			cntrl_table[interface]->owner = malloc(owner_tam + 1);
			if (cntrl_table[interface]->owner == NULL) {
				/* free recent allocated memory */
				free(cntrl_table[interface]->owner);
				free(cntrl_table[interface]);
				cntrl_table[interface] = NULL;

				return ERROR_MALLOC;
			}
			strncpy(cntrl_table[interface]->owner, own, owner_tam);

			cntrl_quantidade++;

			return SUCCESS;
		}
		else {
			return ERROR_MALLOC;
		}
	}
	else {
		return ERROR_ISACTIVE;
	}
}


/*
   retorna o endereço de indice->index, para ser usado como referência
   */
unsigned int *pdist_control_busca_index_addr(const unsigned int indice)
{
	if (indice < PDISTCNTRL_TAM) {
		if (cntrl_table[indice] != NULL) {
			return &cntrl_table[indice]->index;
		}
		else {
			return NULL;
		}
	}
	else {
		return NULL;
	}
}


//int protdist_control_getCIndexAtIndex(const unsigned int index)
//{
//    if ((index > 0) && (index <= cntrl_quantidade) &&
//	    (cntrl_table[index] != NULL)) {
//	return cntrl_table[index]->index;
//    }
//    else {
//	return ERROR_NOSUCHENTRY;
//    }
//}


/*
   atualiza a contagem de dropped_frames
   */
int pdist_control_atualiza_drops(const unsigned int indice, const uint32_t drp_frames)
{
	if (indice < PDISTCNTRL_TAM) {
		if (cntrl_table[indice] != NULL) {
			cntrl_table[indice]->dropped_frames = drp_frames;

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




/* ProtocolDist STATS *********************************************************/
unsigned int protdist_stats_getQtd()
{
	return stats_quantidade;
}


static unsigned int protdist_stats_localiza(const unsigned int index_control,
		const unsigned int index_stats)
{
	unsigned int i = 0;	    /* offset da hash */
	unsigned int chave = ((index_control & 0xffff) << 16) | (index_stats & 0xffff);
	unsigned int hash_index;

	HASH(chave, i, hash_index);

	/* encontraremos a entrada se:
	   1) estiver antes de 'profundidade'
	   2) a posição atual conter algum dado (!= NULL)
	   3) os dados da chave forem iguais aos de confirmação
	   */
	if ((stats_hashtable[hash_index] != NULL) &&
			(stats_hashtable[hash_index]->chave_confirma == chave)) {
		/* bala! achamos na primeira */
		return hash_index;
	}

	/* holy.. colisão */
	i++;
	while (i <= stats_profundidade) {
		HASH(chave, i, hash_index);
		if ((stats_hashtable[hash_index] != NULL) &&
				(stats_hashtable[hash_index]->chave_confirma == chave)) {
			/* Wheee! :) */
			return hash_index;
		}
		i++;
	}

	/* clever! */
	return PDISTSTATS_TAM;
}


int protdist_stats_getControlIndex(const unsigned int index_control,
		const unsigned int index_stats)
{
	unsigned int hash_index = protdist_stats_localiza(index_control, index_stats);

	if (hash_index != PDISTSTATS_TAM) {
		/* acho que achou ;) */
		return stats_hashtable[hash_index]->control_index;
	}

	return ERROR_NOSUCHENTRY;
}


/*
   retorna o control index de uma entrada localizada na posição informada
   */
int pdist_stats_tabela_busca_controlindex(const unsigned int indice, uint32_t *coloca)
{
	if (stats_hashtable[indice] != NULL) {
		*coloca = stats_hashtable[indice]->control_index;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int protdist_stats_getProtIndex(const unsigned int index_control,
		const unsigned int index_stats)
{
	unsigned int hash_index = protdist_stats_localiza(index_control, index_stats);

	if (hash_index != PDISTSTATS_TAM) {
		/* acho que achou ;) */
		return stats_hashtable[hash_index]->protdir_index;
	}

	return ERROR_NOSUCHENTRY;
}


/*
   retorna o local index de uma entrada localizada na posição informada
   */
int pdist_stats_tabela_busca_protdirindex(const unsigned int indice, uint32_t *coloca)
{
	if (stats_hashtable[indice] != NULL) {
		*coloca = stats_hashtable[indice]->protdir_index;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int protdist_stats_getPkts(const unsigned int index_control,
		const unsigned int index_stats)
{
	unsigned int hash_index = protdist_stats_localiza(index_control, index_stats);

	if (hash_index != PDISTSTATS_TAM) {
		/* acho que achou ;) */
		return stats_hashtable[hash_index]->pkts;
	}

	return ERROR_NOSUCHENTRY;
}


/*
   retorna a quantidade de pacotes
   */
int pdist_stats_tabela_busca_pkts(const unsigned int indice, uint32_t *copia)
{
	if (stats_hashtable[indice] != NULL) {
		*copia = stats_hashtable[indice]->pkts;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int protdist_stats_getOctets(const unsigned int index_control,
		const unsigned int index_stats)
{
	unsigned int hash_index = protdist_stats_localiza(index_control, index_stats);

	if (hash_index != PDISTSTATS_TAM) {
		/* acho que achou ;) */
		return stats_hashtable[hash_index]->octets;
	}

	return ERROR_NOSUCHENTRY;
}


/*
   retorna a quantidade de octetos
   */
int pdist_stats_tabela_busca_octets(const unsigned int indice, uint32_t *copia)
{
	if (stats_hashtable[indice] != NULL) {
		*copia = stats_hashtable[indice]->octets;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int protdist_stats_deleteEntry(const unsigned int index_control,
		const unsigned int index_stats)
{
	unsigned int hash_index = protdist_stats_localiza(index_control, index_stats);

	if (hash_index != PDISTSTATS_TAM) {
		free(stats_hashtable[hash_index]);
		stats_hashtable[hash_index] = NULL;
		stats_quantidade--;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/**
 * Updates an existing entry for the given protocol encapsulation, or add a new
 * entry with the data provided.
 *
 * \retval SUCCESS	If no errors during creation/updating.
 * \retval ERROR_FULL	If protocolDist table is full.
 * \retval ERROR_HASH	If too many collisions occured in the hash table.
 * \retval ERROR_MALLOC	If memory could not be allocated.
 */
int
pdist_update(const unsigned int index_control, const unsigned int index_stats,
		const uint32_t pkts, const uint32_t octets)
{
	unsigned int i = 0;	    /* offset da hash */
	unsigned int chave = ((index_control & 0xffff) << 16) | (index_stats & 0xffff);
	unsigned int hash_index = protdist_stats_localiza(index_control, index_stats);

	if (hash_index != PDISTSTATS_TAM) {
		/* Entry exists -- only update. */

#if PDIST_DEBUG
		Debug("(%d, %d, %u, %u)[%u]: updating", index_control,
				index_stats, pkts, octets, hash_index);
#endif
		stats_hashtable[hash_index]->pkts += pkts;
		stats_hashtable[hash_index]->octets += octets;
		return SUCCESS;
	}

	if (stats_quantidade >= PDISTSTATS_MAX) {
		/* Table is full, cannot create entry. */
		Debug("(%d, %d, %u, %u): table is full", index_control,
				index_stats, pkts, octets);
		return ERROR_FULL;
	}

	/* Compute index for this entry. */
	HASH(chave, i, hash_index);

	while ((i < PDISTSTATS_MAX) && (stats_hashtable[hash_index] != NULL)) {
		/* Compute another index, last one collided. */
		i++;
		HASH(chave, i, hash_index);
	}
	if (i >= PDISTSTATS_MAX) {
		Debug("could not add entry, too many collisions: (%u/%u)",
				stats_quantidade, PDISTSTATS_TAM);
		return ERROR_HASH;
	}

#if PDIST_DEBUG
	Debug("(%d, %d, %u, %u): new entry at %u", index_control, index_stats,
			pkts, octets, hash_index);
#endif

	/* Get a struct and fill the data. */
	stats_hashtable[hash_index] = malloc(sizeof(pdist_stats_t));
	if (stats_hashtable[hash_index] == NULL) {
#if PDIST_DEBUG
		Debug("not enough memory");
#endif
		return ERROR_MALLOC;
	}

	stats_hashtable[hash_index]->control_index = index_control;
	stats_hashtable[hash_index]->protdir_index = index_stats;
	stats_hashtable[hash_index]->pkts = pkts;
	stats_hashtable[hash_index]->octets = octets;
	stats_hashtable[hash_index]->chave_confirma = chave;
	stats_quantidade++;

	/* Update depth of this hash table. */
	if (i > stats_profundidade)
		stats_profundidade = i;

	/* Include this entry in the list, for OID traversal. */
	if (lista_insere(hash_index) != SUCCESS)
		Debug("lista_insere(%u, %u) failed", chave, hash_index);

	return SUCCESS;
}


/* explicitamente solicita a ordenação da tabela */
int pdist_stats_tabela_prepara()
{
	if (lista_primeiro() == SUCCESS) {
		return SUCCESS;
	}
	else {
		return ERROR_INDEXLIST;
	}
}


/* posiciona e retorna o primeiro índice da lista */
int pdist_stats_tabela_primeiro(unsigned int *resultado)
{
	if (lista_primeiro() == SUCCESS) {
		*resultado = lista_atual->indice;
		return SUCCESS;
	}
	else {
		return ERROR_INDEXLIST;
	}
}


/* devolve o índice da próxima entrada */
int pdist_stats_tabela_prox(unsigned int *resultado)
{
	if (lista_proximo() == SUCCESS) {
		*resultado = lista_atual->indice;
		return SUCCESS;
	}
	else {
		return ERROR_INDEXLIST;
	}
}


/* apenas verifica se o índice pode ser usado */
int pdist_stats_tabela_testa(const unsigned int indice)
{
	if (stats_hashtable[indice] != NULL) {
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


void pdist_stats_tabela_debug()
{
	/* FIXME: definitely broken. */
	while (lista_proximo() == SUCCESS) {
		//	Debug("%u.%u > ",
		//		*stats_hashtable[lista_atual->indice]->control_index,
		//		*stats_hashtable[lista_atual->indice]->protdir_index);
		Debug("%u > ", lista_atual->indice);
	}
	Debug("#");
}


/*
   percorre a tabela stats em busca do encapsulamento na protocolDir sendo
   removido. O(n), sempre, pois pode [poderá, um dia] haver mais de uma
   interface sendo monitorada.

   essa função foi feita para ser chamada a partir da protocolDir, quando um
   encapsulamento é removido e todas as entradas que faziam referência devem
   ser removidas.
   */
int pdist_stats_remove_cascata(unsigned int pdir_index)
{
	unsigned int indice = 0;
	unsigned int remocoes = 0;

	while (1) {
		while ((indice < PRIMO) || ((stats_hashtable[indice] != NULL) &&
					(stats_hashtable[indice]->protdir_index != pdir_index))) {
			indice++;
		}

		if (indice < PRIMO) {
			/* referência encontrada */
			lista_remove_indice(indice);
			free(stats_hashtable[indice]);
			stats_hashtable[indice] = NULL;
			stats_quantidade--;
			remocoes++;
		}
		else {
			/* toda a tabela foi percorrida - interromper o 'while (1)' */
			break;
		}
	}

#if PDIST_DEBUG
	Debug("%u entrada(s) removida(s)", remocoes);
#endif

	return SUCCESS;
}

