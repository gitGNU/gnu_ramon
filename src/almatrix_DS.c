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

#include <time.h>	    // time_t
#include <netinet/in.h>	    // in_addr_t
#include <stdint.h>	    // uint32_t
#include <stdio.h>	    // fprintf
#include <stdlib.h>	    // malloc

#include "configuracao.h"

#include "primo.h"
#include "funcao_hash.h"

#if PTSL
#include "stateful.h"
#endif

#include "pedb.h"
#include "hlmatrix.h"
#include "almatrix_DS.h"
#include "exit_codes.h"
#include "log.h"


/* local defines */
#define ALMATRIXDS_MAX	65536
#define ALMATRIXDS_TAM	PRIMO


static almatrix_t   *tabela_hash[ALMATRIXDS_TAM] = {NULL, };
static unsigned int quantidade = 0;	// quantidade de entradas na tabela
static unsigned int profundidade = 0;	// maior profundidade (limite de busca)


#define	QUERO_PRIMEIRO	1
#define	QUERO_PROXIMO	1
#undef	QUERO_ORDENAR
#undef	QUERO_REMOVER
#include "lista_indices.h"


unsigned int almatrix_DS_quantidade()
{
	return quantidade;
}


static unsigned int almatrix_DS_localiza(const in_addr_t src_address, const in_addr_t dest_address,
		const unsigned int portas, const unsigned int chave)
{
	unsigned int i = 0;	    /* offset da hash */
	unsigned int hash_index;

	HASH(chave, i, hash_index);
	if ((tabela_hash[hash_index] != NULL) &&
			(tabela_hash[hash_index]->portas == portas) &&
			(tabela_hash[hash_index]->source_addr == src_address) &&
			(tabela_hash[hash_index]->destin_addr == dest_address)) {
		/* found in the first try */
		return hash_index;
	}

	/* start probing */
	i++;
	while (i <= profundidade) {
		HASH(chave, i, hash_index);
		if ((tabela_hash[hash_index] == NULL) ||
				(tabela_hash[hash_index]->portas != portas) ||
				(tabela_hash[hash_index]->source_addr != src_address) ||
				(tabela_hash[hash_index]->destin_addr != dest_address)) {
			/* nao encontrou */
			i++;
		}
		else {
			/* encontrou a entrada */
			return hash_index;
		}
	}

	return ALMATRIXDS_TAM;
}


int almatrix_DS_insereAtualiza(pedb_t *dados)
{
	unsigned int    i;
	unsigned int    indice_entrada;
	unsigned int    indice_saida;
	uint32_t	    portas;
	uint32_t	    chave;

	portas = (dados->nl_localindex << 16) | dados->al_localindex;

	/* estranho.. pq só atualiza entrada de pacotes se o pacote for unicast?? */
	if (dados->is_broadcast == 0) {
		chave = dados->ip_dest ^ portas;
		indice_entrada = almatrix_DS_localiza(dados->ip_orig, dados->ip_dest, portas, chave);

		/* atualizar/criar ENTRADA de pacotes */
		if (indice_entrada != ALMATRIXDS_TAM) {
#if DEBUG_ALMATRIX_DS == 1
			Debug("atualizando (%d)", indice_entrada);
#endif
			tabela_hash[indice_entrada]->pkts++;
			tabela_hash[indice_entrada]->octets += dados->tamanho;

#ifdef USE_TIMEFILTER
			tabela_hash[indice_entrada]->timemark = dados->uptime;
#endif
		}
		else {
			/* alocar uma posição na tabela */
#if DEBUG_ALMATRIX_DS == 1
			Debug("inserindo nova (%d)", indice_entrada);
#endif
			i = 0;
			HASH(chave, i, indice_entrada);

			while ((i < ALMATRIXDS_MAX) && (tabela_hash[indice_entrada] != NULL)) {
				i++;
				HASH(chave, i, indice_entrada);
			}
			if (i >= ALMATRIXDS_MAX) {
				Debug("tabela cheia? (%u/%u)",
						quantidade, ALMATRIXDS_MAX);
				return ERROR_FULL;
			}
			if (i > profundidade) {
				profundidade = i;
			}

			/* criar a entrada */
			tabela_hash[indice_entrada] = malloc(sizeof(almatrix_t));
#if PLEASE_CHECK_FOR_ERRORS == 1
			if (tabela_hash[indice_entrada] == NULL) {
				Debug("erro no malloc!");
				return ERROR_MALLOC;
			}
#endif
			tabela_hash[indice_entrada]->portas = portas;
			tabela_hash[indice_entrada]->source_addr = dados->ip_orig;
			tabela_hash[indice_entrada]->destin_addr = dados->ip_dest;
			tabela_hash[indice_entrada]->localindex_net = dados->nl_localindex;
			tabela_hash[indice_entrada]->localindex_app = dados->al_localindex;

			tabela_hash[indice_entrada]->pkts = 1;
			tabela_hash[indice_entrada]->octets = dados->tamanho;

			tabela_hash[indice_entrada]->interface = dados->interface;

			tabela_hash[indice_entrada]->create_time = dados->uptime;

#ifdef USE_TIMEFILTER
			tabela_hash[indice_entrada]->timemark = dados->uptime;
#else
			tabela_hash[indice_entrada]->timemark = 0;
#endif

			/* atualizar NlInserts na HlHost */
			if (hlmatrix_atualizaNlInserts(dados->interface) != SUCCESS) {
				Debug("hlmatrix_atualizaNlInserts(%d) falhou",
						dados->interface);
			}

			if (lista_insere(indice_entrada) != SUCCESS)
				Debug("lista_insere() falhou");

			quantidade++;
		}
	}

#if 0
	/* atualizar/criar SAIDA de pacotes */
	chave = dados->ip_orig ^ portas;
	indice_saida = almatrix_DS_localiza(dados->ip_dest, dados->ip_orig, portas, chave);

	if (indice_saida != ALMATRIXDS_TAM) {
#if DEBUG_ALMATRIX_DS == 1
		Debug("atualizando (%d)", indice_saida);
#endif
		tabela_hash[indice_saida]->pkts++;
		tabela_hash[indice_saida]->octets += dados->tamanho;

#ifdef USE_TIMEFILTER
		tabela_hash[indice_saida]->timemark = dados->uptime;
#endif
	}
	else {
		/* alocar uma posição na tabela */
#if DEBUG_ALMATRIX_DS == 1
		Debug("inserindo nova (%d)", indice_saida);
#endif
		i = 0;
		HASH(chave, i, indice_saida);

		while ((i < ALMATRIXDS_MAX) && (tabela_hash[indice_saida] != NULL)) {
			i++;
			HASH(chave, i, indice_saida);
		}
		if (i >= ALMATRIXDS_MAX) {
			Debug("tabela cheia? (%u/%u)", quantidade,
					ALMATRIXDS_MAX);
			return ERROR_FULL;
		}
		if (i > profundidade) {
			profundidade = i;
		}

		/* criar a entrada */
		tabela_hash[indice_saida] = malloc(sizeof(almatrix_t));
#if PLEASE_CHECK_FOR_ERRORS == 1
		if (tabela_hash[indice_saida] == NULL) {
			Debug("erro no malloc!");
			return ERROR_MALLOC;
		}
#endif
		tabela_hash[indice_saida]->portas = portas;
		tabela_hash[indice_saida]->source_addr = dados->ip_dest;
		tabela_hash[indice_saida]->destin_addr = dados->ip_orig;
		tabela_hash[indice_saida]->localindex_net = dados->nl_localindex;
		tabela_hash[indice_saida]->localindex_app = dados->al_localindex;

		tabela_hash[indice_saida]->pkts = 1;
		tabela_hash[indice_saida]->octets = dados->tamanho;

		tabela_hash[indice_saida]->interface = dados->interface;

		tabela_hash[indice_saida]->create_time = dados->uptime;

#ifdef USE_TIMEFILTER
		tabela_hash[indice_saida]->timemark = dados->uptime;
#else
		tabela_hash[indice_saida]->timemark = 0;
#endif

		/* atualizar NlInserts na HlHost */
		if (hlmatrix_atualizaNlInserts(dados->interface) != SUCCESS) {
			Debug("hlmatrix_atualizaNlInserts(%d) falhou",
					dados->interface);
		}

		if (lista_insere(indice_saida) != SUCCESS) {
			Debug("lista_insere() falhou");
		}

		quantidade++;
	}
#endif

	return SUCCESS;
}


void almatrix_DS_hashStats()
{
	Debug("entradas: %d, profundidade: %d\n", quantidade, profundidade);
}


/*
 *  returns the full index for an entry, which is:
 *  hlMatrixControlIndex.alMatrixDSTimeMark.protocolDirLocalIndexNet
 *  .nlMatrixDSDestAddress.nlMatrixDSSourceAddress.protocolDirLocalIndexApp
 */
int almatrix_ds_helper(const unsigned int indice, uint32_t *hlmindex, uint32_t *al_tmark,
		uint32_t *plindex_net, uint32_t *nlm_dstaddr, uint32_t *nlm_srcaddr,
		uint32_t *plindex_app)
{
	if ((indice < ALMATRIXDS_TAM) && (tabela_hash[indice] != NULL)) {
		*hlmindex = tabela_hash[indice]->interface;
		*al_tmark = tabela_hash[indice]->timemark;
		*plindex_net = tabela_hash[indice]->localindex_net;
		*nlm_dstaddr = tabela_hash[indice]->destin_addr;
		*nlm_srcaddr = tabela_hash[indice]->source_addr;
		*plindex_app = tabela_hash[indice]->localindex_app;

		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
 *  functions to prepare (ask sorting), traverse the index list and test an entry.
 *  return the index (if exists) by the caller's pointer
 */
int almatrix_ds_tabela_prepara(unsigned int *ptr)
{
	if (lista_primeiro() == SUCCESS) {
		*ptr = lista_atual->indice;
		return SUCCESS;
	}
	else {
		*ptr = ALMATRIXDS_TAM;
		return ERROR_INDEXLIST;
	}
}


int almatrix_ds_tabela_proximo(unsigned int *ptr)
{
	if (lista_proximo() == SUCCESS) {
		*ptr = lista_atual->indice;
		return SUCCESS;
	}
	else {
		*ptr = ALMATRIXDS_TAM;
		return ERROR_INDEXLIST;
	}
}


int almatrix_ds_testa(const unsigned int indice)
{
	if ((indice < ALMATRIXDS_TAM) && (tabela_hash[indice] != NULL)) {
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
 *  functions to retrieve data from an entry, copying it to the caller's pointer
 */
int almatrix_ds_busca_pkts(const unsigned int indice, uint32_t *ptr)
{
	if ((indice < ALMATRIXDS_TAM) && (tabela_hash[indice] != NULL)) {
		*ptr = tabela_hash[indice]->pkts;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int almatrix_ds_busca_octets(const unsigned int indice, uint32_t *ptr)
{
	if ((indice < ALMATRIXDS_TAM) && (tabela_hash[indice] != NULL)) {
		*ptr = tabela_hash[indice]->octets;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int almatrix_ds_busca_createtime(const unsigned int indice, uint32_t *ptr)
{
	if ((indice < ALMATRIXDS_TAM) && (tabela_hash[indice] != NULL)) {
		*ptr = tabela_hash[indice]->create_time;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}

