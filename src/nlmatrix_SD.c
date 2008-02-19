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
#include "exit_codes.h"

#if PTSL
#include "stateful.h"
#endif

#include "primo.h"
#include "funcao_hash.h"

#include "pedb.h"
#include "hlmatrix.h"
#include "nlmatrix_SD.h"
#include "log.h"

/* local defines */
#define NLMATRIXSD_MAX	65536
#define NLMATRIXSD_TAM	PRIMO

static unsigned int quantidade = 0;	// quantidade de entradas na tabela
static unsigned int profundidade = 0;	// maior profundidade (limite de busca)
static nlmatrix_t   *tabela_hash[NLMATRIXSD_TAM] = {NULL, };


#define QUERO_PROXIMO   1
#define QUERO_PRIMEIRO	1
#undef	QUERO_REMOVER
#include "lista_indices.h"


unsigned int nlmatrix_SD_quantidade()
{
	return quantidade;
}


/* AMD Guide: pg 32 */
/* NlMatrix SD: hash usa src_address */
static unsigned int nlmatrix_SD_localiza(const in_addr_t src_address, const in_addr_t dest_address)
{
	unsigned int i = 0;	    /* offset da hash */
	unsigned int hash_index;

	HASH(src_address, i, hash_index);
	if ((tabela_hash[hash_index] != NULL) &&
			(tabela_hash[hash_index]->source_addr == src_address) &&
			(tabela_hash[hash_index]->destin_addr == dest_address)) {
		/* found! */
		return hash_index;
	}

	i++;
	while (i <= profundidade) {
		HASH(src_address, i, hash_index);
		if ((tabela_hash[hash_index] == NULL) ||
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

	/* clever trick */
	return NLMATRIXSD_TAM;
}


int nlmatrix_SD_insereAtualiza(pedb_t *dados)
{
	/* se a entrada existe, atualizar, caso contrário, criar uma */
	unsigned int i;
	unsigned int indice_entrada;
	unsigned int indice_saida;


	/* estranho.. pq só atualiza entrada de pacotes se o pacote for unicast?? */
	if (dados->is_broadcast == 0) {
		indice_entrada = nlmatrix_SD_localiza(dados->ip_dest, dados->ip_orig);

		/* atualizar/criar ENTRADA de pacotes */
		if (indice_entrada < NLMATRIXSD_TAM) {
#if DEBUG_NLMATRIX_SD == 1
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
#if DEBUG_NLMATRIX_SD == 1
			Debug("inserindo nova (%d)", indice_entrada);
#endif
			i = 0;
			HASH(dados->ip_dest, i, indice_entrada);

			while ((i < NLMATRIXSD_MAX) && (tabela_hash[indice_entrada] != NULL)) {
				i++;
				HASH(dados->ip_dest, i, indice_entrada);
			}
			if (i >= NLMATRIXSD_MAX) {
				Debug("tabela cheia - descartando");
				return ERROR_FULL;
			}
			if (i > profundidade) {
				profundidade = i;
			}

			/* criar a entrada */
			tabela_hash[indice_entrada] = malloc(sizeof(nlmatrix_t));
#if PLEASE_CHECK_FOR_ERRORS == 1
			if (tabela_hash[indice_entrada] == NULL) {
				Debug("erro no malloc!");
				return ERROR_MALLOC;
			}
#endif
			tabela_hash[indice_entrada]->localindex = dados->nl_localindex;
			tabela_hash[indice_entrada]->pkts = 1;
			tabela_hash[indice_entrada]->octets = dados->tamanho;

			tabela_hash[indice_entrada]->create_time = dados->uptime;

#ifdef USE_TIMEFILTER
			tabela_hash[indice_entrada]->timemark = dados->uptime;
#else
			tabela_hash[indice_entrada]->timemark = 0;
#endif

			tabela_hash[indice_entrada]->source_addr = dados->ip_dest;
			tabela_hash[indice_entrada]->destin_addr = dados->ip_orig;

			tabela_hash[indice_entrada]->hlmatrix_index = dados->interface;

			/* atualizar NlInserts na HlHost */
			if (hlmatrix_atualizaNlInserts(dados->interface) != SUCCESS) {
				Debug("hlmatrix_atualizaNlInserts(%d) falhou",
						dados->interface);
			}

			if (lista_insere(indice_entrada) != SUCCESS) {
				Debug("lista_insere() falhou");
			}

			quantidade++;
		}
	}

#if 0
	/* atualizar/criar SAIDA de pacotes */
	indice_saida = nlmatrix_SD_localiza(dados->ip_orig, dados->ip_dest);
	if (indice_saida < NLMATRIXSD_TAM) {
#if DEBUG_NLMATRIX_SD == 1
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
#if DEBUG_NLMATRIX_SD == 1
		Debug("inserindo nova (%d)", indice_saida);
#endif
		i = 0;
		HASH(dados->ip_orig, i, indice_saida);
		while ((i < NLMATRIXSD_MAX) && (tabela_hash[indice_saida] != NULL)) {
			i++;
			HASH(dados->ip_orig, i, indice_saida);
		}
		if (i >= NLMATRIXSD_MAX) {
			Debug("tabela cheia - descartando");
			return ERROR_FULL;
		}
		if (i > profundidade) {
			profundidade = i;
		}

		/* criar a entrada */
		tabela_hash[indice_saida] = malloc(sizeof(nlmatrix_t));
#if PLEASE_CHECK_FOR_ERRORS == 1
		if (tabela_hash[indice_saida] == NULL) {
			Debug("erro no malloc!");
			return ERROR_MALLOC;
		}
#endif
		tabela_hash[indice_saida]->localindex = dados->nl_localindex;
		tabela_hash[indice_saida]->pkts = 1;
		tabela_hash[indice_saida]->octets = dados->tamanho;

		tabela_hash[indice_saida]->create_time = dados->uptime;

#ifdef USE_TIMEFILTER
		tabela_hash[indice_saida]->timemark = dados->uptime;
#else
		tabela_hash[indice_saida]->timemark = 0;
#endif

		tabela_hash[indice_saida]->source_addr = dados->ip_orig;
		tabela_hash[indice_saida]->destin_addr = dados->ip_dest;

		tabela_hash[indice_saida]->hlmatrix_index = dados->interface;

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


void nlmatrix_SD_hashStats()
{
	Debug("entradas: %d, profundidade: %d", quantidade, profundidade);
}


/*
 *  function to build the indexing
 *  hlMatrixControlIndex.nlMatrixSDTimeMark.protocolDirLocalIndex
 *  .nlMatrixSDSourceAddress.nlMatrixSDDestAddress
 */
int nlmatrix_sd_helper(const unsigned int indice, uint32_t tripa[])
{
	if ((indice < NLMATRIXSD_TAM) && (tabela_hash[indice] != NULL)) {
		tripa[0] = tabela_hash[indice]->hlmatrix_index;
		tripa[1] = tabela_hash[indice]->timemark;
		tripa[2] = tabela_hash[indice]->localindex;
		tripa[3] = tabela_hash[indice]->source_addr;
		tripa[4] = tabela_hash[indice]->destin_addr;

		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
 *  functions to prepare and traverse the index list
 */
int nlmatrix_sd_tabela_prepara(unsigned int *ptr)
{
	if (lista_primeiro() == SUCCESS) {
		*ptr = lista_atual->indice;
		return SUCCESS;
	}
	else {
		*ptr = NLMATRIXSD_TAM;
		return ERROR_INDEXLIST;
	}
}


int nlmatrix_sd_tabela_proximo(unsigned int *ptr)
{
	if (lista_proximo() == SUCCESS) {
		*ptr = lista_atual->indice;
		return SUCCESS;
	}
	else {
		*ptr = NLMATRIXSD_TAM;
		return ERROR_INDEXLIST;
	}
}


int nlmatrix_sd_testa(const unsigned int indice)
{
	if ((indice < NLMATRIXSD_TAM) && (tabela_hash[indice] != NULL)) {
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
 *  functions to retrieve data
 */
int nlmatrix_sd_busca_pkts(const unsigned int indice, uint32_t *ptr)
{
	if ((indice < NLMATRIXSD_TAM) && (tabela_hash[indice] != NULL)) {
		*ptr = tabela_hash[indice]->pkts;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int nlmatrix_sd_busca_octets(const unsigned int indice, uint32_t *ptr)
{
	if ((indice < NLMATRIXSD_TAM) && (tabela_hash[indice] != NULL)) {
		*ptr = tabela_hash[indice]->octets;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int nlmatrix_sd_busca_createtime(const unsigned int indice, uint32_t *ptr)
{
	if ((indice < NLMATRIXSD_TAM) && (tabela_hash[indice] != NULL)) {
		*ptr = tabela_hash[indice]->create_time;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}

