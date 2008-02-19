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
#include "alhost.h"
#include "hlhost.h"
#include "exit_codes.h"
#include "log.h"


/* local defines */
#define ALHOST_MAX  65536
#define ALHOST_TAM  PRIMO


static alhost_t	    *tabela_hash[ALHOST_TAM] = {NULL, };
static unsigned int quantidade = 0;	    /* quantidade de entradas na tabela */
static unsigned int profundidade = 0;	    /* maior profundidade (limite de busca) */


#define QUERO_PROXIMO	1
#define	QUERO_PRIMEIRO	1
#undef	QUERO_REMOVER
#include "lista_indices.h"


unsigned int alhost_quantidade()
{
    return quantidade;
}


static unsigned int alhost_localiza(const unsigned int chave,
		const in_addr_t address, const uint32_t portas)
{
	unsigned int i = 0;		/* offset da hash */
	unsigned int hash_index;	// = hash(chave, i);

	/* compute the hash and try to access */
	HASH(chave, i, hash_index);
	if ((tabela_hash[hash_index] != NULL) &&
			(tabela_hash[hash_index]->nlhost_address == address) &&
			(tabela_hash[hash_index]->portas == portas)) {
		/* Whee! found! */
		return hash_index;
	}

	/* not found in the first try, so we start the probing */
	i++;
	while (i <= profundidade) {
		HASH(chave, i, hash_index);
		if ((tabela_hash[hash_index] == NULL) ||
				(tabela_hash[hash_index]->nlhost_address != address) ||
				(tabela_hash[hash_index]->portas != portas)) {
			/* nao encontrou a entrada - tentar a proxima hash */
			i++;
		}
		else {
			/* achou. tomara ;) */
			return hash_index;
		}
	}

	/* we cannot return a negative number, so... */
	return ALHOST_TAM;
}


int alhost_insereAtualiza(pedb_t *dados)
{
	/* será usado também como verificação da posição na tabela */
	uint32_t	    portas = (dados->nl_localindex << 16) | dados->al_localindex;

	uint32_t	    chave_entrada = dados->ip_dest ^ portas;
	uint32_t	    chave_saida = dados->ip_orig ^ portas;

	unsigned int    indice_saida;
	unsigned int    indice_entrada;
	unsigned int    i;


	if (dados->is_broadcast == 0) {
		/* atualizar/criar ENTRADA de pacotes */
		indice_entrada = alhost_localiza(chave_entrada, dados->ip_dest, portas);

		if (indice_entrada != ALHOST_TAM) {
#if DEBUG_ALHOST == 1
			Debug("atualizando (%u)\n", indice_entrada);
#endif
			tabela_hash[indice_entrada]->in_pkts++;
			tabela_hash[indice_entrada]->in_octets += dados->tamanho;

#ifdef USE_TIMEFILTER
			tabela_hash[indice_entrada]->timemark = dados->uptime;
#endif
		}
		else {
			/* alocar uma posição na tabela */
			i = 0;
			HASH(chave_entrada, i, indice_entrada);

			/* TODO: verificar se essa ordem é boa (nlhost_tam)(* != NULL) */
			while ((i < ALHOST_MAX) && (tabela_hash[indice_entrada] != NULL)) {
				i++;
				HASH(chave_entrada, i, indice_entrada);
			}
			if (i >= ALHOST_MAX) {
				Debug("tabela cheia (%u/%u) - descartando",
						quantidade, ALHOST_MAX);
				return ERROR_FULL;
			}
			if (i > profundidade) {
				profundidade = i;
			}

			/* criar a entrada */
			tabela_hash[indice_entrada] = calloc(1, sizeof(alhost_t));
#if PLEASE_CHECK_FOR_ERRORS == 1
			if (tabela_hash[indice_entrada] == NULL) {
				Debug("Error in input entry memory allocation!");
				return ERROR_MALLOC;
			}
#endif
#if DEBUG_ALHOST == 1
			Debug("inserindo (%u)", indice_entrada);
#endif
			tabela_hash[indice_entrada]->nlhost_address = dados->ip_dest;
			tabela_hash[indice_entrada]->portas = portas;
			tabela_hash[indice_entrada]->localindex_app = dados->al_localindex;
			tabela_hash[indice_entrada]->localindex_net = dados->nl_localindex;
			tabela_hash[indice_entrada]->in_pkts = 1;
			tabela_hash[indice_entrada]->in_octets = dados->tamanho;
			tabela_hash[indice_entrada]->hlhost_index = dados->interface;

			/* zerar os de saida, ainda nao registrados */
			tabela_hash[indice_entrada]->out_pkts = 0;
			tabela_hash[indice_entrada]->out_octets = 0;
			tabela_hash[indice_entrada]->create_time = dados->uptime;

#ifdef USE_TIMEFILTER
			tabela_hash[indice_entrada]->timemark = dados->uptime;
#else
			tabela_hash[indice_entrada]->timemark = 0;
#endif

			/* atualizar hlhost */
			if (hlhost_atualizaAlInserts(dados->interface) != SUCCESS) {
				Debug("hlhost_atualizaAlInserts(%d) falhou",
						dados->interface);
			}

			if (lista_insere(indice_entrada) != SUCCESS) {
				Debug("lista_insere() falhou");
			}
			quantidade++;
		}
	}

	/* atualizar/criar SAIDA de pacotes */
	indice_saida = alhost_localiza(chave_saida, dados->ip_orig, portas);
	if (indice_saida != ALHOST_TAM) {
#if DEBUG_ALHOST == 1
		Debug("atualizando (%u)\n", indice_saida);
#endif
		tabela_hash[indice_saida]->out_pkts++;
		tabela_hash[indice_saida]->out_octets += dados->tamanho;

#ifdef USE_TIMEFILTER
		tabela_hash[indice_saida]->timemark = dados->uptime;
#endif
	}
	else {
		/* alocar uma posição na tabela */
		i = 0;
		HASH(chave_saida, i, indice_saida);

		while ((i < ALHOST_MAX) && (tabela_hash[indice_saida] != NULL)) {
			i++;
			HASH(chave_saida, i, indice_saida);
		}
		if (i >= ALHOST_MAX) {
			Debug("tabela cheia (%u/%u) - descartando",
					quantidade, ALHOST_MAX);
			return ERROR_FULL;
		}
		if (i > profundidade) {
			profundidade = i;
		}

		/* criar a entrada */
		tabela_hash[indice_saida] = calloc(1, sizeof(alhost_t));
#if PLEASE_CHECK_FOR_ERRORS == 1
		if (tabela_hash[indice_saida] == NULL) {
			Debug("Error in output entry memory allocation!");
			return ERROR_MALLOC;
		}
#endif
#if DEBUG_ALHOST == 1
		Debug("inserindo (%u)", indice_saida);
#endif
		tabela_hash[indice_saida]->nlhost_address = dados->ip_orig;
		tabela_hash[indice_saida]->portas = portas;
		tabela_hash[indice_saida]->localindex_app = dados->al_localindex;
		tabela_hash[indice_saida]->localindex_net = dados->nl_localindex;
		tabela_hash[indice_saida]->out_pkts = 1;
		tabela_hash[indice_saida]->out_octets = dados->tamanho;
		tabela_hash[indice_saida]->in_pkts = 0;
		tabela_hash[indice_saida]->in_octets = 0;
		tabela_hash[indice_saida]->hlhost_index = dados->interface;

		tabela_hash[indice_saida]->create_time = dados->uptime;

#ifdef USE_TIMEFILTER
		tabela_hash[indice_saida]->timemark = dados->uptime;
#else
		tabela_hash[indice_saida]->timemark = 0;
#endif

		/* atualiza hlhost */
		if (hlhost_atualizaAlInserts(dados->interface) != SUCCESS) {
			Debug("hlhost_atualizaAlInserts(%d) falhou",
					dados->interface);
		}

		if (lista_insere(indice_saida) != SUCCESS) {
			Debug("lista_insere() falhou");
		}

		quantidade++;
	}

	return SUCCESS;
}


/*
   remove todas as entradas relacionadas com o encapsulamento sendo removido
   pela protocolDir
   */
int alhost_remove_pdir(const unsigned int pdir_localindex)
{
	/* FIXME!!! code me, na verdade */
	return ERROR_NEEDCODING;
}


/**
 * Copy data of the desired entry:
 *
 * hlHostControlIndex.
 *   alHostTimeMark.
 *   protocolDirLocalIndexNet.
 *   nlHostAddress.
 *   protocolDirLocalIndexApp
 */
int alhost_helper(const unsigned int indice, uint32_t *hlcindex,
		uint32_t *al_tmark, uint32_t *plindex_nl, uint32_t *nl_address,
		uint32_t *plindex_al)
{
	if (tabela_hash[indice] != NULL) {
		*hlcindex = tabela_hash[indice]->hlhost_index;
		*al_tmark = tabela_hash[indice]->timemark;
		*plindex_nl = tabela_hash[indice]->localindex_net;
		*nl_address = tabela_hash[indice]->nlhost_address;
		*plindex_al = tabela_hash[indice]->localindex_app;

		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/**
 * Prepare a list for chained traversal.
 *
 * This function is called to prepare the list with elements from the hashtable,
 * and return the index of the first element.
 */
int alhost_tabela_prepara(unsigned int *ptr)
{
	if (lista_primeiro() == SUCCESS) {
		*ptr = lista_atual->indice;
		return SUCCESS;
	}
	else {
		/* in the case the caller doesnt check return codes, we pass a surely
		   invalid index */
		*ptr = ALHOST_TAM;
		return ERROR_INDEXLIST;
	}
}


/**
 * Get the index of the next element in the list.
 */
int alhost_tabela_proximo(unsigned int *ptr)
{
	if (lista_proximo() == SUCCESS) {
		*ptr = lista_atual->indice;
		return SUCCESS;
	}
	else {
		*ptr = ALHOST_TAM;
		return ERROR_INDEXLIST;
	}
}


/**
 * Tests if the desired index is valid within the hashtable.
 */
int alhost_testa(const unsigned int indice)
{
	if ((indice < ALHOST_TAM) && (tabela_hash[indice] != NULL)) {
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/**
 * Copy InPkts to the <tt>ptr</tt> pointer.
 */
int alhost_busca_inpkts(const unsigned int indice, uint32_t *ptr)
{
	if ((indice < ALHOST_TAM) && (tabela_hash[indice] != NULL)) {
		*ptr = tabela_hash[indice]->in_pkts;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/**
 * Copy OutPkts to the <tt>ptr</tt> pointer.
 */
int alhost_busca_outpkts(const unsigned int indice, uint32_t *ptr)
{
	if ((indice < ALHOST_TAM) && (tabela_hash[indice] != NULL)) {
		*ptr = tabela_hash[indice]->out_pkts;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/**
 * Copy InOctets to the <tt>ptr</tt> pointer.
 */
int alhost_busca_inoctets(const unsigned int indice, uint32_t *ptr)
{
	if ((indice < ALHOST_TAM) && (tabela_hash[indice] != NULL)) {
		*ptr = tabela_hash[indice]->in_octets;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/**
 * Copy OutOctets to the <tt>ptr</tt> pointer.
 */
int alhost_busca_outoctets(const unsigned int indice, uint32_t *ptr)
{
	if ((indice < ALHOST_TAM) && (tabela_hash[indice] != NULL)) {
		*ptr = tabela_hash[indice]->out_octets;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/**
 * Copy CreateTime to the <tt>ptr</tt> pointer.
 */
int alhost_busca_createtime(const unsigned int indice, uint32_t *ptr)
{
	if ((indice < ALHOST_TAM) && (tabela_hash[indice] != NULL)) {
		*ptr = tabela_hash[indice]->create_time;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}

