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

#include <time.h>	    // time_t
#include <netinet/in.h>	    // in_addr_t
#include <stdint.h>	    // uint32_t
#include <stdio.h>	    // fprintf
#include <stdlib.h>	    // malloc

#include "configuracao.h"
#include "exit_codes.h"

#include "primo.h"
#include "funcao_hash.h"

#if PTSL
#include "stateful.h"
#endif

#include "pedb.h"
#include "hlhost.h"
#include "nlhost.h"


/* these are needed only here */
#define NLHOST_MAX  65536   /* maximum entries number */
#define NLHOST_TAM  PRIMO   /* hash table size */


static nlhost_t	    *tabela_hash[NLHOST_TAM] = {NULL, };
static unsigned int quantidade = 0;	// quantidade de entradas na tabela
static unsigned int profundidade = 0;   // maior profundidade (limite de busca)

static char	    urgent_color_string[] = "\033[1;41;37m"; // texto branco com fundo vermelho
static char	    reset_color_string[]  = "\033[0m";


#define QUERO_PROXIMO	1
#define QUERO_PRIMEIRO	1
#undef	QUERO_REMOVER
#include "lista_indices.h"


unsigned int nlhost_quantidade()
{
	return quantidade;
}


static unsigned int nlhost_localiza(const uint32_t address)
{
	unsigned int i = 0;		/* offset da hash */
	unsigned int hash_index;	// = hash(address, i);

	/* compute hash and try to access */
	HASH(address, i, hash_index);
	if ((tabela_hash[hash_index] != NULL) &&
			(tabela_hash[hash_index]->address == address)) {
		/* found! */
		return hash_index;
	}

	/* not found in the first try - start probing */
	i++;
	while (i <= profundidade) {
		HASH(address, i, hash_index);
		if ((tabela_hash[hash_index] == NULL) ||
				(tabela_hash[hash_index]->address != address)) {
			/* nao encontrou */
			i++;
		}
		else {
			/* encontrou a entrada */
			return hash_index;
		}
	}

	/* we can't return a negative number, so we return table's size */
	return NLHOST_TAM;
}


int nlhost_insereAtualiza(pedb_t *dados)
{
	/* se a entrada existe, atualizar, caso contrário, criar uma */
	unsigned int i;
	unsigned int indice_entrada;
	unsigned int indice_saida;

	/* estranho.. pq só atualiza entrada de pacotes se o pacote for unicast?? */
	if (dados->is_broadcast == 0) {
		indice_entrada = nlhost_localiza(dados->ip_dest);

		/* atualizar/criar ENTRADA de pacotes */
		if (indice_entrada != NLHOST_TAM) {
#if DEBUG_NLHOST == 1
			fprintf(stderr, "nlhost[entrada]: atualizando (%d)\n", indice_entrada);
#endif
			tabela_hash[indice_entrada]->in_pkts++;
			tabela_hash[indice_entrada]->in_octets += dados->tamanho;

#ifdef USE_TIMEFILTER
			tabela_hash[indice_entrada]->timemark = dados->uptime;
#endif
		}
		else {
			/* alocar uma posição na tabela */
#if DEBUG_NLHOST == 1
			fprintf(stderr, "nlhost[entrada]: inserindo nova (%d)\n", indice_entrada);
#endif
			i = 0;
			HASH(dados->ip_dest, i, indice_entrada);

			while ((i < NLHOST_MAX) && (tabela_hash[indice_entrada] != NULL)) {
				i++;
				HASH(dados->ip_dest, i, indice_entrada);
			}
			if (i >= NLHOST_MAX) {
				fprintf(stderr, "%snlhost: tabela cheia (%u/%u) - descartando%s\n",
						urgent_color_string, quantidade, NLHOST_MAX, reset_color_string);
				return ERROR_FULL;
			}
			if (i > profundidade) {
				profundidade = i;
			}

			/* criar a entrada */
			tabela_hash[indice_entrada] = calloc(1, sizeof(nlhost_t));
#if PLEASE_CHECK_FOR_ERRORS == 1
			if (tabela_hash[indice_entrada] == NULL) {
				fprintf(stderr, "%snlhost.c: Error in hash entry memory allocation!%s\n", urgent_color_string,
						reset_color_string);
				return ERROR_MALLOC;
			}
#endif
			tabela_hash[indice_entrada]->create_time = dados->uptime;

#ifdef USE_TIMEFILTER
			tabela_hash[indice_entrada]->timemark = dados->uptime;
#else
			tabela_hash[indice_entrada]->timemark = 0;
#endif

			tabela_hash[indice_entrada]->localindex = dados->nl_localindex;
			tabela_hash[indice_entrada]->hlhost_index = dados->interface;
			tabela_hash[indice_entrada]->in_pkts = 1;
			tabela_hash[indice_entrada]->in_octets = dados->tamanho;

			/* zerar os de saida, ainda nao registrados */
			tabela_hash[indice_entrada]->out_pkts =
				tabela_hash[indice_entrada]->out_octets =
				tabela_hash[indice_entrada]->out_macbroadcast_pkts = 0;

			tabela_hash[indice_entrada]->address = dados->ip_dest;

			/* atualizar NlInserts na HlHost */
			if (hlhost_atualizaNlInserts(dados->interface) != SUCCESS) {
				fprintf(stderr, "%snlhost[entrada]: hlhost_atualizaNlInserts(%d) falhou%s\n",
						urgent_color_string, dados->interface, reset_color_string);
			}

			if (lista_insere(indice_entrada) != SUCCESS) {
				fprintf(stderr, "%snlhost[entrada]: lista_insere() falhou%s\n",
						urgent_color_string, reset_color_string);
			}

			quantidade++;
		}
	}

	/* atualizar/criar SAIDA de pacotes */
	indice_saida = nlhost_localiza(dados->ip_orig);
	if (indice_saida != NLHOST_TAM) {
#if DEBUG_NLHOST == 1
		fprintf(stderr, "nlhost[saida]: updating (%d)\n", indice_saida);
#endif
		tabela_hash[indice_saida]->out_pkts++;
		tabela_hash[indice_saida]->out_octets += dados->tamanho;
		if (dados->is_broadcast != 0) {
			tabela_hash[indice_saida]->out_macbroadcast_pkts++;
		}

#ifdef USE_TIMEFILTER
		tabela_hash[indice_saida]->timemark = dados->uptime;
#endif
	}
	else {
		/* alocar uma posição na tabela */
#if DEBUG_NLHOST == 1
		fprintf(stderr, "nlhost[saida]: inserindo nova (%d)\n", indice_saida);
#endif
		i = 0;
		HASH(dados->ip_orig, i, indice_saida);

		while ((i < NLHOST_MAX) && (tabela_hash[indice_saida] != NULL)) {
			i++;
			HASH(dados->ip_orig, i, indice_saida);
		}
		if (i >= NLHOST_MAX) {
			fprintf(stderr, "%snlhost.c: Table full (%u/%u) - discarding data%s\n",
					urgent_color_string, quantidade, NLHOST_MAX, reset_color_string);
			return ERROR_FULL;
		}
		if (i > profundidade) {
			profundidade = i;
		}

		/* criar a entrada */
		tabela_hash[indice_saida] = calloc(1, sizeof(nlhost_t));
#if PLEASE_CHECK_FOR_ERRORS == 1
		if (tabela_hash[indice_saida] == NULL) {
			fprintf(stderr, "%snlhost.c: Error in hash entry memory allocation!%s\n", urgent_color_string,
					reset_color_string);
			return ERROR_MALLOC;
		}
#endif
		tabela_hash[indice_saida]->create_time = dados->uptime;

#ifdef USE_TIMEFILTER
		tabela_hash[indice_saida]->timemark = dados->uptime;
#else
		tabela_hash[indice_saida]->timemark = 0;
#endif

		tabela_hash[indice_saida]->localindex = dados->nl_localindex;
		tabela_hash[indice_saida]->hlhost_index = dados->interface;
		tabela_hash[indice_saida]->out_pkts = 1;
		tabela_hash[indice_saida]->out_octets = dados->tamanho;
		if (dados->is_broadcast != 0) {
			tabela_hash[indice_saida]->out_macbroadcast_pkts = 1;
		}
		else {
			tabela_hash[indice_saida]->out_macbroadcast_pkts = 0;
		}

		/* zerar os de entrada, ainda nao registrados */
		tabela_hash[indice_saida]->in_pkts =
			tabela_hash[indice_saida]->in_octets = 0;

		tabela_hash[indice_saida]->address = dados->ip_orig;

		/* atualizar NlInserts na HlHost */
		if (hlhost_atualizaNlInserts(dados->interface) != SUCCESS) {
			fprintf(stderr, "%snlhost[saída]: hlhost_atualizaNlInserts(%d) falhou%s\n",
					urgent_color_string, dados->interface, reset_color_string);
		}

		if (lista_insere(indice_saida) != SUCCESS) {
			fprintf(stderr, "%snlhost[saida]: lista_insere() falhou%s\n",
					urgent_color_string, reset_color_string);
		}

		quantidade++;
	}

	return SUCCESS;
}

/*
 * Function that removes an entry into the Hash table.
 */
int nlhost_remove_pdir(const unsigned int pdir_localindex)
{
	/* FIXME!!! */
	if (pdir_localindex <= NLHOST_TAM) {
		tabela_hash[pdir_localindex]->address = 0;
		tabela_hash[pdir_localindex]->localindex = 0;
		tabela_hash[pdir_localindex]->hlhost_index = 0;
		tabela_hash[pdir_localindex]->in_pkts = 0;
		tabela_hash[pdir_localindex]->in_octets = 0;
		tabela_hash[pdir_localindex]->out_pkts = 0;
		tabela_hash[pdir_localindex]->out_octets = 0;
		tabela_hash[pdir_localindex]->out_macbroadcast_pkts = 0;
		tabela_hash[pdir_localindex]->timemark = 0;
		tabela_hash[pdir_localindex]->create_time = 0;
		free(tabela_hash[pdir_localindex]);
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


void nlhost_hashStats()
{
	fprintf(stderr, "NlHost:\n   > Entradas: %d   Profundidade: %d\n",
			quantidade, profundidade);
}


int nlhost_helper(const unsigned int index, uint32_t *hlcindex,
		uint32_t *nl_tmark, uint32_t *p_lindex, uint32_t *nl_address)
{
	if (tabela_hash[index] != NULL) {
		*hlcindex = tabela_hash[index]->hlhost_index;
		*nl_tmark = tabela_hash[index]->timemark;
		*p_lindex = tabela_hash[index]->localindex;
		*nl_address = tabela_hash[index]->address;

		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
 *  sort the index list and copy the first index to the caller's pointer
 *  returns a state (success or error)
 */
int nlhost_tabela_prepara(unsigned int *ptr)
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
 *  copy the next index (if exists) to the caller's pointer
 *  returns a state (success or error)
 */
int nlhost_tabela_proximo(unsigned int *ptr)
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
 *  tests an entry, returning a state (success or error)
 */
int nlhost_tabela_testa(const unsigned int index)
{
	if ((index < NLHOST_TAM) && (tabela_hash[index] != NULL)) {
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
 *  functions to retrieve data of a specified index
 */
int nlhost_busca_inpkts(const unsigned int index, uint32_t *ptr)
{
	if ((index < NLHOST_TAM) && (tabela_hash[index] != NULL)) {
		*ptr = tabela_hash[index]->in_pkts;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int nlhost_busca_outpkts(const unsigned int index, uint32_t *ptr)
{
	if ((index < NLHOST_TAM) && (tabela_hash[index] != NULL)) {
		*ptr = tabela_hash[index]->out_pkts;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int nlhost_busca_inoctets(const unsigned int index, uint32_t *ptr)
{
	if ((index < NLHOST_TAM) && (tabela_hash[index] != NULL)) {
		*ptr = tabela_hash[index]->in_octets;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int nlhost_busca_outoctets(const unsigned int index, uint32_t *ptr)
{
	if ((index < NLHOST_TAM) && (tabela_hash[index] != NULL)) {
		*ptr = tabela_hash[index]->out_octets;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int nlhost_busca_outmacnonunicast(const unsigned int index, uint32_t *ptr)
{
	if ((index < NLHOST_TAM) && (tabela_hash[index] != NULL)) {
		*ptr = tabela_hash[index]->out_macbroadcast_pkts;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int nlhost_busca_createtime(const unsigned int index, uint32_t *ptr)
{
	if ((index < NLHOST_TAM) && (tabela_hash[index] != NULL)) {
		*ptr = tabela_hash[index]->create_time;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}

