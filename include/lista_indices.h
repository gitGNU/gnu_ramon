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

/* Lista Encadeada de Índices de 32bits
 *
 *   Define o tipo básico (nodo da lista) e operações.
 */

#ifndef __LISTA_ST
#define __LISTA_ST
typedef struct Lista_st {
	unsigned int    indice; /* índice da entrada correspondente */
	struct Lista_st *prox;  /* ponteiro para o próximo nodo da lista */
} lista_t;

#endif /* __LISTA_ST */


/* lista encadeada */
static lista_t		*lista_cabeca = NULL;	/* inicio da lista */
static lista_t		*lista_atual = NULL;	/* posicao para LEITURA */
static unsigned int	lista_qtd = 0;		/* número de elementos */


/* Lista Encadeada ************************************************************/
static int lista_insere(const unsigned int indice)
{
	lista_t *aloca_ptr;

	aloca_ptr = malloc(sizeof(lista_t));
	if (aloca_ptr == NULL) {
		return ERROR_MALLOC;
	}

	aloca_ptr->indice = indice;

	if (lista_qtd) {
		/* lista possui 1+ elementos */
		aloca_ptr->prox = lista_cabeca;
	}
	else {
		/* primeiro elemento */
		aloca_ptr->prox = NULL;
	}

	/* inserir no inicio */
	lista_cabeca = aloca_ptr;
	lista_qtd++;

	return SUCCESS;
}


#if QUERO_REMOVER
static int lista_remove_indice(const unsigned int indice)
{
	lista_t     *acha_ptr;
	lista_t     *anterior_ptr;

	if (lista_qtd > 1) {
		acha_ptr = anterior_ptr = lista_cabeca;
		/* percorre */
		while ((acha_ptr->indice != indice) && (acha_ptr->prox != NULL)) {
			anterior_ptr = acha_ptr;
			acha_ptr = acha_ptr->prox;
		}

		if (acha_ptr->indice != indice) {
			return ERROR_NOSUCHENTRY;
		}

		if (acha_ptr != anterior_ptr) {
			/* achou e não é no início */
			anterior_ptr->prox = acha_ptr->prox;
		}
		else {
			/* achou no início */
			lista_cabeca = acha_ptr->prox;
		}

		free(acha_ptr);
	}

	if ((lista_qtd == 1) && (lista_cabeca->indice == indice)) {
		/* remover o único elemento */
		free(lista_cabeca);
		lista_cabeca = NULL;
		lista_qtd = 0;

		return SUCCESS;
	}

	/* lista possui elemento unico que nao confere OU nao possui elementos */
	return ERROR_NOSUCHENTRY;
}
#endif /* QUERO_REMOVER */


#if QUERO_DESTRUIR
static int lista_destroi()
{
	lista_t *mata_ptr = lista_cabeca;
	lista_t *back_ptr = lista_cabeca;

	while (back_ptr != NULL) {
		back_ptr = back_ptr->prox;
		free(mata_ptr);
		mata_ptr = back_ptr;
	}

	lista_cabeca = lista_final = NULL;

	return SUCCESS;
}
#endif /* QUERO_DESTRUIR */


#if QUERO_PRIMEIRO
static int lista_primeiro()
{
	if (lista_cabeca != NULL) {
		lista_atual = lista_cabeca;
		return SUCCESS;
	}
	else {
		return ERROR_EMPTY;
	}
}
#endif /* QUERO_PRIMEIRO */


#if QUERO_PROXIMO
static int lista_proximo()
{
	if (lista_atual != NULL) {
		if (lista_atual->prox != NULL) {
			/* existe um próximo elemento */
			lista_atual = lista_atual->prox;
			return SUCCESS;
		}
		else {
			/* o elemento atual é o último */
			return ERROR_LASTENTRY;
		}
	}
	else {
		if (lista_cabeca != NULL) {
			/* inicializar */
			lista_atual = lista_cabeca;
			return SUCCESS;
		}
		else {
			return ERROR_EMPTY;
		}
	}
}
#endif /* QUERO_PROXIMO */

