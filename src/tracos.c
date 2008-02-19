/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2004, 2008  Ricardo Nabinger Sanchez
 * Copyright (C) 2004  Diego Wentz Antunes
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

/** \file tracos.c
 *  \brief Main ID-Trace module, containing most of the protocol trace
 *  handling functions.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <pthread.h>

#include "configuracao.h"
#include "exit_codes.h"
#include "globals.h"
#include "stateful.h"
#include "primo.h"
#include "funcao_hash.h"
#include "pedb.h"
#include "sysuptime.h"
#include "tracos.h"


/** \brief Maximum number of entries in the hash-table. */
#define STATEFUL_MAX	65536
/** \brief Real number of entries in the hash-table
 *
 *  #STATEFUL_TAM must be a \b prime number and 25% greater than #STATEFUL_MAX,
 *  in order to guarantee that the table load will not exceed occupancy factor
 *  of 80% (and keep fast retrieval).
 */
#define STATEFUL_TAM	PRIMO


/** \brief Trace instance hash-table. \hideinitializer */
static instancia_t	tabela[STATEFUL_TAM] = { {0, }, };

/** \brief Hash-table entries counter. \hideinitializer */
static u_int		nr_entradas = 0;

/** \brief Hash-table collisions counter. \hideinitializer*/
static u_int		nr_colisoes = 0;

/** \brief Pointer to the PEDB processed by the packet capture module. \hideinitializer */
static pedb_t		*pedb = NULL;

/** \brief Pointer to the packet data area. \hideinitializer*/
static u_char		*dados_ptr = NULL;

/** \brief Pointer to the state being processed \hideinitializer*/
static estado_t		*estado_pendente_ptr = NULL;

/** \brief Pointer to the trace being processed \hideinitializer*/
static traco_t		*traco_atual_ptr;

/** \brief Pointer to the trace instance being processed \hideinitializer*/
static instancia_t	*instancia_atual_ptr = NULL;

/** \brief Current instance's list head \hideinitializer*/
static li_inst_t	*li_atual_ptr = NULL;

/** \brief Current instance's previous list element \hideinitializer*/
static li_inst_t	*li_prev_ptr = NULL;

/** \brief Hash-table element index being processed or #STATEFUL_TAM (similar to NULL) \hideinitializer*/
static u_int		indice_atual = STATEFUL_TAM;

/** \brief Char strings to convert IP addresses */
static char		str_iporigem[16];
static char		str_ipdestino[16];


#if 0
struct li_traco_s {
    unsigned int	id;
    traco_t		*traco_ptr;
    struct li_traco_s	*prox_ptr;
};
#endif

static struct li_traco_s    *li_tracos_ini = NULL;
static struct li_traco_s    *li_tracos_fim = NULL;
static u_int		    li_tracos_qtd = 0;


/** \brief Character loop-copy internal function.
 *
 *  The purpose of this function is to inline a char-copy routine, avoiding
 *  library calls and maybe loss of code locality.
 *  \param dst Pointer to destination.
 *  \param src Pointer to source.
 *  \param len How many chars to copy from \a src to \a dst.
 */
static void
do_char_memcpy(u_char *dst, u_char *src, unsigned long len)
{
	while (len) {
		len--;
		*dst = *src;
		src++;
		dst++;
	}
}


/** \brief Searches for a trace instance in the hash-table.
 *
 *  \retval index	    If an instance was found.
 *  \retval STATEFUL_TAM    If nothing was found.
 */
static u_int
pend_busca()
{
	unsigned long   chave;
	u_int	    indice;
	u_int	    i;

	chave = pedb->rede_sport + pedb->rede_dport + pedb->ip_orig + pedb->ip_dest;
	HASH(chave, 0, indice);

	if (tabela[indice].nr_inst) {
		/* let's check... */
		if ( (pedb->ip_cliente == tabela[indice].ip_cliente) &&
				(pedb->ip_servidor == tabela[indice].ip_servidor) &&
				(pedb->porta_cliente == tabela[indice].porta_cliente) &&
				(pedb->porta_servidor == tabela[indice].porta_servidor) ) {
			/* found! */
			return (indice);
		}
	}

	/* start loop search */
	i = 1;
	while (i <= nr_colisoes) {
		HASH(chave, i, indice);
		if (tabela[indice].nr_inst) {
			/* let's check... */
			if ( (pedb->ip_cliente == tabela[indice].ip_cliente) &&
					(pedb->ip_servidor == tabela[indice].ip_servidor) &&
					(pedb->porta_cliente == tabela[indice].porta_cliente) &&
					(pedb->porta_servidor == tabela[indice].porta_servidor) ) {
				/* found! */
				return (indice);
			}
		}
		i++;
	}
	/* not found */
	return (STATEFUL_TAM);
}


/** \brief Includes an instance of a protocol trace in the hash-table.
 *
 *  \param *traco   Pointer to a protocol trace.
 *  \param *estado  Pointer to one of its states.  Often this is the next state
 *		    related to the current state, if a transition occured.
 *  \param timeout_ms	How many milliseconds to wait before timing out this instance.
 *  \retval SUCCESS	If no errors.
 *  \retval ERROR_FULL	If hash-table is full.
 *  \retval BUG		If nr_instancias is (probably) corrupted.
 *  \retval TRACE_NULL_ERROR	If \a traco is NULL.
 */
static int
pend_inclui(traco_t *traco, estado_t *estado, const u_int timeout_ms)
{
	unsigned long   chave;
	u_int	    indice;
	u_int	    i = 0;
	li_inst_t	    *ptr;

	chave = pedb->rede_sport + pedb->rede_dport + pedb->ip_orig + pedb->ip_dest;
	indice = pend_busca();

	if (indice == STATEFUL_TAM) {
		HASH(chave, 0, indice);
		if (tabela[indice].nr_inst == 0) {	/* free space */
setup_table_paramenters:
			tabela[indice].nr_inst = 1;
			tabela[indice].li_primeiro = calloc(1, sizeof(li_inst_t));

			tabela[indice].li_primeiro->traco_ptr = traco;
			tabela[indice].li_primeiro->pendente_ptr = estado;

			tabela[indice].ip_cliente = pedb->ip_cliente;
			tabela[indice].ip_servidor = pedb->ip_servidor;
			tabela[indice].porta_cliente = pedb->porta_cliente;
			tabela[indice].porta_servidor = pedb->porta_servidor;

			/* Setup the deadline */
			if (timeout_ms > 0) {
				tabela[indice].li_primeiro->validade_ms = sysuptime_mili() + timeout_ms;
			} else {
				tabela[indice].li_primeiro->validade_ms = 0;
			}

			nr_entradas++;
			if ( (i > nr_colisoes) && (i != 0) ) {
				nr_colisoes = i;
			}

			/*XXX*/
			//	    Debug("pend_inclui - %u/%u: SOURCE= %u:%u, DEST= %u:%u",
			//		nr_entradas, STATEFUL_MAX,
			//		pedb->ip_orig, pedb->rede_sport,
			//		pedb->ip_dest, pedb->rede_dport);

			return (SUCCESS);
		}
		/* Collision detected! */
		i = 1;
		if (nr_entradas < STATEFUL_MAX) {
			HASH(chave, i, indice);
			while ((tabela[indice].nr_inst) && (i < STATEFUL_MAX)) {
				Debug("Colision level: %u", nr_colisoes);
				i++;
				HASH(chave, i, indice);
			}
			if (i < STATEFUL_MAX) {		/* free space found */
				goto setup_table_paramenters;
			} else {
				/* nr_entradas is trashed? */
				return (BUG);
			}
		}
		/* Table full! */
		return (ERROR_FULL);
	} else {
		/*
		 *  there is already an entry, so we will append an additional
		 *  entry to the start of the list
		 */
		ptr = tabela[indice].li_primeiro;

		tabela[indice].li_primeiro = calloc(1, sizeof(li_inst_t));

		tabela[indice].li_primeiro->li_prox = ptr;
		tabela[indice].li_primeiro->pendente_ptr = estado;
		tabela[indice].li_primeiro->traco_ptr = traco;
		tabela[indice].nr_inst++;

		if (timeout_ms > 0) {
			tabela[indice].li_primeiro->validade_ms = sysuptime_mili() + timeout_ms;
		} else {
			tabela[indice].li_primeiro->validade_ms = 0;
		}

		return (SUCCESS);
	}
}


/**
 * \brief Removes an instance from the hash-table
 *  Actually, removes an instance from a linked list \b inside the hash-table.
 *  \bug    For some reason, it doesn't detect errors -- thus, always returns
 *	    SUCCESS, and the agent might crash.
 *  \todo   Fix me!
 */
static int
pend_remove()
{
	li_inst_t *p = li_atual_ptr;

	if (li_prev_ptr != li_atual_ptr) {
		/* not the first */
		li_prev_ptr->li_prox = li_atual_ptr->li_prox;
		li_atual_ptr = li_atual_ptr->li_prox;
	}
	else {
		/* removing the initial node */
		instancia_atual_ptr->li_primeiro = li_atual_ptr->li_prox;
		li_atual_ptr = li_atual_ptr->li_prox;
		li_prev_ptr = li_atual_ptr;
	}

	//    Debug("  +--> removendo instancia %p", p);
	free(p);
	instancia_atual_ptr->nr_inst--;
	nr_entradas--;

	return (SUCCESS);
}


/** \brief Tests a filter.
 *  Tests a filter based on what was set up.
 *  \param msg_ptr  Pointer to a filter descriptor, which contains the needed
 *		    data to do the evalutation.
 *  \retval SUCCESS		Filter found something in the packet.
 *  \retval TRACE_DIRECTION	Packet direction (client/server) doesn't match filter's.
 *  \retval TRACE_MSGNOTFOUND	Filter did not find anything in the packet.
 *  \retval ERROR_EVILVALUE	Some unexpected operation code in the filter was found.
 *  \retval ERROR_NEEDCODING	Not implemented (yet).
 */
static int
testa_mensagem(mensagem_t *msg_ptr)
{
	u_char	    *cru_ptr;
	variavel_t	    *v_ptr;
	u_int	    i,j;

	i = j = 0;

	/*
	 *	check packet direction
	 */
	if (((pedb->direcao != FROM_ANY) && (msg_ptr->direcao != FROM_ANY))
			&& (msg_ptr->direcao != pedb->direcao)) {
		return (TRACE_DIRECTION);
	}

	/*
	 *	decide if we'll use bits or bytes, then the operation type
	 */
	if (msg_ptr->flags.tipo == MSG_BITCT) {
		/*
		 *  message is bitcounter
		 */
		cru_ptr = dados_ptr + (msg_ptr->offset / 8);
		switch (msg_ptr->flags.encaps) {
			case OFF_REDE:
				cru_ptr += pedb->offset_rede;
				break;
			case OFF_TRANSPORTE:
				cru_ptr += pedb->offset_trans;
				break;
			case OFF_APLICACAO:
				cru_ptr += pedb->offset_aplic;
				break;
		}

		switch (msg_ptr->flags.operacao) {
			case OPER_IGUAL:
				switch (msg_ptr->flags.comparacao) {
					case CMP_NENHUMA:
						Debug("comparisson type is none");
						return (ERROR_NEEDCODING);
						break;

						//		    case CMP_CHAVE_E_PACOTE:
						//			i = 0;
						//			while (i < msg_ptr->variavel->tamanho) {
						//			    if ( (cru_ptr[i] & msg_ptr->variavel->mascara[i]) !=
						//				    msg_ptr->chave[i]) {
						//				return TRACE_MSGNOTFOUND;
						//			    }
						//			}
						//			return SUCCESS;
						//			break;

					case CMP_CHAVEPTR_E_PACOTE:
						i = 0;
						while (i < msg_ptr->tam_chave) {
							if ( (cru_ptr[i] & msg_ptr->chave_mask_ptr[i]) !=
									msg_ptr->chave_ptr[i]) {
								return (TRACE_MSGNOTFOUND);
							}
							i++;
						}
						//			Debug("mensagem `%s' encontrada", msg_ptr->ident);
						return (SUCCESS);
						break;

					case CMP_CHAVE_E_VAR:
						return (ERROR_NEEDCODING);
						break;

					case CMP_CHAVE_E_CHAVEPTR:
						return (ERROR_NEEDCODING);
						break;

					case CMP_CHAVEPTR_E_VAR:
						return (ERROR_NEEDCODING);
						break;

					case CMP_VAR_E_PACOTE:
						i = 0;
						while (i < msg_ptr->variavel->tamanho) {
							if ( (cru_ptr[i] & msg_ptr->variavel->mascara[i]) !=
									msg_ptr->variavel->var_ptr[i]) {
								return (TRACE_MSGNOTFOUND);
							}
							i++;
						}
						//			Debug("mensagem `%s' encontrada", msg_ptr->ident);
						break;

					default:
						Debug("unknown comparisson type `%u'", msg_ptr->flags.comparacao);
						return (ERROR_EVILVALUE);
				}
				break;

			case OPER_MAIOR:
				switch (msg_ptr->flags.comparacao) {
					case CMP_NENHUMA:
						Debug("comparisson type is none");
						return (ERROR_NEEDCODING);
						break;

					case CMP_CHAVEPTR_E_PACOTE:
						i = 0;
						while (i < msg_ptr->variavel->tamanho) {
							if ( (cru_ptr[i] & msg_ptr->variavel->mascara[i]) >
									msg_ptr->chave_ptr[i]) {
								return TRACE_MSGNOTFOUND;
							}
						}
						return SUCCESS;
						break;

					case CMP_CHAVEPTR_E_VAR:
						return ERROR_NEEDCODING;
						break;

					case CMP_VAR_E_PACOTE:
						i = 0;
						while (i < msg_ptr->variavel->tamanho) {
							if ( (cru_ptr[i] & msg_ptr->variavel->mascara[i]) >
									msg_ptr->variavel->var_ptr[i]) {
								return TRACE_MSGNOTFOUND;
							}
							i++;
						}
						break;

					default:
						fprintf(stderr,
								"%stracos: testa_mensagem: unknown comparisson type `%u'",
								bug_color_str, msg_ptr->flags.comparacao, bug_nocolor_str);
						return ERROR_EVILVALUE;
				}
				break;

			case OPER_MAIORIGUAL:
				switch (msg_ptr->flags.comparacao) {
					case CMP_NENHUMA:
						Debug("comparisson type is none");
						return ERROR_NEEDCODING;
						break;

					case CMP_CHAVEPTR_E_PACOTE:
						i = 0;
						while (i < msg_ptr->variavel->tamanho) {
							if ( (cru_ptr[i] & msg_ptr->variavel->mascara[i]) >=
									msg_ptr->chave_ptr[i]) {
								return TRACE_MSGNOTFOUND;
							}
						}
						return SUCCESS;
						break;

					case CMP_CHAVEPTR_E_VAR:
						return ERROR_NEEDCODING;
						break;

					case CMP_VAR_E_PACOTE:
						i = 0;
						while (i < msg_ptr->variavel->tamanho) {
							if ( (cru_ptr[i] & msg_ptr->variavel->mascara[i]) >=
									msg_ptr->variavel->var_ptr[i]) {
								return TRACE_MSGNOTFOUND;
							}
							i++;
						}
						break;

					default:
						fprintf(stderr,
								"%stracos: testa_mensagem: unknown comparisson type `%u'",
								bug_color_str, msg_ptr->flags.comparacao, bug_nocolor_str);
						return ERROR_EVILVALUE;
				}
				break;

			case OPER_MENOR:
				switch (msg_ptr->flags.comparacao) {
					case CMP_NENHUMA:
						Debug("comparisson type is none");
						return ERROR_NEEDCODING;
						break;

					case CMP_CHAVEPTR_E_PACOTE:
						i = 0;
						while (i < msg_ptr->variavel->tamanho) {
							if ( (cru_ptr[i] & msg_ptr->variavel->mascara[i]) <
									msg_ptr->chave_ptr[i]) {
								return TRACE_MSGNOTFOUND;
							}
						}
						return SUCCESS;
						break;

					case CMP_CHAVEPTR_E_VAR:
						return ERROR_NEEDCODING;
						break;

					case CMP_VAR_E_PACOTE:
						i = 0;
						while (i < msg_ptr->variavel->tamanho) {
							if ( (cru_ptr[i] & msg_ptr->variavel->mascara[i]) <
									msg_ptr->variavel->var_ptr[i]) {
								return TRACE_MSGNOTFOUND;
							}
							i++;
						}
						break;

					default:
						fprintf(stderr,
								"%stracos: testa_mensagem: unknown comparisson type `%u'",
								bug_color_str, msg_ptr->flags.comparacao, bug_nocolor_str);
						return ERROR_EVILVALUE;
				}
				break;

			case OPER_MENORIGUAL:
				switch (msg_ptr->flags.comparacao) {
					case CMP_NENHUMA:
						Debug("comparisson type is none");
						return ERROR_NEEDCODING;
						break;

					case CMP_CHAVEPTR_E_PACOTE:
						i = 0;
						while (i < msg_ptr->variavel->tamanho) {
							if ( (cru_ptr[i] & msg_ptr->variavel->mascara[i]) <=
									msg_ptr->chave_ptr[i]) {
								return TRACE_MSGNOTFOUND;
							}
						}
						return SUCCESS;
						break;

					case CMP_CHAVEPTR_E_VAR:
						return ERROR_NEEDCODING;
						break;

					case CMP_VAR_E_PACOTE:
						i = 0;
						while (i < msg_ptr->variavel->tamanho) {
							if ( (cru_ptr[i] & msg_ptr->variavel->mascara[i]) <=
									msg_ptr->variavel->var_ptr[i]) {
								return TRACE_MSGNOTFOUND;
							}
							i++;
						}
						break;

					default:
						fprintf(stderr,
								"%stracos: testa_mensagem: unknown comparisson type `%u'",
								bug_color_str, msg_ptr->flags.comparacao, bug_nocolor_str);
						return ERROR_EVILVALUE;
				}
				break;

			case OPER_DIFERENTE:
				switch (msg_ptr->flags.comparacao) {
					case CMP_NENHUMA:
						Debug("comparisson type is none");
						return ERROR_NEEDCODING;
						break;

					case CMP_CHAVEPTR_E_PACOTE:
						i = 0;
						while (i < msg_ptr->variavel->tamanho) {
							if ( (cru_ptr[i] & msg_ptr->variavel->mascara[i]) ==
									msg_ptr->chave_ptr[i]) {
								return TRACE_MSGNOTFOUND;
							}
						}
						return SUCCESS;
						break;

					case CMP_CHAVEPTR_E_VAR:
						return ERROR_NEEDCODING;
						break;

					case CMP_VAR_E_PACOTE:
						i = 0;
						while (i < msg_ptr->variavel->tamanho) {
							if ( (cru_ptr[i] & msg_ptr->variavel->mascara[i]) ==
									msg_ptr->variavel->var_ptr[i]) {
								return TRACE_MSGNOTFOUND;
							}
							i++;
						}
						break;

					default:
						fprintf(stderr,
								"%stracos: testa_mensagem: unknown comparisson type `%u'",
								bug_color_str, msg_ptr->flags.comparacao, bug_nocolor_str);
						return ERROR_EVILVALUE;
				}
				break;

			case OPER_ARMAZENAR:
				v_ptr = msg_ptr->variavel;
				do_char_memcpy(v_ptr->var_ptr, cru_ptr, v_ptr->tamanho);

				/*
				 *  now apply the mask to the last word, so we can compare unaligned
				 *  memory in the future
				 */
				v_ptr->var_ptr[0] = cru_ptr[0] & v_ptr->mascara[0];
				v_ptr->var_ptr[v_ptr->tamanho - 1] =
					cru_ptr[v_ptr->tamanho - 1] & v_ptr->mascara[v_ptr->tamanho - 1];
				break;

			default:
				Debug("unknown operation `%u'",
						msg_ptr->flags.operacao);
				return ERROR_EVILVALUE;
		}
	}
	else {
		/*
		 *  message is fieldcounter or nooffset
		 */
		switch (msg_ptr->flags.operacao) {
		case OPER_IGUAL:
			switch (msg_ptr->flags.comparacao) {
			case CMP_CHAVEPTR_E_PACOTE:
				//			    Debug("i: %u\t j: %u\t tam: %u\tchave: ",
				//				    msg_ptr->offset / 65536, msg_ptr->offset % 65536,
				//				    msg_ptr->tam_chave, msg_ptr->chave_ptr);
				/* FIXME: assumindo (e pulando) ether2.ipv4.tcp.APLIC */
				i = pedb->offset_aplic;
				//			    i = msg_ptr->offset / 65536;
				/* skip non-printable characters */
				while (dados_ptr[i] <= 32) { i++; }
				/*
				 *	OK, we're at the beginning of token 0, hopefully.
				 *	now we skip tokens, if needed.
				 */
				//			    for (j = 0; j < (msg_ptr->offset % 65536); j++) {
				for (j = 0; j < msg_ptr->offset; j++) {
					while (dados_ptr[i] > 32) { i++; }
					while (dados_ptr[i] <= 32) { i++; }
				}
				/*	Now we should be at the correct token -- compare it */
				for (j = 0; j < msg_ptr->tam_chave; j++, i++) {
					//				Debug("(%u[%c], %u[%c])", i, dados_ptr[i], j, msg_ptr->chave_ptr[j]);
					if (dados_ptr[i] != msg_ptr->chave_ptr[j]) {
						return TRACE_MSGNOTFOUND;
					}
				}

				return SUCCESS;
			}
			break;

			case OPER_MAIOR:
				return ERROR_NEEDCODING;
				break;

			case OPER_MAIORIGUAL:
				return ERROR_NEEDCODING;
				break;

			case OPER_MENOR:
				return ERROR_NEEDCODING;
				break;

			case OPER_MENORIGUAL:
				return ERROR_NEEDCODING;
				break;

			case OPER_DIFERENTE:
				return ERROR_NEEDCODING;
				break;

			case OPER_ARMAZENAR:
				return ERROR_NEEDCODING;
				break;

			default:
				Debug("unknown operation `%u'",
						 msg_ptr->flags.operacao);
				return ERROR_EVILVALUE;
			}
		}

		return SUCCESS;
	}
}


/*
 *  function to test a state (estado_pendente_ptr) by testing its messages
 *
 *  assumes:
 *	- estado_pendente_ptr is a valid pointer to a state
 */
static int
testa_estado()
{
	/*
	 *	for each one of the three possible messages, there can be another 3
	 *	`child' messages, which must be tested if SUCCESS.
	 *	FIXME: the `child' messages, for the moment, are ANDed.  in the future
	 *	there should be support for other logical operations.
	 */
	if (estado_pendente_ptr->nr_depende == 1) {
		/*
		 *  test main message
		 */
		if (testa_mensagem(estado_pendente_ptr->depende_0.mensagem) != SUCCESS) {
			return TRACE_MSGNOTFOUND;
		}

		/*
		 *  if existant, test the other (up to 6, yet) messages
		 */
		if (estado_pendente_ptr->depende_0.nr_msg_depende == 1) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_0) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_0.nr_msg_depende == 2) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_1) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_0.nr_msg_depende == 3) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_2) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_0.nr_msg_depende == 4) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_3) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_0.nr_msg_depende == 5) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_4) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_0.nr_msg_depende == 6) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_5) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
	}

	if (estado_pendente_ptr->nr_depende == 2) {
		/*
		 *  test main message
		 */
		if (testa_mensagem(estado_pendente_ptr->depende_1.mensagem) != SUCCESS) {
			return TRACE_MSGNOTFOUND;
		}

		/*
		 *  if existant, test the other (up to 6, yet) messages
		 */
		if (estado_pendente_ptr->depende_1.nr_msg_depende == 1) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_0) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_1.nr_msg_depende == 2) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_1) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_1.nr_msg_depende == 3) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_2) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_1.nr_msg_depende == 4) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_3) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_1.nr_msg_depende == 5) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_4) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_1.nr_msg_depende == 6) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_5) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
	}

	if (estado_pendente_ptr->nr_depende == 3) {
		/*
		 *  test main message
		 */
		if (testa_mensagem(estado_pendente_ptr->depende_2.mensagem) != SUCCESS) {
			return TRACE_MSGNOTFOUND;
		}

		/*
		 *  if existant, test the other (up to 6, yet) messages
		 */
		if (estado_pendente_ptr->depende_2.nr_msg_depende == 1) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_0) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_2.nr_msg_depende == 2) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_1) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_2.nr_msg_depende == 3) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_2) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_2.nr_msg_depende == 4) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_3) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_2.nr_msg_depende == 5) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_4) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
		if (estado_pendente_ptr->depende_2.nr_msg_depende == 6) {
			if (testa_mensagem(estado_pendente_ptr->depende_0.msg_depende_5) != SUCCESS) {
				return TRACE_MSGNOTFOUND;
			}
		}
	}

	return SUCCESS;
}


/**
 * Verifica a lista de pendencias e faz a remocao destas baseando-se nos Timeouts!!
 */
void *
tracos_check_remove_pend()
{
	unsigned long   chave;
	unsigned long   actual_time;
	u_int	    indice, i;
	li_inst_t	    *instPtr;
	estado_t	    *statePtr;

	indice = i = 0;

#if DEBUG
	Debug("Running with PID: %d", getpid());
#endif

	chave = pedb->rede_sport + pedb->rede_dport + pedb->ip_orig + pedb->ip_dest;
	indice = pend_busca();
	/*	Preciso varrer a tabela a procura de pendencias. Quando encontrar
	 *	uma devo verificar o timeout e em caso afirmativo, devo eliminar
	 *	a pendencia.
	 */
	if (indice == STATEFUL_TAM) { /* Nenhuma entrada */
		HASH(chave, i, indice);
		if (tabela[indice].nr_inst != 0) {
			instPtr = tabela[indice].li_primeiro;
			statePtr = instPtr->pendente_ptr;

			actual_time = sysuptime_mili();

			if (statePtr->nr_depende == 1) {
				if (testa_mensagem(statePtr->depende_0.mensagem) != SUCCESS) {
					Debug("TRACE_MSGNOTFOUND");
				}

				if (statePtr->depende_0.nr_msg_depende == 1) {
					if (instPtr->validade_ms > (statePtr->depende_0.msg_depende_0->timeout_ms + actual_time)) {
						free(statePtr->depende_0.msg_depende_0);
					}
				}
				if (statePtr->depende_0.nr_msg_depende == 2) {
					if (instPtr->validade_ms > (statePtr->depende_0.msg_depende_1->timeout_ms + actual_time)) {
						free(statePtr->depende_0.msg_depende_1);
					}
				}
				if (statePtr->depende_0.nr_msg_depende == 3) {
					if (instPtr->validade_ms > (statePtr->depende_0.msg_depende_2->timeout_ms + actual_time)) {
						free(statePtr->depende_0.msg_depende_2);
					}
				}
			}

			if (statePtr->nr_depende == 2) {
				if (testa_mensagem(statePtr->depende_1.mensagem) != SUCCESS) {
					Debug("TRACE_MSGNOTFOUND");
				}

				if (statePtr->depende_1.nr_msg_depende == 1) {
					if (instPtr->validade_ms > (statePtr->depende_1.msg_depende_0->timeout_ms + actual_time)) {
						free(statePtr->depende_1.msg_depende_0);
					}
				}
				if (statePtr->depende_1.nr_msg_depende == 2) {
					if (instPtr->validade_ms > (statePtr->depende_1.msg_depende_1->timeout_ms + actual_time)) {
						free(statePtr->depende_1.msg_depende_1);
					}
				}
				if (statePtr->depende_1.nr_msg_depende == 3) {
					if (instPtr->validade_ms > (statePtr->depende_1.msg_depende_2->timeout_ms + actual_time)) {
						free(statePtr->depende_1.msg_depende_2);
					}
				}
			}

			if (statePtr->nr_depende == 3) {
				if (testa_mensagem(statePtr->depende_2.mensagem) != SUCCESS) {
					Debug("TRACE_MSGNOTFOUND");
				}

				if (statePtr->depende_2.nr_msg_depende == 1) {
					if (instPtr->validade_ms > (statePtr->depende_2.msg_depende_0->timeout_ms + actual_time)) {
						free(statePtr->depende_2.msg_depende_0);
					}
				}
				if (statePtr->depende_2.nr_msg_depende == 2) {
					if (instPtr->validade_ms > (statePtr->depende_2.msg_depende_1->timeout_ms + actual_time)) {
						free(statePtr->depende_2.msg_depende_1);
					}
				}
				if (statePtr->depende_2.nr_msg_depende == 3) {
					if (instPtr->validade_ms > (statePtr->depende_2.msg_depende_2->timeout_ms + actual_time)) {
						free(statePtr->depende_2.msg_depende_2);
					}
				}
			}
		}
	} else {
		/* Entrada vazia, devo prosseguir com o proximo indice. */
		i = 1;

		actual_time = sysuptime_mili();

		if (nr_entradas < STATEFUL_MAX) {
			HASH(chave, i, indice);
			while ((tabela[indice].nr_inst) && (i < STATEFUL_MAX)) {
				i++;
				HASH(chave, i, indice);
			}
			if (i < STATEFUL_MAX) {
				instPtr = tabela[indice].li_primeiro;
				statePtr = instPtr->pendente_ptr;

				if (statePtr->nr_depende == 1) {
					if (testa_mensagem(statePtr->depende_0.mensagem) != SUCCESS) {
						Debug("TRACE_MSGNOTFOUND");
					}

					if (statePtr->depende_0.nr_msg_depende == 1) {
						if (instPtr->validade_ms > (statePtr->depende_0.msg_depende_0->timeout_ms + actual_time)) {
							free(statePtr->depende_0.msg_depende_0);
						}
					}
					if (statePtr->depende_0.nr_msg_depende == 2) {
						if (instPtr->validade_ms > (statePtr->depende_0.msg_depende_1->timeout_ms + actual_time)) {
							free(statePtr->depende_0.msg_depende_1);
						}
					}
					if (statePtr->depende_0.nr_msg_depende == 3) {
						if (instPtr->validade_ms > (statePtr->depende_0.msg_depende_2->timeout_ms + actual_time)) {
							free(statePtr->depende_0.msg_depende_2);
						}
					}
				}

				if (statePtr->nr_depende == 2) {
					if (testa_mensagem(statePtr->depende_1.mensagem) != SUCCESS) {
						Debug("TRACE_MSGNOTFOUND");
					}

					if (statePtr->depende_1.nr_msg_depende == 1) {
						if (instPtr->validade_ms > (statePtr->depende_1.msg_depende_0->timeout_ms + actual_time)) {
							free(statePtr->depende_1.msg_depende_0);
						}
					}
					if (statePtr->depende_1.nr_msg_depende == 2) {
						if (instPtr->validade_ms > (statePtr->depende_1.msg_depende_1->timeout_ms + actual_time)) {
							free(statePtr->depende_1.msg_depende_1);
						}
					}
					if (statePtr->depende_1.nr_msg_depende == 3) {
						if (instPtr->validade_ms > (statePtr->depende_1.msg_depende_2->timeout_ms + actual_time)) {
							free(statePtr->depende_1.msg_depende_2);
						}
					}
				}

				if (statePtr->nr_depende == 3) {
					if (testa_mensagem(statePtr->depende_2.mensagem) != SUCCESS) {
						Debug("TRACE_MSGNOTFOUND");
					}

					if (statePtr->depende_2.nr_msg_depende == 1) {
						if (instPtr->validade_ms > (statePtr->depende_2.msg_depende_0->timeout_ms + actual_time)) {
							free(statePtr->depende_2.msg_depende_0);
						}
					}
					if (statePtr->depende_2.nr_msg_depende == 2) {
						if (instPtr->validade_ms > (statePtr->depende_2.msg_depende_1->timeout_ms + actual_time)) {
							free(statePtr->depende_2.msg_depende_1);
						}
					}
					if (statePtr->depende_2.nr_msg_depende == 3) {
						if (instPtr->validade_ms > (statePtr->depende_2.msg_depende_2->timeout_ms + actual_time)) {
							free(statePtr->depende_2.msg_depende_2);
						}
					}
				}
			} else {
				Debug("BUG VIOLENTOOOOO");
			}
		}
	}
}


/*
 *  Functions to deal with traces/messages/states/variables
 */
static inline u_char
do_ctoi(u_char c)
{
	return (c % '0');
}

static inline u_char
do_qual_mascara_bit(u_int bit)
{
	return (1 << (bit % (sizeof(u_char) * 8)));
}


int
tracos_preenche_variavel(variavel_t *ptr, char *id_ptr, u_int tamanho,
		u_int offset, u_int isbit, char *bitstring)
{
	u_int    i;
	u_int    pos;
	u_int    base;
	u_int    wordsize = sizeof(u_char) * 8;

	/* setup the memory size we'll allocate */
	if (isbit) {
		/*
		 *  setup bitcounter variable size
		 */
		if ((offset % wordsize) > 0) {
			ptr->tamanho = 1;
		}
		else {
			ptr->tamanho = 0;
		}
		ptr->tamanho += tamanho / wordsize;
		if ((tamanho % wordsize) > 0) {
			ptr->tamanho++;
		}

		/*
		 *  althought the variable itself is allocated out of this conditional,
		 *  the mask must be allocated now
		 */
		ptr->mascara = calloc(ptr->tamanho, sizeof(u_char));

		/*
		 *  now we must setup a mask suitable to filter the important bits.
		 *  this should be the same size of the variable (machine words), to
		 *  match perfectly.
		 *
		 *  this doesn't need to be fast, only work correctly
		 */

		/* filter out the last 3 bits, to get the base address, which is multiple of 8 */
		base = offset & (~7UL);
		for (i = 0, pos = offset; i < tamanho; i++, pos++) {
			//	    ptr->mascara[pos / 8 - base] |= do_ctoi(bitstring[i]) <<
			//	    ptr->mascara[i / 8] |= do_ctoi(bitstring[i]) <<
			ptr->mascara[(pos - base) / 8] |= do_ctoi(bitstring[i]) <<
				(7 - (pos % 8));
		}
	}
	else {
		/* tamanho_minimo is byte sized */
		ptr->tamanho = tamanho / sizeof(char);
	}

	/*
	 *	allocate memory for the variable
	 */
	ptr->var_ptr = calloc(ptr->tamanho, sizeof(char));
	if (ptr->var_ptr == NULL) {
		return ERROR_CALLOC;
	}

	/*
	 *	link identification stuff
	 */
	ptr->ident = id_ptr;

	return SUCCESS;
}


/** \brief Fills a filter with given parameters.
 *
 *  \param  *ptr	Pointer to filter area that is about to be filled.
 *  \param  *id_ptr	Pointer to a descritive string (useful only for debugging purposes).
 *  \param  tamanho_chave   Size of the search key, either in bits or bytes, based on \a tipo_mensagem.
 *  \param  *chave	Pointer to a string consisting of ASCII 1s or 0s (if filter is
 *			BITCOUNTER) or any string (if filter is FIELDCOUNTER/NOOFFSET)
 *  \param  offset	Number of bits or bytes to skip in the packet starting from
 *			the very beginning (ie, ethernet header).
 *  \param  tipo_mensagem   Filter type (MSG_BITCT, MSG_FIELDCT, MSG_NOOFFSET).
 *  \param  comparacao	Filter comparisson type ( completar!!! ).
 *  \param  operacao	Filter operation type (completar!!!).
 *  \param  timeout	Number of milliseconds to set as a timeout to (cancel) the filter.
 *  \param  *var_ptr	Pointer to a variable (if required by the filter) to use, or NULL.
 *  \param  direcao	Direction (FROM_CLIENT, FROM_SERVER, FROM_ANY) of the packet
 *			the filter may be tested.
 */
int
tracos_preenche_mensagem(mensagem_t *ptr, char *id_ptr, u_int tamanho_chave,
		u_char *chave, u_int offset, u_int tipo_mensagem, u_int comparacao,
		u_int operacao, u_int timeout, variavel_t *var_ptr, u_int direcao,
		u_int f_encaps)
{
	static const u_int	wordsize = sizeof(char) * 8;
	u_int		i, pos, base;

	ptr->timeout_ms = timeout;
	ptr->direcao = direcao;
	ptr->flags.comparacao = comparacao;
	ptr->flags.operacao = operacao;
	ptr->flags.encaps = f_encaps;
	ptr->offset = offset;

	ptr->flags.tipo = tipo_mensagem;

	ptr->variavel = var_ptr;
	i = strlen(id_ptr);
	ptr->ident = calloc(1, i + 1);
	strncpy(ptr->ident, id_ptr, i);

	if (tipo_mensagem == MSG_BITCT) {
		/*
		 *	basic size
		 */
		ptr->tam_chave = tamanho_chave / wordsize;
		/*
		 *	do we need one extra word due to size not word-multiple?
		 */
		ptr->tam_chave += ((tamanho_chave % wordsize) > 0);
		/*
		 *	do we need one extra word due to start/end misalign?
		 */
		ptr->tam_chave += (((offset % wordsize) > 0 ) ||
				(((offset + tamanho_chave) % wordsize) > 0));

		/* allocate memory for the mask -- only BITCT needs this */
		ptr->chave_mask_ptr = calloc(ptr->tam_chave, sizeof(char));
		/*XXX Alguma verificacao de memoria?! */
		/*    if (ptr->chave_ptr == NULL) {
		 *	    Debug("Lets blow it all!");
		 *	}
		 */
	}
	else {
		/* FIXME: if sizeof() != 1, this fails */
		ptr->tam_chave = tamanho_chave;
	}

	/*
	 *  allocate memory
	 */
	ptr->chave_ptr = calloc(ptr->tam_chave, sizeof(char));
	/*XXX Alguma verificacao de memoria?! */
	/*    if (ptr->chave_ptr == NULL) {
	 *	    Debug("Lets blow it all!");
	 *	}
	 */

	/*
	 *  setup initial key mask if message is MSG_BITCT
	 */
	if ((tipo_mensagem == MSG_BITCT) && (chave != NULL)){
		/*
		 *	filter out the last 3 bits, to get the base address, which is
		 *	multiple of 8.  then, set up the key and also the mask
		 *	FIXME: only if sizeof() == 1, as I use hardcoded 8
		 */
		base = offset & (~7UL);
		for (i = 0, pos = offset; i < tamanho_chave; i++, pos++) {
			ptr->chave_ptr[(pos - base) / 8] |= do_ctoi(chave[i]) <<
				(7 - (pos % 8));
			ptr->chave_mask_ptr[(pos - base) / 8] |= 1 << (7 - (pos % 8));
		}
	}
	else {
		do_char_memcpy(ptr->chave_ptr, chave, tamanho_chave);
	}

	return (SUCCESS);
}


/** \brief Marks a state as final in the protocol trace descriptor.
 *
 *  \param *t_ptr   Pointer to the trace descriptor.
 *  \param *e_ptr   Pointer to the final state descriptor.
 *
 *  \retval SUCCESS		No errors.
 *  \retval ERROR_NOSUCHENTRY	Received \a t_ptr is NULL.
 *
 *  \todo   Change *e_ptr to an unsigned int index, so we calculate
 *	    here the address of the state, avoiding having the caller
 *	    doing so.
 */
int
tracos_preenche_estado_final(traco_t *trace_ptr, estado_t *state_ptr)
{
	if (trace_ptr != NULL) {
		trace_ptr->estado_final = state_ptr;
		return (SUCCESS);
	}

	return (ERROR_NOSUCHENTRY);
}


int
tracos_preenche_estado(estado_t *ptr, char *id_ptr, u_int i_depende,
		depende_t *dep_ptr, estado_t *prox)
{
	ptr->nr_depende = i_depende;
	ptr->prox_estado = prox;

	/* aparentemente, fazer um memcpy aqui não fica legal */
	if (i_depende > 0) {
		ptr->depende_0.mensagem = dep_ptr[0].mensagem;
		ptr->depende_0.nr_msg_depende = dep_ptr[0].nr_msg_depende;
		ptr->depende_0.msg_depende_0 = dep_ptr[0].msg_depende_0;
		ptr->depende_0.msg_depende_1 = dep_ptr[0].msg_depende_1;
		ptr->depende_0.msg_depende_2 = dep_ptr[0].msg_depende_2;
		ptr->depende_0.msg_depende_3 = dep_ptr[0].msg_depende_3;
		ptr->depende_0.msg_depende_4 = dep_ptr[0].msg_depende_4;
		ptr->depende_0.msg_depende_5 = dep_ptr[0].msg_depende_5;
	}
	if (i_depende > 1) {
		ptr->depende_1.mensagem = dep_ptr[1].mensagem;
		ptr->depende_1.nr_msg_depende = dep_ptr[1].nr_msg_depende;
		ptr->depende_1.msg_depende_0 = dep_ptr[1].msg_depende_0;
		ptr->depende_1.msg_depende_1 = dep_ptr[1].msg_depende_1;
		ptr->depende_1.msg_depende_2 = dep_ptr[1].msg_depende_2;
		ptr->depende_1.msg_depende_3 = dep_ptr[1].msg_depende_3;
		ptr->depende_1.msg_depende_4 = dep_ptr[1].msg_depende_4;
		ptr->depende_1.msg_depende_5 = dep_ptr[1].msg_depende_5;
	}
	if (i_depende > 2) {
		ptr->depende_2.mensagem = dep_ptr[2].mensagem;
		ptr->depende_2.nr_msg_depende = dep_ptr[2].nr_msg_depende;
		ptr->depende_2.msg_depende_0 = dep_ptr[2].msg_depende_0;
		ptr->depende_2.msg_depende_1 = dep_ptr[2].msg_depende_1;
		ptr->depende_2.msg_depende_2 = dep_ptr[2].msg_depende_2;
		ptr->depende_2.msg_depende_3 = dep_ptr[2].msg_depende_3;
		ptr->depende_2.msg_depende_4 = dep_ptr[2].msg_depende_4;
		ptr->depende_2.msg_depende_5 = dep_ptr[2].msg_depende_5;
	}
	if (i_depende > 3) {
		Debug("limite de 3 dependencias atingido.");
	}

	ptr->ident = id_ptr;

	/* the rest of the structure cannot be filled now */
	return (SUCCESS);
}


traco_t *
tracos_aloca_traco(descricao_t *descricao_ptr, u_int i_estados,
		u_int i_mensagens, u_int i_variaveis, u_int id_num)
{
	traco_t	*ptr;
	char	*chunck_ptr;
	u_int	sz_nome, sz_vers, sz_desc, sz_pala;
	u_int	sz_port, sz_cria, sz_atua, sz_refe;

	Debug("id_num: %x", id_num);

	ptr = calloc(1, sizeof(traco_t));

	if (ptr == NULL) {
		/* memory allocation error */
		Debug("calloc falhou");
		return NULL;
	}

	/*
	 *	now we will insert it in another list
	 */
	if (li_tracos_qtd > 0) {
		/* not the first */
		li_tracos_fim->prox_ptr = calloc(1, sizeof(struct li_traco_s));
		li_tracos_fim = li_tracos_fim->prox_ptr;
	}
	else {
		/* first */
		li_tracos_ini = calloc(1, sizeof(struct li_traco_s));
		li_tracos_fim = li_tracos_ini;
	}
	if (li_tracos_fim != NULL) {
		li_tracos_fim->id = id_num;
		li_tracos_fim->traco_ptr = ptr;
		li_tracos_qtd++;
	}
	else {
		Debug("calloc failed!");
		return NULL;
	}

	ptr->nr_estados = i_estados;
	ptr->estados = calloc(i_estados, sizeof(estado_t));
	if (ptr->estados == NULL) {
		free(ptr);
		return NULL;
	}

	ptr->nr_mensagens = i_mensagens;
	ptr->mensagens = calloc(i_mensagens, sizeof(mensagem_t));
	if (ptr->mensagens == NULL) {
		free(ptr);
		return NULL;
	}

	if (i_variaveis > 0) {
		ptr->nr_variaveis = i_variaveis;
		ptr->variaveis = calloc(i_variaveis, sizeof(variavel_t));
		if (ptr->variaveis == NULL) {
			free(ptr);
			return NULL;
		}
	}

	if (descricao_ptr != NULL) {
		/* pegar o tamanho de todas as strings */
		sz_nome = (descricao_ptr->nome != NULL ? strlen(descricao_ptr->nome) : 0);
		sz_vers = (descricao_ptr->versao != NULL ? strlen(descricao_ptr->versao) : 0);
		sz_desc = (descricao_ptr->descricao != NULL ? strlen(descricao_ptr->descricao) : 0);
		sz_pala = (descricao_ptr->palavras != NULL ? strlen(descricao_ptr->palavras) : 0);
		sz_port = (descricao_ptr->porta != NULL ? strlen(descricao_ptr->porta) : 0);
		sz_cria = (descricao_ptr->criador != NULL ? strlen(descricao_ptr->criador) : 0);
		sz_atua = (descricao_ptr->atualizacao != NULL ? strlen(descricao_ptr->atualizacao) : 0);
		sz_refe = (descricao_ptr->references != NULL ? strlen(descricao_ptr->references) : 0);

		/* alocar um pedaço suficiente para todas as strings e os NULLs */
		chunck_ptr = calloc(1, (sz_nome + sz_vers + sz_desc + sz_pala +
					sz_port + sz_cria + sz_atua + sz_refe + 8));
		if (chunck_ptr == NULL) {
			Debug("erro alocando memória");
			return NULL;
		}
		ptr->descricao = calloc(1, sizeof(descricao_t));

		/* copiar as strings */
		ptr->descricao->nome        = chunck_ptr;
		ptr->descricao->versao      = ptr->descricao->nome        + sz_nome + 1;
		ptr->descricao->descricao   = ptr->descricao->versao      + sz_vers + 1;
		ptr->descricao->palavras    = ptr->descricao->descricao   + sz_desc + 1;
		ptr->descricao->porta       = ptr->descricao->palavras    + sz_pala + 1;
		ptr->descricao->criador     = ptr->descricao->porta       + sz_port + 1;
		ptr->descricao->atualizacao = ptr->descricao->criador     + sz_cria + 1;
		ptr->descricao->references  = ptr->descricao->atualizacao + sz_atua + 1;

		strncpy(ptr->descricao->nome,        descricao_ptr->nome,        sz_nome);
		strncpy(ptr->descricao->versao,      descricao_ptr->versao,      sz_vers);
		strncpy(ptr->descricao->descricao,   descricao_ptr->descricao,   sz_desc);
		strncpy(ptr->descricao->palavras,    descricao_ptr->palavras,    sz_pala);
		strncpy(ptr->descricao->porta,       descricao_ptr->porta,       sz_port);
		strncpy(ptr->descricao->criador,     descricao_ptr->criador,     sz_cria);
		strncpy(ptr->descricao->atualizacao, descricao_ptr->atualizacao, sz_atua);
		strncpy(ptr->descricao->references,  descricao_ptr->references,  sz_refe);

		ptr->ident = ptr->descricao->nome;
	}

	/* the rest of this struct cannot be filled now */
	return ptr;
}


/** \brief Searches for a trace by an \a ID in the traces list.
 *  \param id	the protocol trace unique ID created by the manager.
 *  \return	A (trace_t *) if found, NULL otherwise.
 */
traco_t *
tracos_localiza_por_id(const u_int id)
{
	struct li_traco_s	*ptr = li_tracos_ini;

	while ((ptr != NULL) && (ptr->id != id)) {
		ptr = ptr->prox_ptr;
	}

	if (ptr != NULL) {
		return ptr->traco_ptr;
	} else {
		return NULL;
	}
}


/** \b Special function to fix the pointer 0xdeadbeef ID and change it to the
 * new ID passed by the caller.
 *
 * \param id	the protocol trace unique ID created by the manager.
 * \remarks	updates the old ID (0xdeadbeef) with the given one.
 * \return	A (trace_t *) if found, NULL otherwise.
 */
traco_t *
tracos_localiza_corrige_id(const u_int id)
{
	struct li_traco_s	*ptr = li_tracos_ini;

	/* FIXME */
	Debug("     li_traco_s: %p", ptr);
	while ((ptr != NULL) && (ptr->id != 0xdeadbeef)) {
		//	Debug("     id: %u", ptr->id);
		ptr = ptr->prox_ptr;
	}

	if (ptr != NULL) {
		ptr->id = id;
		return ptr->traco_ptr;
	}
	else {
		/* FIXME */
		Debug("0xdeadbeef nao encontrado");
		return NULL;
	}
}


/*
 *  main function to deal with traces (new or pendencies)
 */
int
tracos_verifica(pedb_t *prepacote, u_char *area_dados_ptr)
{
	uint32_t	ip;
	/*
	   pthread_t	remove_pend_pth;

	   if (pthread_create(&remove_pend_pth, NULL, tracos_check_remove_pend, NULL)) {
	   Debug("could not create check_remove_pend() thread");
	   abort();
	   }
	   */
	pedb = prepacote;
	dados_ptr = area_dados_ptr;

	/*
	 *	first we check the open traces
	 */
	indice_atual = pend_busca();

	/* FIXME */
	//    Debug("indice: %u\t nr_inst: %u",
	//	    indice_atual == STATEFUL_TAM ? STATEFUL_TAM : indice_atual,
	//	    indice_atual == STATEFUL_TAM ? 0 : tabela[indice_atual].nr_inst);

	if (indice_atual < STATEFUL_TAM) {
		/* yes, there is one pendency */
		instancia_atual_ptr = &tabela[indice_atual];
		li_atual_ptr = tabela[indice_atual].li_primeiro;
		li_prev_ptr = li_atual_ptr;
		/* para remocao */

		//	Debug("nó inicial: %p", tabela[indice_atual].li_primeiro);

		while (li_atual_ptr != NULL) {
			//	    Debug("  +--> instancia %p\t\tant: %p", li_atual_ptr, li_prev_ptr);

			/* check timeout, if there is one */
			if ((li_atual_ptr->validade_ms) && (sysuptime_mili() > li_atual_ptr->validade_ms)) {
				/* expired */
				Debug("timeout: %u // %lu", li_atual_ptr->validade_ms, sysuptime_mili());
				li_atual_ptr->traco_ptr->nr_falhas++;
				pend_remove();
				continue;
			}
			else {
				/* now try the state's messages */
				estado_pendente_ptr = li_atual_ptr->pendente_ptr;
				if (testa_estado() == SUCCESS) {
					if (estado_pendente_ptr->prox_estado == li_atual_ptr->traco_ptr->estado_final) {
						/*	trace is now complete - account and remove it from hash table	*/
						li_atual_ptr->traco_ptr->nr_sucessos++;
						ip = ntohl(pedb->ip_orig);
						sprintf(str_iporigem, "%u.%u.%u.%u", (ip >> 24) & 0xff,
								(ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
						ip = ntohl(pedb->ip_dest);
						sprintf(str_ipdestino, "%u.%u.%u.%u", (ip >> 24) & 0xff,
								(ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
						Debug("Ocorrencia: %s (%u), %s -> %s\n",
								li_atual_ptr->traco_ptr->ident, li_atual_ptr->traco_ptr->nr_sucessos,
								str_iporigem, str_ipdestino);
						//			Debug("tracos: ocorrência do traço `%s' detectada (total=%u)",
						//				li_atual_ptr->traco_ptr->descricao->descricao,
						//				li_atual_ptr->traco_ptr->nr_sucessos);
						pend_remove();
						continue;
					}
					else {
						/*  trace keeps in the table	*/
						li_atual_ptr->pendente_ptr =
							li_atual_ptr->pendente_ptr->prox_estado;
#if HUNT_BUGS
						if (li_atual_ptr->pendente_ptr == NULL) {
							Debug("prox_estado == NULL",
									bug_color_str, bug_nocolor_str);
						}
#endif
					}
				}
			}

			li_prev_ptr = li_atual_ptr;
			li_atual_ptr = li_atual_ptr->li_prox;
		}
	}

	/*
	 *	done with the open traces, now it's time to check if we can open new
	 *	traces - at the moment, this may be buggy
	 *
	 *	try network, transport and application traces
	 */
	traco_atual_ptr = pedb->prim_traco_rede;
	//    estado_pendente_ptr = &(pedb->prim_traco_rede->estados[0]);
	while (traco_atual_ptr != NULL) {
		estado_pendente_ptr = &traco_atual_ptr->estados[0];
		if (testa_estado() != SUCCESS) {
			//	    Debug("R :(");
		}
		else {
			//	    Debug("R :)");
			if (estado_pendente_ptr->prox_estado == traco_atual_ptr->estado_final) {
				/*
				 *  trace has only one state -- account
				 */
				traco_atual_ptr->nr_sucessos++;
				Debug("Ocorrencia: %s (%u)", traco_atual_ptr->ident,
						traco_atual_ptr->nr_sucessos);
			}
			else {
				/*
				 *  new instance of a multi-state trace
				 */
				if (traco_atual_ptr->estados[0].prox_estado == NULL) {
					Debug("estado nulo!");
					return TRACE_NULL_ERROR;
				}
				else {
					pend_inclui(traco_atual_ptr, traco_atual_ptr->estados[0].prox_estado, 30000);
				}
			}
		}

		traco_atual_ptr = traco_atual_ptr->proximo_traco;
	}

	/*
	 *	transport-layer traces
	 */
	traco_atual_ptr = pedb->prim_traco_transporte;
	//    estado_pendente_ptr = &(pedb->prim_traco_transporte->estados[0]);
	while (traco_atual_ptr != NULL) {
		estado_pendente_ptr = &traco_atual_ptr->estados[0];
		if (testa_estado() != SUCCESS) {
			//	    Debug("T :(");
		}
		else {
			//	    Debug("T :)");
			if (estado_pendente_ptr->prox_estado == traco_atual_ptr->estado_final) {
				/*
				 *  trace has only one state -- account
				 */
				traco_atual_ptr->nr_sucessos++;
#if HUNT_BUGS
				Debug("Ocorrencia: %s (%u)", traco_atual_ptr->ident,
						traco_atual_ptr->nr_sucessos);
#endif
			}
			else {
				/*
				 *  new instance of a multi-state trace
				 */
				if (traco_atual_ptr->estados[0].prox_estado == NULL) {
					Debug("estado nulo!", bug_color_str,
							bug_nocolor_str);
					return TRACE_NULL_ERROR;
				}
				else {
#if HUNT_BUGS
					if (pend_inclui(traco_atual_ptr, estado_pendente_ptr->prox_estado, 30000) != SUCCESS) {
						Debug("pend_inclui() != SUCCESS");
					}
#else
					pend_inclui(traco_atual_ptr, traco_atual_ptr->estados[0].prox_estado, 30000);
#endif
				}
			}
		}

		traco_atual_ptr = traco_atual_ptr->proximo_traco;
	}

	/*
	 *	application-layer traces
	 */
	traco_atual_ptr = pedb->prim_traco_aplicacao;
	while (traco_atual_ptr != NULL) {
		estado_pendente_ptr = &traco_atual_ptr->estados[0];
		if (testa_estado() != SUCCESS) {
			//	    Debug("A :(");
		}
		else {
			//	    Debug("A :)");
			if (estado_pendente_ptr->prox_estado == traco_atual_ptr->estado_final) {
				/*
				 *  trace is complete - account
				 */
				Debug("Ocorrencia: %s (%u)", traco_atual_ptr->ident,
						traco_atual_ptr->nr_sucessos);
				traco_atual_ptr->nr_sucessos++;
			}
			else {
				/*
				 *  new instance of a multi-state trace
				 */
				if (traco_atual_ptr->estados[0].prox_estado == NULL) {
					Debug("estado nulo!");
					return TRACE_NULL_ERROR;
				}
				else {
					//#if HUNT_BUGS
					//		    Debug("vou incluir uma pendencia.");
					pend_inclui(traco_atual_ptr, traco_atual_ptr->estados[0].prox_estado, 30000);
				}
			}
		}
		traco_atual_ptr = traco_atual_ptr->proximo_traco;
	}
	return SUCCESS;
}
