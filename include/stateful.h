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

#ifndef __STATEFUL_H
#define __STATEFUL_H

/*
 *  forward type declarations
 */
typedef struct depende_s    depende_t;
typedef struct descricao_s  descricao_t;
typedef struct variavel_s   variavel_t;
typedef struct flags_s	    flags_t;
typedef struct mensagem_s   mensagem_t;
typedef struct estado_s	    estado_t;
typedef struct traco_s	    traco_t;
typedef struct instancia_s  instancia_t;
typedef struct li_inst_s    li_inst_t;

/*
 *  Textual description structure
 */
struct descricao_s {
	char	*nome;		/* protocol trace name */
	char	*versao;	/* ... version */
	char	*descricao;	/* ... description */
	char	*palavras;	/* ... keywords */
	char	*porta;		/* ... port */
	char	*criador;	/* ... owner */
	char	*atualizacao;	/* ... last update */
	char	*references;

	/* stuff needed in NetSNMP */
	unsigned int	pdir_name_len;	/* size of pdir_name (chars) */
	char	*pdir_name;	/* protocolDir indexing? */
	//	char	*pdir_name_fault;	/* protocolDir indexing? */
};


/*
 *  Variables
 */
struct variavel_s {
	unsigned int	tamanho;	/* var_ptr length, in words */
	unsigned char	*mascara;	/* mask */

	/* TODO: incluir um unsigned long pre-alocado */
	unsigned char	*var_ptr;	/* the variable itself */

	char		*ident;	/* identification string */
};


/*
 *  special structure, which modelates the dependency among messages
 *  this is possibly the most complicated structure here.  in states,
 *  we model a OR type of dependency, while in the messages we model
 *  the AND type.  and they can be mixed.
 */

struct depende_s {
	mensagem_t	*mensagem;
	unsigned int	nr_msg_depende;	/* number of dependent messages */
	mensagem_t	*msg_depende_0;
	mensagem_t	*msg_depende_1;
	mensagem_t	*msg_depende_2;
	mensagem_t	*msg_depende_3;
	mensagem_t	*msg_depende_4;
	mensagem_t	*msg_depende_5;

	/* TODO: support more than 6 messages */
};



/*
 *  Messages
 */

/* Flags */
#define	MSG_RESERV	0   /* not used - reserved for (maybe?) future use */
#define MSG_BITCT	1   /* bit counter message */
#define	MSG_FIELDCT	2   /* field counter message */
#define MSG_NOOFFSET	3   /* no offset message */

#define CMP_NENHUMA		0
#define CMP_CHAVE_E_PACOTE	1
#define CMP_CHAVEPTR_E_PACOTE	2
#define CMP_CHAVE_E_VAR		3   /* compare 'chave' with 'variavel'	    */
#define CMP_CHAVE_E_CHAVEPTR	4   /* compare 'chave' with 'chave_ptr'	    */
#define CMP_CHAVEPTR_E_VAR	5   /* compare 'chave_ptr' with 'variavel'  */
#define CMP_VAR_E_PACOTE	6

#define OPER_IGUAL	0
#define OPER_MAIOR	1
#define OPER_MAIORIGUAL	2
#define OPER_MENOR	3
#define OPER_MENORIGUAL	4
#define OPER_DIFERENTE	5
#define OPER_ARMAZENAR	6   /* used to store a variable */

struct flags_s {		/* TODO: check performance penalty */
	unsigned int tipo:2;		/* message type selection */
	unsigned int comparacao:3;	/* comparison type */
	unsigned int operacao:3;	/* comparisson operator type */
	unsigned int encaps:2;		/* filter encapsulation type */
	unsigned int __pad:22;		/* unused - just to keep flags with 32bits */
};

struct mensagem_s {
	unsigned int	direcao;
	unsigned int	timeout_ms;	/* transition timeout in miliseconds */
	unsigned int	nr_usos;	/* number of times this message was processed */

	flags_t	flags;

	unsigned int	offset;		/* bits if MSG_BITCT, else bytes */

	unsigned int	tam_chave;	/* key size */
//	unsigned char	chave[16];	/* 16 bytes so we avoid some mallocs */
	unsigned char	*chave_ptr;	/* for longer than 16 bytes keys */
	unsigned char	*chave_mask_ptr;

	variavel_t	*variavel;	/* TODO: add support for multiple variables */

	char	*ident;	/* identification string */
};


/*
 *	States
 */
struct estado_s {
	unsigned int	nr_depende;	/* number of messages this state has */
	depende_t	depende_0;	/* 3 pre-allocated messages */
	depende_t	depende_1;
	depende_t	depende_2;

/* TODO: multiple messages/dependencies */
//	depende_t	**dependencias; /* extra messages */

	unsigned int	nr_referencias; /* how many traces refer this state */
	estado_t	*prox_estado;	/* next state if success */

	char		*ident;		/* identification string */
};


/*
 *  Main data structure for the protocol Traces (linked in the protocolDir)
 */
struct traco_s {
	unsigned int	nr_instancias;	/* instances of this protocol trace */
	unsigned int	nr_sucessos;	/* finished instances of this protocol trace */
	unsigned int	nr_falhas;	/* not finished instances */

	unsigned int	nr_estados;	/* number of states */
	estado_t	*estados;	/* pointer to array of states */
	estado_t	*estado_final;	/* final state (pointer comparisson) */

	unsigned int	nr_mensagens;	/* number of messages */
	mensagem_t	*mensagens;	/* pointer to array of messages */

	unsigned int	nr_variaveis;	/* number of variables */
	variavel_t	*variaveis;	/* FIXME pointer to array of variables */

	descricao_t	*descricao;	/* textual description of this protocol trace */

	traco_t		*proximo_traco; /* pointer to next protocol trace */

	char		*ident;		/* identification string */

	unsigned int	pdir_index;
	unsigned int	pdir_localindex;

	unsigned int	running;	/* is this trace running? */
};


/*
 *  Special hash table for open traces (pendencies)
 */
struct instancia_s {
	unsigned int	nr_inst;	/* how many similar instances do we have? */

	in_addr_t	ip_cliente;	/* needed to verify hash table entry */
	in_addr_t	ip_servidor;
	unsigned int	porta_cliente;
	unsigned int	porta_servidor;

	li_inst_t	*li_primeiro;
	li_inst_t	*li_ultimo;
};


/*
 *	special list for the special hash structure ;)
 */
struct li_inst_s {
	li_inst_t	*li_prox;
	unsigned int	validade_ms;	/* deadline for this pendency, in miliseconds
	and in system uptime 'format' */
	estado_t	*pendente_ptr;	/* which state is pending */
	traco_t		*traco_ptr;
};


struct li_traco_s {
	unsigned int		id;
	traco_t			*traco_ptr;
	struct li_traco_s	*prox_ptr;
};

#endif	/* __STATEFUL_H */
