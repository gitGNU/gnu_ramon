/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2003, 2004, 2008  Ricardo Nabinger Sanchez
 * Copyright (C) 2003, 2004  Diego Wentz Antunes
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

#include <stdlib.h>
#include <stdint.h> /* uint32_t */
#include <stdio.h>  /* FILE fread fopen fclose */
#include <string.h> /* strncpy */
#include <unistd.h>
#include <sys/types.h>

#include "configuracao.h"
#include "globals.h"
#include "exit_codes.h"
#include "rowstatus.h"

#ifdef PTSL
#include <netinet/in.h>
#include "stateful.h"
#include "pedb.h"
#include "tracos.h"
#endif

#include "sysuptime.h"
#include "protocoldir.h"

/* para remoção nas tabelas */
#include "alhost.h"
#include "nlhost.h"
#include "protocoldist.h"

#include "hlhost.h"
#include "hlmatrix.h"
#include "log.h"

/* local defines */
#define PDIR_TAM    5119	/* prime number, * 0.8 = PDIR_MAX */
#define PDIR_MAX    4096	/* maximum entries: MUST be power of 2 */

#define HASH(chave,i,resultado) \
{ \
	register uint32_t desl; \
	register uint32_t base; \
	desl = (chave % (PDIR_TAM - 2)); \
	base = (chave % PDIR_TAM); \
	desl++; \
	base += i; \
	desl *= base; \
	resultado = desl % PDIR_TAM; \
}

static pdir_node_t	*pdir_table[PDIR_TAM] = {NULL, };


/** \brief  a new structure to see if an encapsulation is registered in the
 *	    protocol directory (protocolDir).
 *
 *  This new structure consists of a bitmap, where each bit stores if a
 *  application protocol should or should not be further analysed.
 *
 *  The size is determined by:
 *
 *	total_size = Entries / (8 * sizeof(long))
 */
#define WORDSIZE_BITS (sizeof(long) * 8)
static unsigned long	pdir_bit_table[65536 / WORDSIZE_BITS];

static unsigned long	lastchange;	    /* system uptime when last changed */
static unsigned int	quantidade;	    /* number of entries in the table */
static unsigned int	profundidade;   /* depth of the hash table */

#ifdef PTSL
static traco_t		*traco_novo_ptr;
#endif

/* lista de índices */
#define QUERO_REMOVER	1
#define QUERO_PRIMEIRO	1
#define QUERO_PROXIMO	1
#include "lista_indices.h"


/**  \brief  Lookup function for the protocolDir
 *
 *  This function searches the protocolDir table, telling the caller if the
 *  RMON2 agent is programmed to completely decode the packet.
 *
 *  \param port	packet port (found in the TCP/UDP header)
 *  \retval nonzero if the agent is programmed to decode the packet
 *  \retval 0	    otherwise
 */
int pdir_bit_localiza(const unsigned int port)
{
	return (pdir_bit_table[port / WORDSIZE_BITS] & (1 << (port % WORDSIZE_BITS)));
}


/*
   busca uma entrada na tabela hash.
   retorna o ponteiro se encontrar, ou NULL
   */
pdir_node_t *pdir_localiza(const unsigned int enlace, const unsigned int rede,
		const unsigned int transporte, const unsigned int aplicacao)
{
	/* chave existe SE:
	   1) estiver antes de 'profundidade'
	   2) a posição sendo verificada conter dados
	   3) os dados passados conferirem
	   */

	uint32_t chave = (transporte << 16) | (aplicacao & 0x0000ffff);
	uint32_t verifica = (enlace << 16) | (rede & 0x0000ffff);
	unsigned int i = 0;
	unsigned int indice;

	HASH(chave, i, indice);

	/* verificar se a primeira tentativa foi bem sucedida */
	if ((pdir_table[indice] != NULL) &&
			(pdir_table[indice]->transp_aplic == chave) &&
			(pdir_table[indice]->enlace_rede == verifica)) {
		return pdir_table[indice];
	}

	/* ok, executaremos uma busca completa */
	i++;
	while (i <= profundidade) {
		HASH(chave, i, indice);
		if ((pdir_table[indice] != NULL) &&
				(pdir_table[indice]->transp_aplic == chave) &&
				(pdir_table[indice]->enlace_rede == verifica)) {
			/* encontrada */
			return pdir_table[indice];
		}
		i++;
	}

	return NULL;
}


/** \brief Searches for an entry in the protocolDir hash table and returns its
 *  index if found, or #PDIR_TAM otherwise.
 *
 *  This functions requires the protocol encapsulation identifiers:
 *
 *  \param  enlace	link-layer numerical ID
 *  \param  rede	network-layer numerical ID
 *  \param  transporte	trasport-layer numerical ID
 *  \param  aplicacao	application-layer numerical ID
 *
 *  \return An index ranging from 0 to (PDIR_TAM - 1) if found, PDIR_TAM otherwise.
 */
unsigned int pdir_localiza_indice(const unsigned int enlace, const unsigned int rede,
		const unsigned int transporte, const unsigned int aplicacao)
{
	/*
	 *	chave existe SE:
	 *	    1) estiver antes de 'profundidade'
	 *	    2) a posição sendo verificada conter dados
	 *	    3) os dados passados conferirem
	 */

	uint32_t chave = (transporte << 16) | (aplicacao & 0x0000ffff);
	uint32_t verifica = (enlace << 16) | (rede & 0x0000ffff);
	unsigned int i = 0;
	unsigned int indice;

	HASH(chave, i, indice);

	/* verificar se a primeira tentativa foi bem sucedida */
	if ((pdir_table[indice] != NULL) &&
			(pdir_table[indice]->transp_aplic == chave) &&
			(pdir_table[indice]->enlace_rede == verifica)) {
		return indice;
	}

	/* ok, executaremos uma busca completa */
	i++;
	while (i <= profundidade) {
		HASH(chave, i, indice);
		if ((pdir_table[indice] != NULL) &&
				(pdir_table[indice]->transp_aplic == chave) &&
				(pdir_table[indice]->enlace_rede == verifica)) {
			/* encontrada */
			return indice;
		}
		i++;
	}

	return PDIR_TAM;
}


static int test_isnumber(char *ptr) {
	while (*ptr != '\0') {
		if ((*ptr >= '0') && (*ptr <= '9'))
			ptr++;
		else
			return 0;
	}

	return 1;
}

static int test_isstring(char *ptr) {
	while (*ptr != '\0') {
		if (*ptr > ' ')
			ptr++;
		else
			return 0;
	}

	return 1;
}

/* regex: '^ +[0-9]+ +[0-9]+ +[0-9]+ +[0-9]+ +[0-9]+ +[0-9]+ +[0-9]+ +[0-9]+ +[\.0-9A-Za-z]+ +[0-9]+ +[0-9]+ +[0-9]+ +[0-9]+ +[\.0-9A-Za-z\-]+ *$' */
	int
init_protocoldir(char *filename)
{
	const char	 sep_ptr[] = "\n\t\r ";
	char		 linha[256];
	char		*token_ar[16];
	unsigned int	 contador = 1;
	unsigned int	 line = 0;
	int		 ret;
	FILE		*file_ptr;
	pdir_node_t	*pdn_ptr;

	if (filename == NULL)
		filename = PDIR_CONF;

	Debug("initializing protocolDir (%s)", filename);
	file_ptr = fopen(filename, "r");


	/* read all lines */
	while (fgets(linha, sizeof(linha), file_ptr) != NULL) {
		line++;
		/* locate all tokens */
		token_ar[0] = strtok(linha, sep_ptr);
		token_ar[1] = strtok(NULL, sep_ptr);
		token_ar[2] = strtok(NULL, sep_ptr);
		token_ar[3] = strtok(NULL, sep_ptr);
		token_ar[4] = strtok(NULL, sep_ptr);
		token_ar[5] = strtok(NULL, sep_ptr);
		token_ar[6] = strtok(NULL, sep_ptr);
		token_ar[7] = strtok(NULL, sep_ptr);
		token_ar[8] = strtok(NULL, sep_ptr);	/* string */
		token_ar[9] = strtok(NULL, sep_ptr);
		token_ar[10] = strtok(NULL, sep_ptr);
		token_ar[11] = strtok(NULL, sep_ptr);
		token_ar[12] = strtok(NULL, sep_ptr);
		token_ar[13] = strtok(NULL, sep_ptr);	/* string */
		token_ar[14] = strtok(NULL, sep_ptr);
		token_ar[15] = strtok(NULL, sep_ptr);	/* preferrably nothing, but... */

		/* inspect them: first check for NULL strings (empty or incomplete line) */
		if ((token_ar[0] == NULL) || (token_ar[1] == NULL) ||
				(token_ar[2] == NULL) || (token_ar[3] == NULL) ||
				(token_ar[4] == NULL) || (token_ar[5] == NULL) ||
				(token_ar[6] == NULL) || (token_ar[7] == NULL) ||
				(token_ar[8] == NULL) || (token_ar[9] == NULL) ||
				(token_ar[10] == NULL) || (token_ar[11] == NULL) ||
				(token_ar[12] == NULL) || (token_ar[13] == NULL) ||
				(token_ar[14] == NULL))
			continue;

		/* then check for comments */
		if (token_ar[0][0] == '#') {
			continue;
		}
		if ((token_ar[15] != NULL) && (token_ar[15][0] != '#')) {
			Debug("warning, garbage after last field on line %u",
					line);
		}

		/* after check for valid fields, starting with numbers */
		if (!test_isnumber(token_ar[0]) || !test_isnumber(token_ar[1]) ||
				!test_isnumber(token_ar[2]) || !test_isnumber(token_ar[3]) ||
				!test_isnumber(token_ar[4]) || !test_isnumber(token_ar[5]) ||
				!test_isnumber(token_ar[6]) || !test_isnumber(token_ar[7]) ||
				!test_isnumber(token_ar[9]) || !test_isnumber(token_ar[10]) ||
				!test_isnumber(token_ar[11]) || !test_isnumber(token_ar[12]) ||
				!test_isnumber(token_ar[14])) {
			Debug("discarding line %u (number test faile)",
					line);
			continue;
		}
		if (!test_isstring(token_ar[8]) || !test_isstring(token_ar[13])) {
			Debug("discarding line %u (control character found)",
					line);
			continue;
		}

		/* OK, should be correct then */
		pdn_ptr = calloc(1, sizeof(pdir_node_t));
		if (pdn_ptr == NULL)
			return ERROR_CALLOC;

		pdn_ptr->idlink		= strtol(token_ar[0], NULL, 10);
		pdn_ptr->idnet		= strtol(token_ar[1], NULL, 10);
		pdn_ptr->idtrans	= strtol(token_ar[2], NULL, 10);
		pdn_ptr->idapp		= strtol(token_ar[3], NULL, 10);
		pdn_ptr->param1		= strtol(token_ar[4], NULL, 10);
		pdn_ptr->param2		= strtol(token_ar[5], NULL, 10);
		pdn_ptr->param3		= strtol(token_ar[6], NULL, 10);
		pdn_ptr->param4		= strtol(token_ar[7], NULL, 10);
		pdn_ptr->descricao	= strdup(token_ar[8]);
		pdn_ptr->tipo		= strtol(token_ar[9], NULL, 10);
		pdn_ptr->addrmap_config	= strtol(token_ar[10], NULL, 10);
		pdn_ptr->host_config	= strtol(token_ar[11], NULL, 10);
		pdn_ptr->matrix_config	= strtol(token_ar[12], NULL, 10);
		pdn_ptr->owner		= strdup(token_ar[13]);
		pdn_ptr->row_status	= strtol(token_ar[14], NULL, 10);
		pdn_ptr->local_index	= contador;

		if ((pdn_ptr->descricao == NULL) || (pdn_ptr->owner == NULL))
			Debug("warning, short on memory");

		ret = protdir_insere(pdn_ptr);
		if (ret != SUCCESS)
			return ret;

		contador++;
		quantidade++;
	}

	lastchange = sysuptime();
	Debug("reporting %u entries, hash-table depth is %u",
			quantidade, profundidade);

#ifdef PTSL
	if (pdir_tracos_init() != SUCCESS)
		return TRACE_INIT_ERROR;
#endif

	return SUCCESS;
}


#if 0
/*
   inicialização da protocolDir, lendo a configuração do arquivo
   */
int protdir_init()
{
	char			linha[256] = {'\0', };
	char			*inicio_ptr;
	char			*fim_ptr;
	int				token_n;
	FILE			*f_ptr;
	int				insere_retorno;
	pdir_node_t	    *aloca_ptr;
	unsigned int    contador = 1;

	/* FIXME */
	f_ptr = fopen(PDIR_CONF, "r");

	if (f_ptr == NULL) {
		Debug("protdir_init(): erro ao tentar abrir protocoldir.conf");
		return ERROR_IO;
	}

	while (fgets(linha, 255, f_ptr) != NULL) {
		inicio_ptr = fim_ptr = linha;
		token_n = 0;

		while ((token_n < 15) && (fim_ptr <= &linha[255])) {
			while (*inicio_ptr <= ' ') {
				inicio_ptr++;
			}
			fim_ptr = inicio_ptr;
			while (*fim_ptr > ' ') {
				fim_ptr++;
			}
			*fim_ptr = '\0';
			switch (token_n) {
				case 0:
					if (*inicio_ptr != '#') {
						aloca_ptr = calloc(1, sizeof(pdir_node_t));
						aloca_ptr->idlink = (uint32_t) atoi(inicio_ptr);
					}
					else
						/* FIXME: hacks */
						token_n = 16;
					continue;
					break;
				case 1: aloca_ptr->idnet = (uint32_t) atoi(inicio_ptr); break;
				case 2: aloca_ptr->idtrans = (uint32_t) atoi(inicio_ptr); break;
				case 3: aloca_ptr->idapp = (uint32_t) atoi(inicio_ptr); break;
				case 4: aloca_ptr->param1 = (unsigned char) atoi(inicio_ptr); break;
				case 5: aloca_ptr->param2 = (unsigned char) atoi(inicio_ptr); break;
				case 6: aloca_ptr->param3 = (unsigned char) atoi(inicio_ptr); break;
				case 7: aloca_ptr->param4 = (unsigned char) atoi(inicio_ptr); break;
					/* nao tem local_index */
				case 8:
					aloca_ptr->descricao = calloc(1, fim_ptr - inicio_ptr + 1);
					if (aloca_ptr == NULL) {
						return ERROR_MALLOC;
					}
					strncpy(aloca_ptr->descricao, inicio_ptr, (fim_ptr - inicio_ptr));
					aloca_ptr->descricao[strlen(inicio_ptr)] = '\0';
					break;
				case 9: aloca_ptr->tipo = (unsigned char) atoi(inicio_ptr); break;
				case 10: aloca_ptr->addrmap_config = (unsigned char) atoi(inicio_ptr); break;
				case 11: aloca_ptr->host_config = (unsigned char) atoi(inicio_ptr); break;
				case 12: aloca_ptr->matrix_config = (unsigned char) atoi(inicio_ptr); break;
				case 13: aloca_ptr->owner = calloc(1, fim_ptr - inicio_ptr + 1);
					 if (aloca_ptr == NULL) {
						 return ERROR_MALLOC;
					 }
					 strncpy(aloca_ptr->owner, inicio_ptr, (fim_ptr - inicio_ptr));
					 aloca_ptr->owner[strlen(inicio_ptr)] = '\0';
					 break;
				case 14: aloca_ptr->row_status = (unsigned char) atoi(inicio_ptr); break;
			}

			inicio_ptr = fim_ptr;
			token_n++;
		}
		aloca_ptr->local_index = contador;
		contador++;

		insere_retorno = protdir_insere(aloca_ptr);
		if (insere_retorno == SUCCESS) {
			quantidade++;
		}
		else {
			return insere_retorno;
		}
	}

	lastchange = sysuptime();

	Debug("protocolDir: reporting %u entries, hash-table depth is %u",
			quantidade, profundidade);

#ifdef PTSL
	if (pdir_tracos_init() != SUCCESS) {
		return TRACE_INIT_ERROR;
	}
#endif

	return SUCCESS;
}
#endif


void protdir_dumpTable()
{
	int i;
	FILE *fptr = fopen("/tmp/protocoldir.table", "w");

	if (fptr == NULL) {
		Debug("protdir_dumpTable: erro ao criar arquivo");
		return;
	}

	for (i = 0; i < PDIR_TAM; i++) {
		if (pdir_table[i] != NULL) {
			fprintf(fptr, "[%d] = {%u, %u, %u, %u, %u, %u, %u, %u, %d, '%s', %u, %u, %u, %u, '%s', %u}",
					i,
					pdir_table[i]->idlink,
					pdir_table[i]->idnet,
					pdir_table[i]->idtrans,
					pdir_table[i]->idapp,
					pdir_table[i]->param1,
					pdir_table[i]->param2,
					pdir_table[i]->param3,
					pdir_table[i]->param4,
					pdir_table[i]->local_index,
					pdir_table[i]->descricao,
					pdir_table[i]->tipo,
					pdir_table[i]->addrmap_config,
					pdir_table[i]->host_config,
					pdir_table[i]->matrix_config,
					pdir_table[i]->owner,
					pdir_table[i]->row_status);
		}
	}

	fclose(fptr);
}


unsigned int pdir_encapsulamentos()
{
	return quantidade;
}


unsigned long pdir_busca_lastchange()
{
	return lastchange;
}


#ifdef PTSL
/** \brief creates the octet string ID (protocolDir index)
 *
 *  This function is called when protocolDir is being initialized, and it
 *  computes both the size of the octet string OID and the OID itself.
 *  The OID consists of (x * 4 + 1) octets, resulting in this:
 *
 *	x.l.l.l.l.n.n.n.n.t.t.t.t.a.a.a.a
 *
 *  where:
 *	\a x is the number of elements that follow (ie, the x * 4)
 *	\a l is composed by the 4 link level ID octets (in network byte order)
 *	\a n is similar, but for network level ID
 *	\a t is similar, but for transport level ID
 *	\a a is similar, but for application level ID
 *
 *  \param  indice	the corresponding index in the protocolDir to the given
 *			protocol trace
 *  \param  traco_ptr	a pointer to the protocol trace
 *  \param  idnum	an unique ID number for the protocol trace
 *
 *  \retval SUCCESS		if everything went OK
 *  \retval ERROR_NOSUCHENTRY	if \a indice refers to an invalid entry or
 *				\a traco_ptr is \a NULL
 *  \retval ERROR_CALLOC	if \a calloc failed to give us memory
 */
static int do_create_trace_oid_string(const unsigned int indice, traco_t *traco_ptr,
		const unsigned int idnum)
{
	unsigned int tamanho;
#if HUNT_BUGS
	unsigned int i;
#endif

	/* check if entry exists in the protocolDir table, and the parameter */
	if ((indice >= PDIR_TAM) || (pdir_table[indice] == NULL) || traco_ptr == NULL) {
		return ERROR_NOSUCHENTRY;
	}

	if (pdir_table[indice]->idapp != 0) {
		tamanho = 4;
	}
	else {
		if (pdir_table[indice]->idtrans != 0) {
			tamanho = 3;
		}
		else {
			tamanho = 2;
		}
	}

	/* setup size (net-snmp need it) and get memory */
	traco_ptr->descricao->pdir_name = (unsigned char *)calloc(tamanho * 4 + 1, sizeof(char));
	if (traco_ptr->descricao->pdir_name == NULL) {
		return ERROR_CALLOC;
	}
	traco_ptr->descricao->pdir_name_len = tamanho * 4 + 1;

	/* now we're ready to fill in the oid */
	traco_ptr->descricao->pdir_name[0] = (tamanho * 4) & 0xff;

	traco_ptr->descricao->pdir_name[1] = (pdir_table[indice]->idlink >> 24) & 0xff;
	traco_ptr->descricao->pdir_name[2] = (pdir_table[indice]->idlink >> 16) & 0xff;
	traco_ptr->descricao->pdir_name[3] = (pdir_table[indice]->idlink >> 8) & 0xff;
	traco_ptr->descricao->pdir_name[4] = (pdir_table[indice]->idlink) & 0xff;

	traco_ptr->descricao->pdir_name[7] = (pdir_table[indice]->idnet >> 8) & 0xff;
	traco_ptr->descricao->pdir_name[8] = (pdir_table[indice]->idnet) & 0xff;

	if (pdir_table[indice]->idtrans != 0) {
		traco_ptr->descricao->pdir_name[5] = (pdir_table[indice]->idnet >> 24) & 0xff;
		traco_ptr->descricao->pdir_name[6] = (pdir_table[indice]->idnet >> 16) & 0xff;

		traco_ptr->descricao->pdir_name[11] = (pdir_table[indice]->idtrans >> 8) & 0xff;
		traco_ptr->descricao->pdir_name[12] = (pdir_table[indice]->idtrans) & 0xff;

		if (pdir_table[indice]->idapp != 0) {
			/*
			 *	trace is application level
			 */
			traco_ptr->descricao->pdir_name[9] = (pdir_table[indice]->idtrans >> 24) & 0xff;
			traco_ptr->descricao->pdir_name[10] = (pdir_table[indice]->idtrans >> 16) & 0xff;

			traco_ptr->descricao->pdir_name[13] = (idnum >> 8) & 0xff;
			traco_ptr->descricao->pdir_name[14] = idnum & 0xff;
			traco_ptr->descricao->pdir_name[15] = (pdir_table[indice]->idapp >> 8) & 0xff;
			traco_ptr->descricao->pdir_name[16] = (pdir_table[indice]->idapp) & 0xff;
		}
		else {
			/*
			 *	application ID is 0, so the trace must be transport level
			 */
			traco_ptr->descricao->pdir_name[9] = (idnum >> 8) & 0xff;
			traco_ptr->descricao->pdir_name[10] = idnum & 0xff;
			/* FIXME fprintf */
			Debug("idtrans depois = %hhu", traco_ptr->descricao->pdir_name[10]);

		}
	}
	else {
		/*
		 *  transport ID is 0, so the protocol trace must be network level
		 */
		traco_ptr->descricao->pdir_name[5] = (idnum >> 8) & 0xff;
		traco_ptr->descricao->pdir_name[6] = idnum & 0xff;
	}

	return SUCCESS;
}
#endif


int protdir_insere(pdir_node_t *pdir_ptr)
{
	pdir_node_t	    *indice_ptr;
	uint32_t	    chave;
	uint32_t	    verifica;
	unsigned int    i;
	unsigned int    indice;

	if (quantidade < PDIR_MAX) {
		indice_ptr = pdir_localiza(pdir_ptr->idlink, pdir_ptr->idnet,
				pdir_ptr->idtrans, pdir_ptr->idapp);
		if (indice_ptr != NULL) {
			fprintf(stderr,
					"pdir_insere: entrada {%u, %u, %u, %u} já existente, ignorando",
					pdir_ptr->idlink, pdir_ptr->idnet, pdir_ptr->idtrans,
					pdir_ptr->idapp);
			return ERROR_ALREADYEXISTS;
		}

		/* OK, entrada nao existe. busca espaço livre na tabela */
		i = 0;
		chave = (pdir_ptr->idtrans << 16) | (pdir_ptr->idapp & 0x0000ffff);
		verifica = (pdir_ptr->idlink << 16) | (pdir_ptr->idnet & 0x0000ffff);
		HASH(chave, i, indice);

		while ((pdir_table[indice] != NULL) && (i < PDIR_MAX)){
			i++;
			HASH(chave, i, indice);
		}

		if (i < PDIR_MAX) {
			/* lugar livre */
			pdir_table[indice] = pdir_ptr;
			pdir_ptr->transp_aplic = chave;
			pdir_ptr->enlace_rede = verifica;

			if (i > profundidade) {
				/* atualizar limite de busca */
				profundidade = i;
			}

			/* inserir na lista de índices */
			if (lista_insere(indice) != SUCCESS) {
				return ERROR_INDEXLIST;
			}

			return SUCCESS;
		}
		else {
			/* WOW! existe espaço na tabela mas não foi encontrado */
			Debug("could NOT add entry (%u/%u)",
					quantidade, PDIR_TAM);
			return ERROR_HASH;
		}
	}
	else {
		return ERROR_FULL;
	}
}


/*
   remove uma entrada na protocolDir e, em cascata, pede para as tabelas removerem
   entradas que façam referência ao encapsulamento sendo removido
   */
int pdir_remove(const unsigned int e, const unsigned int r,
		const unsigned int t, const unsigned int a)
{
	pdir_node_t	    *ptr = pdir_localiza(e, r, t, a);
	unsigned int    indice;

	if (ptr != NULL) {
		/* passar o endereço do campo localindex para a remoção */

		if ((nlhost_remove_pdir(ptr->local_index) != SUCCESS) ||
				(alhost_remove_pdir(ptr->local_index) != SUCCESS) ||
				(pdist_stats_remove_cascata(ptr->local_index) != SUCCESS)) {
			/* OK, houve um erro, nada de pânico */
			Debug("erro na remoção em cascata");
		}

		/* remover da lista de índices */
		/* FIXME!!! */
		if (lista_remove_indice(indice) != SUCCESS) {
			Debug("índice %u não encontrado na lista",
					indice);
		}

		/* aritmética com ponteiros para descobrir o índice real */
		indice = ((unsigned int)ptr - (unsigned int)pdir_table) / sizeof(pdir_node_t *);
		pdir_table[indice] = NULL;
		quantidade--;

		/* OK, referências já foram removidas */
		free(ptr->descricao);
		free(ptr->owner);
		free(ptr);

		/* atualizar last change */
		lastchange = sysuptime();

		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
   monta a octet string 'id', de um determinado indice no vetor. exemplo:
   12.0.0.0.1.0.0.8.0.0.0.0.17
   n  + L1  + + L2  + +  L3  +

   n  - numer de sub-identifiers (4, 8, 12 ou 16)
   L1 - layer identifier para enlace
   L2 - ... para rede
   L3 - ... para transporte
   L4 - ... para aplicação

   quem chamar essa função *deve* desalocar a string
   FIXME - comentario
   */
int pdir_busca_id_octetstring(const unsigned int indice, char *ptr,
		const unsigned int maximo)
{
	unsigned int tamanho;

	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		if (pdir_table[indice]->idapp != 0) {
			tamanho = 4;
		}
		else {
			if (pdir_table[indice]->idtrans != 0) {
				tamanho = 3;
			}
			else {
				tamanho = 2;
			}
		}

		if (((tamanho * 4) + 1) > maximo) {
			/* we received a too small buffer */
			return 0;
		}

		ptr[0] = (unsigned char)(tamanho * 4);
		/* FIXME: confirmar se isso evita problemas de byte-ordering */
		ptr[1] = (unsigned char)(pdir_table[indice]->idlink >> 24);
		ptr[2] = (unsigned char)(pdir_table[indice]->idlink >> 16);
		ptr[3] = (unsigned char)(pdir_table[indice]->idlink >> 8);
		ptr[4] = (unsigned char)(pdir_table[indice]->idlink);

		ptr[5] = (unsigned char)(pdir_table[indice]->idnet >> 24);
		ptr[6] = (unsigned char)(pdir_table[indice]->idnet >> 16);
		ptr[7] = (unsigned char)(pdir_table[indice]->idnet >> 8);
		ptr[8] = (unsigned char)(pdir_table[indice]->idnet);

		if (pdir_table[indice]->idtrans != 0) {
			ptr[9] = (unsigned char)(pdir_table[indice]->idtrans >> 24);
			ptr[10] = (unsigned char)(pdir_table[indice]->idtrans >> 16);
			ptr[11] = (unsigned char)(pdir_table[indice]->idtrans >> 8);
			ptr[12] = (unsigned char)(pdir_table[indice]->idtrans);

			if (pdir_table[indice]->idapp != 0) {
				ptr[13] = (unsigned char)(pdir_table[indice]->idapp >> 24);
				ptr[14] = (unsigned char)(pdir_table[indice]->idapp >> 16);
				ptr[15] = (unsigned char)(pdir_table[indice]->idapp >> 8);
				ptr[16] = (unsigned char)(pdir_table[indice]->idapp);
			}
		}

		return (tamanho * 4) + 1;
	}
	else {
		return 0;
	}
}


/*
   monta a octet string 'param', de um determinado indice no vetor. exemplo:
   3.0.0.0
   n.P1.P2.P3

   n  - numer de sub-identifiers (?, 1, 2, 3 ou 4)
   P1 - parametros para enlace
   P2 - ... para rede
   P3 - ... para transporte
   P4 - ... para aplicação

   quem chamar essa função *deve* desalocar a string
   */
/*
 *  comment FIXME
 */
int pdir_busca_param_octetstring(const unsigned int indice, char *ptr,
		const unsigned int maximo)
{
	unsigned int tamanho;

	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		if (pdir_table[indice]->idapp != 0) {
			tamanho = 4;
		}
		else {
			if (pdir_table[indice]->idtrans != 0) {
				tamanho = 3;
			}
			else {
				tamanho = 2;
			}
		}

		if ((tamanho + 1) > maximo) {
			/* received buffer is too small */
			return 0;
		}

		ptr[0] = (unsigned char)tamanho;
		/* TODO: confirmar se isso evita problemas de byte-ordering */
		ptr[1] = (unsigned char)pdir_table[indice]->param1;
		ptr[2] = (unsigned char)pdir_table[indice]->param2;

		if (pdir_table[indice]->idtrans != 0) {
			ptr[3] = (unsigned char)pdir_table[indice]->param3;

			if (pdir_table[indice]->idapp != 0) {
				ptr[4] = (unsigned char)pdir_table[indice]->param4;
			}
		}

		return tamanho + 1;
	}
	else {
		return 0;
	}
}


int pdir_tabela_busca_localindex(const unsigned int indice, uint32_t *ptr)
{
	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		*ptr = pdir_table[indice]->local_index;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int pdir_tabela_busca_tipo(const unsigned int indice, unsigned char *ptr)
{
	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		*ptr = pdir_table[indice]->tipo;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int pdir_tabela_busca_addrmapconfig(const unsigned int indice, unsigned int *ptr)
{
	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		*ptr = pdir_table[indice]->addrmap_config;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int pdir_tabela_busca_hostconfig(const unsigned int indice, unsigned int *ptr)
{
	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		*ptr = pdir_table[indice]->host_config;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int pdir_tabela_busca_matrixconfig(const unsigned int indice, unsigned int *ptr)
{
	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		*ptr = pdir_table[indice]->matrix_config;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int pdir_tabela_busca_status(const unsigned int indice, unsigned int *ptr)
{
	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		*ptr = pdir_table[indice]->row_status;
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int pdir_tabela_busca_descr(const unsigned int indice, char *ptr,
		const unsigned int maximo)
{
	unsigned int tamanho;

	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		tamanho = strlen(pdir_table[indice]->descricao);

		if ((tamanho + 1) > maximo) {
			/* small buffer */
			return 0;
		}

		strncpy(ptr, pdir_table[indice]->descricao, tamanho);
		/* just for safety */
		ptr[tamanho] = '\0';

		return tamanho;
	}
	else {
		return 0;
	}
}


/*
 *  copy entry's owner to the supplied pointer to char pointer
 */
//unsigned char *pdir_tabela_busca_owner(const uint32_t indice, size_t *tam_ptr)
int pdir_tabela_busca_owner(const unsigned int indice, char *ptr,
		const unsigned int maximo)
{
	unsigned int tamanho;

	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		tamanho = strlen(pdir_table[indice]->owner);

		if ((tamanho + 1) > maximo) {
			/* buffer too small */
			return 0;
		}

		strncpy(ptr, pdir_table[indice]->owner, tamanho);
		/* safety */
		ptr[tamanho] = '\0';

		return tamanho;
	}
	else {
		return 0;
	}
}



/*
   define a descrição de um encapsulmento com enlace 'e', rede 'r', transporte 't'
   e aplicacao 'a'
   */
int pdir_define_descr(const unsigned int e, const unsigned int r,
		const unsigned int t, const unsigned int a, const char *descr)
{
	char	    *char_ptr;
	pdir_node_t	    *ptr = pdir_localiza(e, r, t, a);
	unsigned int    tamanho;

	if (ptr != NULL) {
		tamanho = strlen(descr);
		char_ptr = calloc(1, (tamanho + 1));

		if (char_ptr == NULL) {
			return ERROR_MALLOC;
		}
		else {
			free(ptr->descricao);
			ptr->descricao = char_ptr;
		}

		strncpy(ptr->descricao, descr, tamanho);
		ptr->descricao[tamanho] = '\0';

		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
   define o dono de um encapsulmento com enlace 'e', rede 'r', transporte 't'
   e aplicacao 'a'
   */
int pdir_define_owner(const unsigned int e, const unsigned int r,
		const unsigned int t, const unsigned int a, const char *owner)
{
	char	    *char_ptr;
	pdir_node_t	    *ptr = pdir_localiza(e, r, t, a);
	unsigned int    tamanho;

	if (ptr != NULL) {
		tamanho = strlen(owner);
		char_ptr = calloc(1, (tamanho + 1));

		if (char_ptr == NULL) {
			return ERROR_MALLOC;
		}
		else {
			free(ptr->owner);
			ptr->owner = char_ptr;
		}

		strncpy(ptr->owner, owner, tamanho);
		ptr->owner[tamanho] = '\0';

		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
   define o xxxx config de um encapsulmento com enlace 'e', rede 'r', transporte 't'
   e aplicacao 'a'
   */
int pdir_define_addrmap_config(const unsigned int e, const unsigned int r,
		const unsigned int t, const unsigned int a, const unsigned int config)
{
	pdir_node_t *ptr = pdir_localiza(e, r, t, a);

	if (ptr != NULL) {
		if ((config != CONFIG_NOT_SUPPORTED) &&
				(config != CONFIG_SUPPORTED_OFF) &&
				(config != CONFIG_SUPPORTED_ON)) {
			return ERROR_EVILVALUE;
		}

		ptr->addrmap_config = (unsigned char)config;
		lastchange = sysuptime();

		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int pdir_define_host_config(const unsigned int e, const unsigned int r,
		const unsigned int t, const unsigned int a, const unsigned int config)
{
	pdir_node_t *ptr = pdir_localiza(e, r, t, a);

	if (ptr != NULL) {
		if ((config != CONFIG_NOT_SUPPORTED) &&
				(config != CONFIG_SUPPORTED_OFF) &&
				(config != CONFIG_SUPPORTED_ON)) {
			return ERROR_EVILVALUE;
		}

		ptr->host_config = (unsigned char)config;
		lastchange = sysuptime();

		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


int pdir_define_matrix_config(const unsigned int e, const unsigned int r,
		const unsigned int t, const unsigned int a, const unsigned int config)
{
	pdir_node_t *ptr = pdir_localiza(e, r, t, a);

	if (ptr != NULL) {
		if ((config != CONFIG_NOT_SUPPORTED) &&
				(config != CONFIG_SUPPORTED_OFF) &&
				(config != CONFIG_SUPPORTED_ON)) {
			return ERROR_EVILVALUE;
		}

		ptr->matrix_config = (unsigned char)config;
		lastchange = sysuptime();

		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
   define o status de um encapsulmento com enlace 'e', rede 'r', transporte 't'
   e aplicacao 'a'
   */
int pdir_define_status(const unsigned int e, const unsigned int r,
		const unsigned int t, const unsigned int a, const unsigned int status)
{
	pdir_node_t *ptr = pdir_localiza(e, r, t, a);

	if (ptr != NULL) {
		if ((status != ROWSTATUS_ACTIVE) &&
				(status != ROWSTATUS_NOT_IN_SERVICE) &&
				(status != ROWSTATUS_NOT_READY) &&
				(status != ROWSTATUS_CREATE_AND_GO) &&
				(status != ROWSTATUS_CREATE_AND_WAIT) &&
				(status != ROWSTATUS_DESTROY)) {
			return ERROR_EVILVALUE;
		}

		ptr->row_status = (unsigned char)status;
		lastchange = sysuptime();

		/* FIXME: se o status NAO for ROWSTATUS_ACTIVE, deve remover entrada */

		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}


/*
   busca o primeiro elemento da lista de indices
   */
int pdir_tabela_primeiro(unsigned int *res)
{
	if (lista_primeiro() == SUCCESS) {
		*res = lista_atual->indice;
		return SUCCESS;
	}
	else {
		return ERROR_INDEXLIST;
	}
}


/*
   busca o proximo elemento da lista de indices
   */
int pdir_tabela_proximo(unsigned int *res)
{
	if (lista_proximo() == SUCCESS) {
		if (res) {
			*res = lista_atual->indice;
			return SUCCESS;
		}
		else {
			Debug("NULL-pointer recebido");
			return ERROR_INDEXLIST;
		}
	}
	else {
		return ERROR_INDEXLIST;
	}
}


/*
   testa uma entrada
   */
int pdir_tabela_testa(const unsigned int indice)
{
	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		return SUCCESS;
	}
	else {
		return ERROR_NOSUCHENTRY;
	}
}




#ifdef PTSL
int pdir_possui_traco(const unsigned int indice) {
	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		return pdir_table[indice]->nr_tracos;
	}

	return ERROR_NOSUCHENTRY;
}


	traco_t *
pdir_primeiro_traco(const unsigned int indice)
{
	if ((indice < PDIR_TAM) && (pdir_table[indice] != NULL)) {
		return pdir_table[indice]->primeiro_traco;
	}

	return NULL;
}


int pdir_traco_busca_idstring(traco_t *traco, unsigned char *str, unsigned int tam)
{
	if (traco != NULL) {
		if (traco->descricao->pdir_name_len <= tam) {
			memcpy(str, traco->descricao->pdir_name, traco->descricao->pdir_name_len);
			return traco->descricao->pdir_name_len;
		}
	}

	return 0;
}


int pdir_traco_run(const unsigned int id_traco)
{
	traco_t *t_ptr;

	Debug("procurando traço com ID %u", id_traco);

	t_ptr = tracos_localiza_por_id(id_traco);

	if (t_ptr != NULL) {
		if (t_ptr->running == 0) {
			t_ptr->proximo_traco = NULL;

			if (pdir_table[t_ptr->pdir_index]->nr_tracos > 0) {
				/* not the first */
				Debug("inserindo traço no final");
				pdir_table[t_ptr->pdir_index]->ultimo_traco->proximo_traco = t_ptr;
				pdir_table[t_ptr->pdir_index]->ultimo_traco = t_ptr;
				t_ptr->running = 1;
			}
			else {
				/* first trace */
				Debug("inserindo traço no inicio");
				pdir_table[t_ptr->pdir_index]->primeiro_traco = t_ptr;
				pdir_table[t_ptr->pdir_index]->ultimo_traco = t_ptr;
				t_ptr->running = 1;
			}

			pdir_table[t_ptr->pdir_index]->nr_tracos++;
			Debug("RUN %s [%u]",
					t_ptr->descricao->descricao, t_ptr->pdir_index);
			return (SUCCESS);
		} else {
			return (ERROR_ALREADYEXISTS);
		}
	} else {
		Debug("traço não encontrado");
	}

	return (ERROR_NOSUCHENTRY);
}


int pdir_traco_remove()
{
	return (ERROR_NEEDCODING);
}


int pdir_traco_pause()
{
	return ERROR_NEEDCODING;
}


int pdir_traco_resume()
{
	return ERROR_NEEDCODING;
}


int
pdir_traco_corrige_ultimo_id(u_int novo_id) {
	int	    ret;
	traco_t *t_ptr;

	if (traco_novo_ptr == NULL) {
		return ERROR_NOSUCHENTRY;
	}

	t_ptr = tracos_localiza_corrige_id(novo_id);
	if (t_ptr != NULL) {
		ret = do_create_trace_oid_string(t_ptr->pdir_index, t_ptr, novo_id);
		traco_novo_ptr = NULL;
		return ret;
	}

	return ERROR_NOSUCHENTRY;
}


	int
pdir_traco_corrige_id(u_int idlink, u_int idnet, u_int idtrans, u_int idapp, u_int novo_id)
{
	u_int	pdir_hash_index;
	traco_t	*t_ptr;

	pdir_hash_index = pdir_localiza_indice(idlink, idnet, idtrans, idapp);
	t_ptr  = tracos_localiza_corrige_id(novo_id);

	Debug("Corrigindo ID %u do traco com hash indice=%u :%p",
			novo_id, pdir_hash_index, t_ptr);

	if ((pdir_hash_index < PDIR_TAM) && (t_ptr != NULL)) {
		return do_create_trace_oid_string(pdir_hash_index, t_ptr, novo_id);
	}

	return ERROR_NOSUCHENTRY;
}


traco_t *pdir_cria_traco(unsigned int idlink, unsigned int idnet, unsigned int idtrans,
		unsigned int idapp, unsigned int nr_estados, unsigned int nr_msgs,
		unsigned int nr_vars, descricao_t *descr_ptr, unsigned int id)
{
	pdir_node_t	    *pdir_ptr;
	traco_t	    *t_ptr;
	unsigned int    ind;

	Debug("criando traco %x", id);

	/*
	 *	find protocoldir entry
	 */
	pdir_ptr = pdir_localiza(idlink, idnet, idtrans, idapp);
	if (pdir_ptr == NULL) {
		return NULL;
	}

	/*
	 *	get a new trace
	 */
	t_ptr = tracos_aloca_traco(descr_ptr, nr_estados, nr_msgs, nr_vars, id);
	if (t_ptr == NULL) {
		Debug("tracos_aloca_traco() falhou");
		return NULL;
	}

#if 0
	/*
	 *	success!
	 */
	if (do_create_trace_oid_string(ind, t_ptr, id) != SUCCESS) {
		Debug("error while creating OID string");
	}
#endif

	/*
	 *	initially, the trace is out of the real arena.  it will be so
	 *	until the boss tell us otherwise.
	 */
	ind = pdir_localiza_indice(idlink, idnet, idtrans, idapp);
	t_ptr->pdir_index = ind;
	traco_novo_ptr = t_ptr;

	/*
	 *	OK, now we are finished
	 */
	Debug("`%s' alocado [%x]", t_ptr->ident, ind);
	return t_ptr;
}


int pdir_tracos_init()
{
	/* FIXME */
	return SUCCESS;
}


#endif

