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

/* estruturas */
typedef struct ProtDistControl_st {
	uint32_t	dropped_frames;	/* counter32 */
	unsigned long	create_time;	/* sysuptime da última ativação da tabela */

	char		*owner;		/* quem inseriu a entrada */

	int		status;		/* rowstatus */
	unsigned int    index;		/* 1..65535 */
} pdistcontrol_t;


typedef struct ProtDistStats_st {
	unsigned int	control_index;	/* índice no protocolDistControlTable*/
	unsigned int	protdir_index;	/* índice no protocolDirTable */

	uint32_t	pkts;
	uint32_t	octets;

	uint32_t	chave_confirma;
} pdist_stats_t;


/* funções da Control */
unsigned int pdist_control_busca_quantidade();
unsigned int pdist_control_busca_maximo();

int pdist_control_testa(const unsigned int indice);

int pdist_control_busca_status(const unsigned int indice);
int pdist_control_busca_index(const unsigned int indice);
int pdist_control_busca_droppedframes(const unsigned int indice, uint32_t *uint_ptr);
int pdist_control_busca_createtime(const unsigned int indice, uint32_t *uint_ptr);

int pdist_control_busca_owner(const unsigned int indice, char *ptr,
        const unsigned int maximo);

int pdist_control_define_owner(const unsigned int indice, const char *owner_ptr);

int pdist_control_define_status(const unsigned int indice, const int novo_status);

int pdist_control_remove(const unsigned int vitima);

int pdist_control_insere(const unsigned int interface, const uint32_t drp_frames,
	char const *own);

uint32_t *pdist_control_busca_index_addr(const unsigned int indice);

int pdist_control_atualiza_drops(const unsigned int indice, const uint32_t drp_frames);


/* funções da Stats */
unsigned int protdist_stats_getQtd();
int protdist_stats_getControlIndex(const unsigned int index_control,
	const unsigned int index_stats);
int pdist_stats_tabela_busca_controlindex(const unsigned int indice, uint32_t *coloca);

int protdist_stats_getProtIndex(const unsigned int index_control,
	const unsigned int index_stats);
int pdist_stats_tabela_busca_protdirindex(const unsigned int indice, uint32_t *coloca);

int protdist_stats_getPkts(const unsigned int index_control,
	const unsigned int index_stats);
int pdist_stats_tabela_busca_pkts(const unsigned int indice, uint32_t *copia);

int protdist_stats_getOctets(const unsigned int index_control,
	const unsigned int index_stats);
int pdist_stats_tabela_busca_octets(const unsigned int indice, uint32_t *copia);

int protdist_stats_deleteEntry(const unsigned int index_control,
	const unsigned int index_stats);
int protdist_stats_insereAtualiza(const unsigned int index_control,
	const unsigned int index_stats, const uint32_t pkts, const uint32_t octets);

int pdist_stats_tabela_prepara();
int pdist_stats_tabela_primeiro();
int pdist_stats_tabela_prox(uint32_t *resultado);

int pdist_stats_tabela_testa(const unsigned int indice);

void pdist_stats_tabela_debug();

int pdist_stats_remove_cascata(unsigned int pdir_index);

