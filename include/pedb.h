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

#ifndef __PEDB_H
#define __PEDB_H

typedef struct PEDB_st {
	int		is_broadcast;	/* flag: 0 = unicast; 1 = broadcast */
	int		prot_enlace;	/* protocolo do enlace (0 ou ETHERTYPE_IP) */
	int		prot_rede;	/* protocolo de rede (0 ou ETHERTYPE_IP) */
	int		prot_transporte;/* IPPROTO_TCP ou IPPROTO_UDP */
	int		rede_sport;	/* porta origem */
	int		rede_dport;	/* porta destino */
	unsigned int    interface;	/* a interface de captura (1, até descobrir pq é 1) */
	int		tamanho;	/* tamanho do pacote */
	unsigned long	uptime;		/* uptime da máquina na hora que o pacote chegou */
	in_addr_t	ip_orig;	/* endereço IP origem */
	in_addr_t	ip_dest;	/* endereço IP destino */
	unsigned int    nl_localindex;	/* indice do encapsulamento de rede */
	unsigned int    al_localindex;	/* indice do encapsulamento de aplicação */

	unsigned int    offset_rede;	/* offset in bytes from 0 to network protocol */
	unsigned int    offset_trans;	/* transport protocol */
	unsigned int    offset_aplic;	/* application protocol */

#if PTSL
	unsigned int    direcao;	/* tells whether packet is from client or server */
	in_addr_t	ip_cliente;	/* endereço IP do cliente */
	in_addr_t	ip_servidor;	/* endereço IP do servidor */
	unsigned int    porta_cliente;
	unsigned int    porta_servidor;

	/* heads of the lists of traces we can test */
	traco_t		*prim_traco_rede;
	traco_t		*prim_traco_transporte;
	traco_t		*prim_traco_aplicacao;
#endif
} pedb_t;

#endif /* __PEDB_H */
