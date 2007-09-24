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

int tracos_preenche_variavel(variavel_t *ptr, char *id_ptr, unsigned int tamanho_minimo,
	unsigned int offset, unsigned int isbit, char *bitstring);

int tracos_preenche_mensagem(mensagem_t *ptr, char *id_ptr, unsigned int tamanho_chave,
	unsigned char *chave, unsigned int offset, unsigned int tipo_mensagem,
	unsigned int comparacao, unsigned int operacao, unsigned int timeout,
	variavel_t *var_ptr, unsigned int direcao, unsigned int f_encaps);

int tracos_preenche_estado_final(traco_t *t_ptr, estado_t *e_ptr);

int tracos_preenche_estado(estado_t *ptr, char *id_ptr, unsigned int i_depende,
	depende_t *dep_ptr, estado_t *prox);

traco_t *tracos_aloca_traco(descricao_t *descricao_ptr, unsigned int i_estados,
	unsigned int i_mensagens, unsigned int i_variaveis, unsigned int id_num);

traco_t *tracos_localiza_por_id(const unsigned int id);

traco_t *tracos_localiza_corrige_id(const unsigned int id);

int tracos_verifica(pedb_t *prepacote, unsigned char *area_dados_ptr);

