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

#define PDIR_CFG_notSupported	1
#define PDIR_CFG_supportedOff	2
#define PDIR_CFG_supportedOn	3

#define CONFIG_NOT_SUPPORTED	1
#define CONFIG_SUPPORTED_OFF	2
#define CONFIG_SUPPORTED_ON	3

typedef struct ProtDir_struct {
    /* para facilitar a vida da hash */
	uint32_t	transp_aplic;
	uint32_t	enlace_rede;

	char		*descricao;
	char		*owner;

	uint32_t	idlink;
	uint32_t	idnet;
	uint32_t	idtrans;
	uint32_t	idapp;

	unsigned int	local_index;
	unsigned int	addrmap_config;
	unsigned int	host_config;
	unsigned int	matrix_config;
	unsigned int	row_status;

	unsigned char	param1;
	unsigned char	param2;
	unsigned char	param3;
	unsigned char	param4;
	unsigned char	tipo;

#if	PTSL
	unsigned int	nr_tracos;
	traco_t	*primeiro_traco;
	traco_t	*ultimo_traco;
#endif
} pdir_node_t;


/* protótipos */
pdir_node_t *pdir_localiza(const unsigned int enlace, const unsigned int rede,
	const unsigned int transporte, const unsigned int aplicacao);

int protdir_init();
int init_protocoldir(char *filename);

void protdir_dumpTable();

unsigned int pdir_encapsulamentos();
unsigned long pdir_busca_lastchange();

int protdir_insere(pdir_node_t *pdir_ptr);
int pdir_remove(const unsigned int e, const unsigned int r,
	const unsigned int t, const unsigned int a);

int pdir_busca_id_octetstring(const unsigned int indice, char *ptr,
        const unsigned int maximo);
int pdir_busca_param_octetstring(const unsigned int indice, char *ptr,
        const unsigned int maximo);

int pdir_tabela_busca_localindex(const unsigned int indice, uint32_t *ptr);
int pdir_tabela_busca_tipo(const unsigned int indice, unsigned char *ptr);
int pdir_tabela_busca_addrmapconfig(const unsigned int indice, unsigned int *ptr);
int pdir_tabela_busca_hostconfig(const unsigned int indice, unsigned int *ptr);
int pdir_tabela_busca_matrixconfig(const unsigned int indice, unsigned int *ptr);
int pdir_tabela_busca_status(const unsigned int indice, unsigned int *ptr);

int pdir_tabela_busca_descr(const unsigned int indice, char *ptr,
        const unsigned int maximo);
int pdir_tabela_busca_owner(const unsigned int indice, char *ptr,
        const unsigned int maximo);

//int protdir_setDescr(const int index, const char *descricao, const int str_len);
int pdir_define_descr(const unsigned int e, const unsigned int r,
	const unsigned int t, const unsigned int a, const char *descr);
//int protdir_setOwner(const int index, char *owner_str, const int str_len);
int pdir_define_owner(const unsigned int e, const unsigned int r,
	const unsigned int t, const unsigned int a, const char *owner);

//int protdir_setAddrMapCfg(const int index, const unsigned char valor);
int pdir_define_addrmap_config(const unsigned int e, const unsigned int r,
	const unsigned int t, const unsigned int a, const unsigned int config);
//int protdir_setHostCfg(const int index, const unsigned char valor);
int pdir_define_host_config(const unsigned int e, const unsigned int r,
	const unsigned int t, const unsigned int a, const unsigned int config);
//int protdir_setMatrixCfg(const int index, const unsigned char valor);
int pdir_define_matrix_config(const unsigned int e, const unsigned int r,
	const unsigned int t, const unsigned int a, const unsigned int config);

//int protdir_setStatus(const int index, const unsigned char novo_stat);
int pdir_define_status(const unsigned int e, const unsigned int r,
	const unsigned int t, const unsigned int a, const unsigned int status);

int pdir_tabela_primeiro(unsigned int *res);
int pdir_tabela_proximo(unsigned int *res);

int pdir_tabela_testa(const unsigned int indice);

#if PTSL
int pdir_possui_traco(const unsigned int indice);

traco_t *pdir_primeiro_traco(const unsigned int indice);

int pdir_traco_busca_idstring(traco_t *traco, unsigned char *str, unsigned int tam);

int pdir_traco_run(const unsigned int id_traco);

traco_t *pdir_cria_traco(unsigned int idlink, unsigned int idnet, unsigned int idtrans,
	unsigned int idapp, unsigned int nr_estados, unsigned int nr_msgs,
	unsigned int nr_vars, descricao_t *descr_ptr, unsigned int id);

int pdir_tracos_init();

int pdir_traco_corrige_ultimo_id(u_int novo_id);

int pdir_traco_corrige_id(unsigned int idlink, unsigned int idnet, unsigned int idtrans,
       unsigned int idapp, unsigned int novo_id);
#endif
