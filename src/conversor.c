/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2003, 2004 Ricardo Nabinger Sanchez, Diego Wentz Antunes
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
#include <stdint.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h> /* ether_header */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <semaphore.h>

#ifdef __linux__
#	define IP_HEADER		struct iphdr
#	define IP_VERSION(a)	(a->version)
#	define IP_HDRLEN(a)		(a->ihl)
#	define IP_ORIG(a)		(a->saddr)
#	define IP_DEST(a)		(a->daddr)
#	define IP_PROTO(a)		(a->protocol)
#	define TCP_HEADER		struct tcphdr
#	define TCP_SPORT(a)		(a->source)
#	define TCP_DPORT(a)		(a->dest)
#	define TCP_DOFF(a)		(a->doff)
#	define UDP_HEADER		struct udphdr
#	define UDP_SPORT(a)		(a->source)
#	define UDP_DPORT(a)		(a->dest)
#else
#	ifdef __FreeBSD__
#	define IP_HEADER		struct ip
#	define IP_VERSION(a)	(a->ip_v)
#	define IP_HDRLEN(a)		(a->ip_hl)
#	define IP_ORIG(a)		(a->ip_src.s_addr)
#	define IP_DEST(a)		(a->ip_dst.s_addr)
#	define IP_PROTO(a)		(a->ip_p)
#	define TCP_HEADER		struct tcphdr
#	define TCP_SPORT(a)		(a->th_sport)
#	define TCP_DPORT(a)		(a->th_dport)
#	define TCP_DOFF(a)		(a->th_off)
#	define UDP_HEADER		struct udphdr
#	define UDP_SPORT(a)		(a->uh_sport)
#	define UDP_DPORT(a)		(a->uh_dport)
#	else
#	error "Unsupported OS (not GNU/Linux nor FreeBSD)."
#	endif
#endif

#include "configuracao.h"

#include <pthread.h>
#define mtx_lock(a) pthread_mutex_lock(a)
#define mtx_unlock(a) pthread_mutex_unlock(a)

#include "rowstatus.h"
#include "exit_codes.h"
#include "globals.h"

/* includes com ordem */
#if PTSL
#include "stateful.h"
#include "pedb.h"	/* cross dependencies */
#include "tracos.h"
#endif

#include "pedb.h"

#include "sysuptime.h"

#include "conversor.h"

#include "protocoldir.h"
#include "protocoldist.h"

#include "hlhost.h"
#include "nlhost.h"
#include "alhost.h"

#include "hlmatrix.h"
#include "nlmatrix_SD.h"
#include "nlmatrix_DS.h"
#include "almatrix_SD.h"
#include "almatrix_DS.h"
#include "settings.h"

#include "fila_cap.h"


/* colorir mensagens graves no terminal */
static char error_color_string[] = "\033[1;41;37m";
static char reset_color_string[] = "\033[0m";

static char *dev;

/* porquice */
//static char dev[] = "eth0";
static char owner[] = "monitor";


/*****************************************************************************
  Fila de pacotes
 ****************************************************************************/
static fila_t		fila[FILA_MAX] = {{0, {0,}},};   /* o vetor de pacotes */

static pthread_mutex_t	fila_pthmutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t	thr_captura;
static sem_t		fila_semaforo;		/* semáforo para proteger fila_tam */


static uint32_t    	fila_tam = 0;		/* tamanho da fila (crítico) */
static uint32_t    	fila_descartes = 0;	/* pacotes descartados */
static uint32_t    	fila_inseridos = 0;	/* pacotes inseridos na fila */
static unsigned int	fila_cabeca = 0;	/* índice da cabeça da fila */
static unsigned int	fila_fim = 0;		/* índice do final da fila */


#if FILA_DEBUG
/* mostrar dados da fila - debug */
static void fila_info()
{
	static int semvalue;

	sem_getvalue(&fila_semaforo, &semvalue);
	fprintf(stderr, "  fila: [%u], inicio: %u, fim: %u, inserções: %u, descartes: %u, semaforo: %d\n",
			fila_tam, fila_cabeca, fila_fim, fila_inseridos, fila_descartes, semvalue);
}
#endif


/*
   função para uma thread:
   fica eternamente tentando coletar pacotes, não retorna
 */
static void *fila_coleta()
{
	char		erro_pcap_string[PCAP_ERRBUF_SIZE] = {'\0',};
	struct pcap_pkthdr	header;

#ifdef __linux__
	struct sched_param	schedparams;
	int					policy;
#endif

	const u_char	*data_ptr;
	pcap_t		*captura;

	fprintf(stderr, "fila: pid %d\n", getpid());

	/* We'll ask for SCHED_RR scheduling policy */
#ifdef __linux__
	if (pthread_getschedparam(pthread_self(), &policy, &schedparams) == 0) {
		schedparams.sched_priority = sched_get_priority_max(SCHED_RR);
		if (pthread_setschedparam(pthread_self(), SCHED_RR, &schedparams) == 0) {
			fprintf(stderr, "conversor: Wheee! we're using SCHED_RR! :)\n");
		}
		else {
			fprintf(stderr, "conversor: could NOT set SCHED_RR\n");
			perror("damn: ");
		}
	}
	else {
		fprintf(stderr, "conversor: pthread_getschedparam() failed\n");
	}
#endif

	/* FIXME colocar "escolhedor" de dev e esquema pra verificar se é ethernet */
	/* abrir interface "dev", capturando SNAPLEN bytes, em modo promíscuo (1),
	   sem (-1) timeout de leitura */
	dev = conf_get_interface();
	if (dev == NULL) {
		fprintf(stderr, "%s:%d: error while trying to open network interface\n",
				__FILE__, __LINE__);
		return (void *)ERROR_IO;
	}
	fprintf(stderr, "abrindo: `%s'\n", dev);
#ifdef __FreeBSD__
	captura = pcap_open_live(dev, FILA_SNAPLEN, 1, 1000, erro_pcap_string);
#endif
#ifdef __linux__
	captura = pcap_open_live(dev, FILA_SNAPLEN, 1, -1, erro_pcap_string);
#endif
	if (captura == NULL) {
		pcap_perror(captura, "conversor: ");
		return (void *)ERROR_IO;
	}
#ifdef __FreeBSD__
	/* Ask non-blocking I/O */
	if (pcap_get_selectable_fd(captura) == -1) {
		fprintf(stderr, "fila: non-blocking I/O refused :(\n");
	}
#endif

	while (1) {
		data_ptr = pcap_next(captura, &header);

		if (data_ptr) {
			if (fila_tam < FILA_MAX) {
				/* data_ptr não é NULL, fila tem espaço */
				fila[fila_cabeca].tam = header.len;
				memcpy(fila[fila_cabeca].dados, data_ptr, FILA_SNAPLEN);
				fila_cabeca = (fila_cabeca + 1) % FILA_MAX;

				/* entering critical section */
				mtx_lock(&fila_pthmutex);
				fila_tam++;
				/* exiting critical section */
				mtx_unlock(&fila_pthmutex);

				fila_inseridos++;

				/* "avisar" chegada de pacote */
				sem_post(&fila_semaforo);
			}
			else {
				/* fila cheia */
				fila_descartes++;
				//		sched_yield();
			}

#if FILA_DEBUG
			fila_info();
#endif

		}
	}
}


/*
 * apenas atualiza o tamanho da fila e o fim (???)
 */
	static void
fila_remove()
{
	fila_fim = (fila_fim + 1) % FILA_MAX;

	/* entering critical section */
	mtx_lock(&fila_pthmutex);
	fila_tam--;

	/* exiting critical section */
	mtx_unlock(&fila_pthmutex);

#if FILA_DEBUG
	fila_info();
#endif
}


/*
   entrega o proximo pacote, se houver
   */
static void fila_proximo()
{
	while (fila_tam == 0) {
		sem_wait(&fila_semaforo);
	}
}


static int fila_inicializa()
{
	if (sem_init(&fila_semaforo, 0, 0) != 0) {
		return ERROR_PKTQUEUE;
	}

	return SUCCESS;
}
/*****************************************************************************/


static int conv_preprocessa_pacote(const u_char *packet, pedb_t *prepacote)
{
	struct ether_header	*ether;
	IP_HEADER		*ip;
	TCP_HEADER		*tcp;
	UDP_HEADER		*udp;
	uint16_t		*u16_ptr;

	ether = (struct ether_header *)packet;
	if (ntohs(ether->ether_type) == ETHERTYPE_IP) {
		/* camada de rede OK */
		prepacote->prot_enlace = 1;
	}
	else {
		/* não é um pacote ethernet válido para nós */
		return ERROR_LINKLAYER;
	}

	/* pula o cabeçalho ethernet */
	ip = (IP_HEADER *)(packet + 14);
	if (IP_VERSION(ip) == 4) {
		/* bom */
		prepacote->prot_rede = ETHERTYPE_IP;
		prepacote->ip_orig = IP_ORIG(ip);
		prepacote->ip_dest = IP_DEST(ip);
		/* NEW */
		prepacote->offset_rede = 14;
		prepacote->offset_trans = prepacote->offset_rede + IP_HDRLEN(ip) * 4;
	}
	else {
		/* pacote IP inválido para nós */
		return ERROR_NETWORKLAYER;
	}

	/* verificar se o pacote é broadcast */
	u16_ptr = (uint16_t *)ether->ether_dhost;
	if ((u16_ptr[0] & u16_ptr[1] & u16_ptr[2]) == 0xffff) {
		/* pacote é broadcast sim */
		prepacote->is_broadcast = 1;
	}
	else {
		prepacote->is_broadcast = 0;
	}

	/* verificar por TCP */
	if (IP_PROTO(ip) == IPPROTO_TCP) {
		tcp = (struct tcphdr *)(packet + prepacote->offset_trans);
		prepacote->prot_transporte = IPPROTO_TCP;
		prepacote->rede_sport = ntohs(TCP_SPORT(tcp));
		prepacote->rede_dport = ntohs(TCP_DPORT(tcp));
		prepacote->offset_aplic = prepacote->offset_trans + TCP_DOFF(tcp) * 4;
	}
	else {
		/* verificar por UDP */
		if (IP_PROTO(ip) == IPPROTO_UDP) {
			udp = (struct udphdr *)(packet + prepacote->offset_trans);
			prepacote->prot_transporte = IPPROTO_UDP;
			prepacote->rede_sport = ntohs(UDP_SPORT(udp));
			prepacote->rede_dport = ntohs(UDP_SPORT(udp));
			prepacote->offset_aplic = prepacote->offset_trans + 8;
		}
		else {
			/* verificar por ICMP */
			if (IP_PROTO(ip) == IPPROTO_ICMP) {
				prepacote->prot_transporte = IPPROTO_ICMP;
				prepacote->rede_sport = 0;
				prepacote->rede_dport = 0;
				prepacote->offset_aplic = prepacote->offset_trans + 8;
			}
			else {
				return ERROR_TRANSPLAYER;
			}
		}
	}

	/* FIXME */
	prepacote->interface = 2;

	//    fprintf(stderr, "offsets: %3u | %3u | %3u\n", prepacote->offset_rede,
	//	    prepacote->offset_trans, prepacote->offset_aplic);

	/* terminou bem */
	return SUCCESS;
}


static int conv_processa_prepacote(pedb_t *dados)
{
	pdir_node_t	*pdir_ptr;

#if DEBUGMSG_INFO_PACOTE
	char	informacao[10] = "   [ERTA]\0";
#endif

	if (hlhost_getRowstatus(dados->interface) != ROWSTATUS_ACTIVE) {
		fprintf(stderr, "conversor: interface %d na HlHost inativa\n",
				dados->interface);
		return ERROR_ISINACTIVE;
	}

	if (pdist_control_busca_status(dados->interface) != ROWSTATUS_ACTIVE) {
		fprintf(stderr, "conversor: interface %d na protocolDist inativa\n",
				dados->interface);
		return ERROR_ISINACTIVE;
	}

#if DEBUGMSG_INFO_PACOTE
	fprintf(stderr, "\033[0;37m Pacote: %d.%d.%d.(%ds/%dd)", dados->prot_enlace, dados->prot_rede,
			dados->prot_transporte, dados->rede_sport, dados->rede_dport);
#endif

	/* achar encapsulamento enlace.rede.(null).(null) */
	pdir_ptr = pdir_localiza(dados->prot_enlace, dados->prot_rede, 0, 0);

	if (pdir_ptr != NULL) {
		/* encapsulamento encontrado - salvar o localindex */
		dados->nl_localindex = pdir_ptr->local_index;
#if DEBUGMSG_PROC_PACOTE
		fprintf(stderr, "\033[0;34menlace.rede.(null).(null)\n");
#endif
#if DEBUGMSG_INFO_PACOTE
		informacao[4] = 'E';
		informacao[5] = 'R';
#endif
		if (protdist_stats_insereAtualiza(dados->interface, pdir_ptr->local_index,
					1, dados->tamanho) != SUCCESS) {
			fprintf(stderr, "%sconversor: protdist_stats_insereAtualiza() falhou%s\n",
					error_color_string, reset_color_string);
		}
		/* encapsulamento suporta nlhost? */
		if (pdir_ptr->host_config == PDIR_CFG_supportedOn) {
			if (nlhost_insereAtualiza(dados) != SUCCESS) {
				fprintf(stderr, "%sconversor: nlhost_insereAtualiza() falhou%s\n",
						error_color_string, reset_color_string);
			}
		}

		/* encapsulamento suporta nlmatrix? */
		if (hlmatrix_getRowstatus(dados->interface) == ROWSTATUS_ACTIVE) {
			/* pacote unicast e nlmatrix suportada */
			if (pdir_ptr->matrix_config == PDIR_CFG_supportedOn) {
				nlmatrix_SD_insereAtualiza(dados);
				nlmatrix_DS_insereAtualiza(dados);
			}
		}

#if PTSL
		dados->prim_traco_rede = pdir_ptr->primeiro_traco;
#endif
	}
	else {
#if DEBUGMSG_INFO_PACOTE
		informacao[4] = '-';
		informacao[5] = '-';
#endif
#if PTSL
		dados->prim_traco_rede = NULL;
#endif
	}

	/* achar encapsulamento enlace.rede.transporte.(null) */
	pdir_ptr = pdir_localiza(dados->prot_enlace, dados->prot_rede,
			dados->prot_transporte, 0);

	if (pdir_ptr != NULL) {
		/* encapsulamento encontrado */
#if DEBUGMSG_PROC_PACOTE
		fprintf(stderr, "\033[0;36menlace.rede.transporte.(null)\n");
#endif
#if DEBUGMSG_INFO_PACOTE
		informacao[6] = 'T';
#endif
		dados->al_localindex = pdir_ptr->local_index;

		if (protdist_stats_insereAtualiza(dados->interface, pdir_ptr->local_index,
					1, dados->tamanho) != SUCCESS) {
			fprintf(stderr, "%sconversor: protdist_stats_insereAtualiza() falhou%s\n",
					error_color_string, reset_color_string);
		}

		/* encapsulamento suporta alhost? */
		if (pdir_ptr->host_config == PDIR_CFG_supportedOn) {
			if (alhost_insereAtualiza(dados) != SUCCESS) {
				fprintf(stderr, "%sconversor: alhost_insereAtualiza() falhou%s\n",
						error_color_string, reset_color_string);
			}
		}

		/* encapsulamento suporta almatrix? */
		if ((pdir_ptr->matrix_config == PDIR_CFG_supportedOn) &&
				(hlmatrix_getRowstatus(dados->interface) == ROWSTATUS_ACTIVE)) {
			if (almatrix_SD_insereAtualiza(dados) != SUCCESS) {
				fprintf(stderr, "%sconversor: almatrix_SD_insereAtualiza() falhou%s\n",
						error_color_string, reset_color_string);
			}
			if (almatrix_DS_insereAtualiza(dados) != SUCCESS) {
				fprintf(stderr, "%sconversor: almatrix_DS_insereAtualiza() falhou%s\n",
						error_color_string, reset_color_string);
			}
		}
#if PTSL
		dados->prim_traco_transporte = pdir_ptr->primeiro_traco;
#endif
	}
	else {
#if DEBUGMSG_INFO_PACOTE
		informacao[6] = '-';
#endif
#if PTSL
		dados->prim_traco_transporte = NULL;
#endif
	}

	/* achar encapsulamento enlace.rede.transporte.aplicacao, primeiro com a porta
	   de origem. se não encontrar, trocar pela de destino e tentar de novo*/
#if PTSL
	if ((dados->rede_sport == 0) && (dados->rede_dport == 0)){
		/* packet has no application layer (eg: ICMP) */
		dados->prim_traco_aplicacao = NULL;
		dados->direcao = FROM_ANY;
		return SUCCESS;
	}
#endif
	pdir_ptr = pdir_localiza(dados->prot_enlace, dados->prot_rede,
			dados->prot_transporte, dados->rede_sport);
	if (pdir_ptr == NULL) {
		pdir_ptr = pdir_localiza(dados->prot_enlace, dados->prot_rede,
				dados->prot_transporte, dados->rede_dport);
		if (pdir_ptr == NULL) {
			/*
			 *	protocol is not registered -- get out
			 */
#if DEBUGMSG_INFO_PACOTE
			informacao[7] = '-';
#endif
#if PTSL
			dados->prim_traco_aplicacao = NULL;
			dados->direcao = FROM_ANY;
#endif
			return SUCCESS;
		}
		else {
			/*
			 *	found with destination as the server
			 */
#if PTSL
			dados->direcao = FROM_CLIENT;
			dados->ip_cliente = dados->ip_orig;
			dados->ip_servidor = dados->ip_dest;
			dados->porta_cliente = dados->rede_sport;
			dados->porta_servidor = dados->rede_dport;
#endif
		}
	}
	else {
		/*
		 *  found with source as the server
		 */
#if PTSL
		dados->direcao = FROM_SERVER;
		dados->ip_cliente = dados->ip_dest;
		dados->ip_servidor = dados->ip_orig;
		dados->porta_cliente = dados->rede_dport;
		dados->porta_servidor = dados->rede_sport;
#endif
	}

	/* salvar o localindex para as Al* */
	dados->al_localindex = pdir_ptr->local_index;
#if DEBUGMSG_PROC_PACOTE
	fprintf(stderr, "\033[1;32menlace.rede.transporte.aplicacao\n");
#endif
#if DEBUGMSG_INFO_PACOTE
	informacao[7] = 'A';
#endif
	if (protdist_stats_insereAtualiza(dados->interface, pdir_ptr->local_index,
				1, dados->tamanho) != SUCCESS) {
		fprintf(stderr, "%sconversor: protdist_stats_insereAtualiza() falhou%s\n",
				error_color_string, reset_color_string);
	}

	/* encapsulamento suporta alhost? */
	if (pdir_ptr->host_config == PDIR_CFG_supportedOn) {
		if (alhost_insereAtualiza(dados) != SUCCESS) {
			fprintf(stderr, "%sconversor: alhost_insereAtualiza falhou%s\n",
					error_color_string, reset_color_string);
		}
	}

	/* encapsulamento suporta almatrix? */
	if (pdir_ptr->matrix_config == PDIR_CFG_supportedOn) {
		if (hlmatrix_getRowstatus(dados->interface) == ROWSTATUS_ACTIVE) {
			if (almatrix_SD_insereAtualiza(dados) != SUCCESS) {
				fprintf(stderr, "%sconversor: almatrix_SD_insereAtualiza() falhou%s\n",
						error_color_string, reset_color_string);
			}

			if (almatrix_DS_insereAtualiza(dados) != SUCCESS) {
				fprintf(stderr, "%sconversor: almatrix_DS_insereAtualiza() falhou%s\n",
						error_color_string, reset_color_string);
			}
		}
	}

#if PTSL
	dados->prim_traco_aplicacao = pdir_ptr->primeiro_traco;
#endif

#if DEBUGMSG_INFO_PACOTE
	fprintf(stderr, "%s\n", informacao);
#endif

	return SUCCESS;
}


#if MEDIR_DESEMPENHO
#include "rdtsc.h"
#endif


/* function that manage the conversion of entries of conexao table (DB cap_pac)
   to the tables of DB RMON2 */
void *captura_processa_pacote()
{
#if MEDIR_DESEMPENHO
	uint64_t	    ticks_ini;
	uint64_t	    ticks_meio;
	uint64_t	    ticks_fim;
	uint32_t	    aguardar = AGUARDAR;    /* medir o tempo para 10, 100, 1000 pacotes */
	uint32_t	    medidos = 0;	    /* pacotes já medidos */
	FILE	    *arq_ptr;

	static const uint32_t AGUARDAR = 1000;
#endif

	pedb_t	    prepacote;

	fprintf(stderr, "conversor: pid %d\n", getpid());

#if MEDIR_DESEMPENHO
	arq_ptr = fopen("/tmp/conversor.data", "w");
	if (arq_ptr == NULL) {
		fprintf(stderr, " *** conversor: sem poder gravar dados\n");
		exit(-10);
	}
#endif

	/* inicializar a fila */
	if (fila_inicializa() != SUCCESS) {
		return (void *)ERROR_PKTQUEUE;
	}

	if (pthread_create(&thr_captura, NULL, fila_coleta, NULL) != 0) {
		fprintf(stderr, "%sconversor: pthread_create() falhou%s\n",
				error_color_string, reset_color_string);
		return (void *)ERROR_THREAD;
	}

	/* capturar e processar os pacotes */
	while (1) {

#if MEDIR_DESEMPENHO
		aguardar--;
		if (aguardar == 0) {
			/* hora de medir */
			rdtsc(ticks_ini);
		}
#endif

		/* aguarda pacote */
		fila_proximo();

		/* chegou! */
		prepacote.uptime = sysuptime();
		prepacote.tamanho = fila[fila_fim].tam;

		if (conv_preprocessa_pacote(fila[fila_fim].dados, &prepacote) == SUCCESS) {
			conv_processa_prepacote(&prepacote);
#if PTSL
			if ((prepacote.prim_traco_rede != NULL) ||
					(prepacote.prim_traco_transporte != NULL) ||
					(prepacote.prim_traco_aplicacao != NULL)) {
				tracos_verifica(&prepacote, fila[fila_fim].dados);
			}
#endif
		}

		/* remover pacote */
		fila_remove();

#if MEDIR_DESEMPENHO
		if (aguardar == 0) {
			rdtsc(ticks_fim);
			medidos += AGUARDAR + drop_atual;
			aguardar = AGUARDAR;

			fprintf(arq_ptr, "%u %0.0f %0.0f %0.0f %u\n", medidos, (double)ticks_ini,
					(double)ticks_meio, (double)ticks_fim, drop_acumulado);
			fflush(arq_ptr);
		}
#endif
	}
}


int conv_inicializa()
{
	if (pdist_control_insere(2, 0, owner) != SUCCESS) {
		fprintf(stderr, "%sconversor: pdist_control_insere(2, 0, %s) != SUCCESS%s\n",
				error_color_string, owner, reset_color_string);
		return ERROR_REALLYBAD;
	}

	if (hlhost_insere(2, owner) != SUCCESS) {
		fprintf(stderr, "%sconversor: hlhost_insere(2, %s) falhou%s\n",
				error_color_string, owner, reset_color_string);
		return ERROR_REALLYBAD;
	}

	if (hlmatrix_insere(2, owner) != SUCCESS) {
		fprintf(stderr, "%sconversor: hlmatrix_insere(2, %s) falhou%s\n",
				error_color_string, owner, reset_color_string);
		return ERROR_REALLYBAD;
	}

	return SUCCESS;
}


//	/* verificar se houve perda de pacotes */
//	if (pcap_stats(cap, &stats) == 0) {
//	    /* stats.ps_drop tem o numero de pacotes descartados desde a ultima consulta */
//	    drop_atual = stats.ps_drop;
//	    if (drop_atual != drop_quantidade) {
//		/* houve perda de pacotes */
//		drop_quantidade = drop_atual;
//		drop_acumulado += drop_atual;
//
//		/* atualizar tabelas */
//		if (protdist_control_updateEntry(prepacote.interface, drop_acumulado) != SUCCESS) {
//		    fprintf(stderr, "%srmon2.conversor.captura_processa_pacote(): updateEntry falhou%s\n",
//			    error_color_string, reset_color_string);
//		}
//
//		if (hlhost_atualizaNlDroppedFrames(prepacote.interface, drop_acumulado) != SUCCESS) {
//		    fprintf(stderr, "%sconversor: hlhost_atualizaNlDroppedFrames(%d, %u) falhou%s\n",
//			    error_color_string, prepacote.interface, drop_acumulado,
//			    reset_color_string);
//		}
//
//		if (hlhost_atualizaAlDroppedFrames(prepacote.interface, drop_acumulado) != SUCCESS) {
//		    fprintf(stderr, "%sconversor: hlhost_atualizaAlDroppedFrames(%d, %u) falhou%s\n",
//			    error_color_string, prepacote.interface, drop_acumulado,
//			    reset_color_string);
//		}
//
//		if (hlmatrix_atualizaNlDroppedFrames(prepacote.interface, drop_acumulado) != SUCCESS) {
//		    fprintf(stderr, "%sconversor: hlmatrix_atualizaNlDroppedFrames(%d, %u) falhou%s\n",
//			    error_color_string, prepacote.interface, drop_acumulado,
//			    reset_color_string);
//		}
//
//		if (hlmatrix_atualizaAlDroppedFrames(prepacote.interface, drop_acumulado) != SUCCESS) {
//		    fprintf(stderr, "%sconversor: hlmatrix_atualizaAlDroppedFrames(%d, %u) falhou%s\n",
//			    error_color_string, prepacote.interface, drop_acumulado,
//			    reset_color_string);
//		}
//
//		fprintf(stderr, "ARGH! perda de pacote!\n");
//	    }
//	}

