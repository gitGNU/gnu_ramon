/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2004 Diego Wentz Antunes, Ricardo Nabinger Sanchez
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


%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "trasserlib.h"

#ifndef DEBUG
#define DEBUG 0
#endif
#ifndef SUCCESS
#define SUCCESS 0
#endif


int yyerror(const char *);
//int yylex(void);

extern int yylineno;
extern char* yytext[];
int merror = 0;
int noerror = 1;
int newcounter = 0;
int f1 = 0;
int f2 = 0;
int f3 = 0;
int f4 = 0;
int f5 = 0;
int f6 = 0;
int f7 = 0;
unsigned int nr_estados, nr_msgs, nr_vars, nr_tracos;
unsigned int id_filtro = 0;
unsigned int id_estado = 1;

MYFIELD_COUNTER 	*f = 0;
MYLFIELD_COUNTER 	*lf = 0;
MYLFIELD_COUNTER 	*tf = 0;
MYBIT_COUNTER   	*b = 0;
MYLBIT_COUNTER		*lb = 0;
MYLBIT_COUNTER		*tb = 0;
MYNO_OFFSET		*n = 0;

%}

//typedef struct {
%union {
	char		    stval[100];
	char		    *ptr;
	unsigned int	    iValue;
	MYTRACE		    *ytrace;
	MYHEADER	    *yheader;
	MYMESSAGES_SEC	    *ymsgs;
	MYMESSAGES_SEC_C    *ymsgs_sec_c;
	MYGROUPS_SEC	    *ygroups;
	MYSTATES_SEC	    *ystates;
	MYSTATES_SEC_FIELD  *ystates_field;
	MYSFIELD	    *ymysfield;
	MYFIELD_COUNTER	    *yfield;
	MYLFIELD_COUNTER    *ylfield;
	MYBIT_COUNTER	    *ybit;
	MYLBIT_COUNTER	    *ylbit;
	MYNO_OFFSET	    *ynooffset;
	void *		    *yvoid;
}
    // v;
//} YYSTYPE;


/******************************************************************************
			Token Definitions
******************************************************************************/
%token	ALPHA DIGIT NUMBER INFTEXT TIME MONTH WKDAY ID DQ_INF DP DATE VIRGULA
%token	UINT CLIENT SERVER VERB_IDENTIFIER MESSAGES GMT NL REFERENCE INFTEXTT
%token	HEADER VERSION DESCRIPTION KEY PORT OWNER LAST_UPDATE ENCAP KEYWORD VERSION_NUMBER
%token	WILDCARD PROT_ENC WID DTIME OPERATOR BEHAVIOR
%token	STRACE DQID ENDSTRACE DDQID
%token	MESSAGES_SECTION MESSAGE END_MESSAGES_SECTION
%token	MESSAGE_CONTENT END_MESSAGE
%token	MESSAGE_TYPE MTYPE MESSAGE_TIMEOUT
%token	GROUPS_SECTION GROUPS_SECTION_CONTENT END_GROUPS_SECTION
%token	GROUP_CONTENT END_GROUP
%token	STATES_SECTION END_STATE END_STATES_SECTION FINAL_STATE GOTO_STATE
%token	FIELD_COUNTER BIT_COUNTER NOOFFSET
%token	GROUP STATE DATE_TIME FLV FTV BLV BTV
%type	<stval>	    DQID STRACE ENDSTRACE DQ_INF ID VERSION_NUMBER DP OPERATOR
%type	<stval>	    VERSION DESCRIPTION KEY PORT OWNER TIME MTYPE VIRGULA GMT BEHAVIOR
%type	<stval>	    INFTEXT KEYWORD DATE_TIME MONTH WKDAY NL UINT WILDCARD PROT_ENC
%type	<stval>	    VERB_IDENTIFIER LAST_UPDATE DDQID WID REFERENCE INFTEXTT DTIME
%type	<stval>	    FLV FTV BLV BTV ENCAP
%type	<stval>	    MESSAGES_SECTION MESSAGE MESSAGE_TYPE MESSAGE_TIMEOUT END_MESSAGE
%type	<stval>	    GROUPS_SECTION GROUP MESSAGES END_GROUP END_GROUPS_SECTION
%type	<stval>	    STATES_SECTION FINAL_STATE STATE GOTO_STATE END_STATE END_STATES_SECTION
%type	<iValue>    DIGIT NUMBER
%type	<ytrace>    trace cards
%type	<yheader>   header
%type	<ymsgs>	    messages_section messages_section_content message_content
%type	<ygroups>   groups_section_content group_content groups_section
%type	<ystates>   states_section_contents states_section_content states_section
%type	<ystates_field> state_contents state_content
%type	<ymysfield> state_fields state_field
%type	<yfield>    field_counters field_counter
%type	<ylfield>   flvs flv ftvs ftv
%type	<ybit>	    bit_counters bit_counter
%type	<ylbit>	    blvs blv btvs btv
%type	<ynooffset> nooffsets nooffset
%type	<ymsgs_sec_c> counters
%type	<yvoid>	    counter
%type	<ptr>	    version description key port owner encap last_update field_uint wild_id
%type	<ptr>	    dqid_trace version_desc description_desc key_desc port_desc owner_desc
%type	<ptr>	    dqid_msgs dqid_bit dqid_no dqid_grp dqid_grp_msgs encap_desc
%type	<ptr>	    message_t prot_field prot_bit prot_no message_timeout
%type	<ptr>	    dqid_grp group_msgs verb_id state_id last_desc reference ref_desc
%type	<ptr>	    f_operator b_operator behave dqinf_field state_dqid identifier
%type	<ptr>	    bit_uinti bit_uintii ident

%start data
%%

/******************************************************************************
    Start TRACE Parser
******************************************************************************/

data		: cards {
/**
 *	Dentro deste bloco de codigo, tu pode verificar se o arquivo de traco foi
 *	parseado com sucesso ou nao, se o valor da variavel merror for igual a 1 entao
 *	um ou mais erros foram encontrados. Dependendo disso tu podes continuar com o
 *	processo ou nao.
 */
		    if (noerror)    {
			printf("Parser Complete.\n");
			/* Run very important things on */
			displayDataStruct($1);
			/* Populates aome of the Agent structures */
			popTrace($1);
			/* Free the memory allocated by the Trasser */
			freeTrace($1);

		    } else if (1 == merror)	{
			printf("Problems in PTSL declaration, please check your file.\n");
		    }
		}
		;

cards		: trace {
		        $$ = $1;
			if (DEBUG)
			    printf("Trace reconized.\n");
		    }
	        | cards trace {
		    if (noerror) {
		        int no = 2;
		        nr_tracos = 2;
		        MYTRACE *temp = $$;
		        while (temp->next) {
			    temp = temp->next;
			    no++;
			    nr_tracos++;
			}
			temp->next = $2;
			if (DEBUG)
			    printf("    Assigned %dth Trace.\n", no);
		    }
		}
		| error {
		    yyerror("Error in Trace input file.\n");
		    YYABORT;
		}
		;

/******************************************************************************

    Start Global TRACE Parser

******************************************************************************/
trace		: STRACE dqid_trace header messages_section groups_section states_section ENDSTRACE {
			MYTRACE *trace = getNewTrace();
			if (trace == NULL) {
			    printf("Could not allocate trace memory.\n");
			    return (-1);
			}
			trace->traceName = $2;
			trace->head = $3;
			trace->msgs_sec = $4;
			trace->groups_sec = $5;
			trace->states_sec = $6;
			$$ = trace;
			if (DEBUG)
			    printf("Trace initialized.\n");
		    }
		;

dqid_trace	: DQID {
		    if (noerror)    {
			id_filtro = 0;
			id_estado = 1;
			char *name = (char *) calloc(strlen($1) + 1, sizeof(char));
			strncpy(name, $1, strlen($1));
			*(name + strlen($1)) = '\0';
			$$ = name;
			if (DEBUG)
			    printf("Trace DQID:%s assigned.\n", name);
		    }
		}
		| error {
		    yyerror("Trace DQID not specified.\n");
		    YYABORT;
		}
		;

/******************************************************************************
    Start Global Header Parser
******************************************************************************/
header		: {
		    $$ = 0;
		}
		| header version description key port encap owner last_update reference behave {
		    if (noerror) {
			MYHEADER *head = getNewHeader();
			if (head == 0) {
			    fprintf(stderr, "Could not allocate head memory.\n");
			    return -1;
			}
			head->version = $2;
			head->description = $3;
			head->key = $4;
			head->port = $5;
			head->encap = $6;
			head->owner = $7;
			head->last_update = $8;
			head->reference = $9;
			head->behave = $10;
			$$ = head;
			if (DEBUG)
			    fprintf(stderr, "Header initialized.\n\n");
		    }
		}
		;

version		: {
		    $$ = 0;
		}
		| VERSION version_desc {
		    $$ = $2;
		}
		;

version_desc	: VERSION_NUMBER {
		    if (noerror) {
			char *version = (char *) calloc(strlen($1) + 1, sizeof(char));
			strncpy(version, $1, strlen($1));
			*(version + strlen($1)) = '\0';
			$$ = version;
			if (DEBUG)
			    printf("Ver= `%s'.\n", version);
		    }
		}
		| error {
		    yyerror("Error in version specification.\n");
		    YYABORT;
		}
		;

description	: {
		    $$ = 0;
		}
		| DESCRIPTION description_desc {
		    $$ = $2;
		}
		;

description_desc: INFTEXT {
		    if (noerror) {
			char *description = (char *) calloc(strlen($1) + 1, sizeof(char));
			strncpy(description, $1, strlen($1));
			*(description + strlen($1)) = '\0';
			$$ = description;
			if (DEBUG)
			    printf("Desc= `%s'.\n", description);
		    }
		}
		| error {
		    yyerror("Error in Description specification.\n");
		    YYABORT;
		}
		;

key		: {
		    $$ = 0;
		}
		| KEY key_desc {
		    $$ = $2;
		}
		;

key_desc	: KEYWORD {
		    if (noerror) {
			char *keyword = (char*) calloc(strlen($1) + 1, sizeof(char));
			strncpy(keyword, $1, strlen($1));
			*(keyword + strlen($1)) = '\0';
			$$ = keyword;
			if (DEBUG)
			    printf("Key= `%s'.\n", keyword);
		    }
		}
		| error {
		    yyerror("Error in Keyword specification.\n");
		    YYABORT;
		}
		;

port		: {
		    $$ = 0;
		}
		| PORT port_desc {
		    $$ = $2;
		}
		;

port_desc	: UINT {
		    if (noerror)    {
			char *port = (char*) calloc(strlen($1) + 1, sizeof(char));
			strncpy(port, $1, strlen($1));
			*(port + strlen($1)) = '\0';
			$$ = port;
			if (DEBUG)
			    printf("Port= `%s'.\n", port);
		    }
		}
	        | error {
		    yyerror("Error in Port specification.\n");
		    YYABORT;
		}
		;

encap		: {
		    $$ = 0;
		}
		| ENCAP encap_desc {
		    $$ = $2;
		}
		;

encap_desc	: INFTEXT {
		    if (noerror)    {
			char *encap = (char*) calloc(strlen($1) + 1, sizeof(char));
			strncpy(encap, $1, strlen($1));
			*(encap + strlen($1)) = '\0';
			$$ = encap;
			if (DEBUG)
			    fprintf(stderr, "Encapsulation= `%s'.\n", encap);
		    }
		}
		| error {
		    yyerror("Error in Encapsulation specification.\n");
		    YYABORT;
		}
		;

owner		: {
		    $$ = 0;
		}
		| OWNER owner_desc {
		    $$ = $2;
		}
		;

owner_desc	: INFTEXT {
		    if (noerror) {
			char *owner = (char*) calloc(strlen($1) + 1, sizeof(char));
			strncpy(owner, $1, strlen($1));
	    		*(owner + strlen($1)) = '\0';
			$$ = owner;
			if (DEBUG)
			    fprintf(stderr, "Owner: `%s'\n", owner);
		    }
		}
		| error {
		    yyerror("Error in Owner specification.\n");
		    YYABORT;
		}
		;

last_update	: {
		    $$ = 0;
		}
		| LAST_UPDATE last_desc {
		    $$ = $2;
		}
		;

last_desc	: DTIME {
		    if (noerror) {
			char *last = (char*) calloc(strlen($1) + 1, sizeof(char));
			strncpy(last, $1, strlen($1));
			*(last + strlen($1)) = '\0';
			$$ = last;
			if (DEBUG)
			    fprintf(stderr, "Last Update: `%s'\n", last);
		    }
		}
		| error {
		    yyerror("Error in Last Update specification.");
		    YYABORT;
		}
reference	: {
		    $$ = 0;
		}
		| REFERENCE ref_desc {
		    $$ = $2;
		}
		;

ref_desc	: INFTEXTT {
		    if (noerror)    {
			char *ref = (char*) calloc(strlen($1) + 1, sizeof(char));
			strncpy(ref, $1, strlen($1));
			*(ref + strlen($1)) = '\0';
			$$ = ref;
			if (DEBUG)
			    printf("Reference=%s.\n", ref);
		    }
		}
		| error {
		    yyerror("Error in Reference specification.");
		    YYABORT;
		}
		;

behave		: {
		    $$ = 0;
		}
		| behave BEHAVIOR {
		    if (noerror)    {
			char *behave = (char*) calloc(strlen($2) + 1, sizeof(char));
			strncpy(behave, $2, strlen($2));
			*(behave + strlen($2)) = '\0';
			$$ = behave;
			if (DEBUG)
			    printf("Behave=%s.\n", behave);
		    }
		}
		| error {
		    yyerror("Error in Behave specification.\n");
		    YYABORT;
		}
		;

/******************************************************************************

    Start Global Messages Section Parser

******************************************************************************/
messages_section    : MESSAGES_SECTION messages_section_content END_MESSAGES_SECTION	{
		    if (noerror) {
			$$ = $2;
		    	if (DEBUG)
			    printf("Messages Section ok.\n");
		    }
		}
		| error {
		    yyerror("Error in Messages Section Content.\n");
		    YYABORT;
		}
		;

messages_section_content    : message_content {
		    if (noerror) {
			$$ = $1;
			if (DEBUG)
			    printf("Assigned Message Content.\n");
		    }
		}
		| messages_section_content message_content {
		    if (noerror)    {
			int no = 2;
			MYMESSAGES_SEC *mtemp = $$;
			while (mtemp->next)  {
			    mtemp = mtemp->next;
			    no++;
			}
			mtemp->next = $2;
			if (DEBUG)
			    printf("Assigned %dth Message Content:%s.\n\n", no, $2->messageName);
		    }
		}
		| error {
		    yyerror("No Message Content included or errors in specification.\n");
		    YYABORT;
		}
		;

message_content	: MESSAGE dqid_msgs message_t message_timeout counters END_MESSAGE {
		    if (noerror) {
			MYMESSAGES_SEC *msgs = getNewMessage();
			if (msgs == NULL) {
			    printf("Could not allocate message memory.\n");
			    return (-1);
			}
			msgs->messageName = $2;
			msgs->messageType = $3;
			msgs->timeout = $4;
			msgs->ptrCounter = $5;
			$$ = msgs;
			if (DEBUG)
			    printf("Message Content Initiated.\n");
		    }
		}
		| error {
		    yyerror("Error in Message Content.\n");
		    YYABORT;
		}
		;

dqid_msgs	: DQID {
		    if (noerror)    {
			char *dqid_msgs = (char*) calloc(strlen($1) + 1, sizeof(char));
			strncpy(dqid_msgs, $1, strlen($1));
			*(dqid_msgs + strlen($1)) = '\0';
			$$ = dqid_msgs;
			if (DEBUG)
			    printf("Messages DQID=%s assigned.\n", dqid_msgs);
		    }
		}
		| error {
		    yyerror("Error in message DQID.\n");
		    YYABORT;
		}
		;

message_t	: MESSAGE_TYPE MTYPE {
		    if (noerror)    {
			char *mtype = (char*) calloc(strlen($2) + 1, sizeof(char));
			strncpy(mtype, $2, strlen($2));
			*(mtype + strlen($2)) = '\0';
			$$ = mtype;
			if (DEBUG)
			    printf("Msgs type=%s.\n", mtype);
		    }
		}
		| error {
		    yyerror("Error in message type.\n");
		    YYABORT;
		}
		;

message_timeout	: {
		    $$ = 0;
		}
		| MESSAGE_TIMEOUT UINT {
		    if (noerror) {
			char *timeout = (char*) calloc(strlen($2) + 1, sizeof(char));
			strncpy(timeout, $2, strlen($2));
			*(timeout + strlen($2)) = '\0';
			$$ = timeout;
			if (DEBUG)
			    printf("TimeOut=%s.\n", timeout);
		    }
		}
		| error {
		    yyerror("Error in message timeout.\n");
		    YYABORT;
		}
		;

/******************************************************************************

    Start Global Groups Section Parser

******************************************************************************/
groups_section	: {
		    $$ = 0;
		}
		| groups_section GROUPS_SECTION groups_section_content END_GROUPS_SECTION {
		    if (noerror)    {
			$$ = $3;
			if (DEBUG)
			    printf("Groups Section Content.\n");
		    }
		}
		| error	{
		    yyerror("Error in Groups Section Content definition.\n");
		    YYABORT;
		}
		;

groups_section_content:group_content	{
		if (noerror)    {
	    	$$ = $1;
		    if (DEBUG)
			printf("Assigned Group Content:%s.\n", $1->groupName);
		}
    }
    |groups_section_content group_content	{
		if (noerror)    {
	    	int no = 2;
		    MYGROUPS_SEC *gtemp = $$;
		    while (gtemp->next)  {
				gtemp = gtemp->next;
				no++;
	    	}
		    gtemp->next = $2;
		    if (DEBUG)
				printf("Assigned %dth Group content.\n\n", no);
		}
    }
    |error	{
		yyerror("Error in Group content.\n");
 		YYABORT;
   }
group_content:GROUP dqid_grp group_msgs END_GROUP {
		if (noerror)    {
	    	MYGROUPS_SEC *group = getNewGroup();
		    if (group == 0) {
				printf("Could not allocate group memory.\n");
				return -1;
	    	}
		    group->groupName = $2;
		    group->message = $3;
	    	$$ = group;
		    if (DEBUG)	{
				printf("GroupsSection.\n");
				printf("Group Name:%s, ptr:%p\n", group->groupName, group->groupName);
				printf("Group Message:%s, ptr:%p\n", group->message, group->message);
		    }
		}
    }
dqid_grp	: DQID {
		    char *dqid = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(dqid, $1, strlen($1));
		    *(dqid + strlen($1)) = '\0';
		    $$ = dqid;
		    if (DEBUG)
		        printf("Group DQID:%s assigned.\n", dqid);
		}
		| error {
		    yyerror("Error in Group DQID.\n");
		    YYABORT;
		}
		;

group_msgs	: MESSAGES dqid_grp_msgs {
		    $$ = $2;
		    if (DEBUG)
			printf("Assigned group messages.\n");
		}
		;

dqid_grp_msgs	: DDQID {
		    char *d_msgs = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(d_msgs, $1, strlen($1));
		    *(d_msgs + strlen($1)) = '\0';
		    $$ = d_msgs;
		    if (DEBUG)
			printf("Group Msgs DDQID:%s assigned.\n", d_msgs);
		}
		| error {
		    yyerror("Error in Group Messages DDQID.\n");
		    YYABORT;
		}
		;

/******************************************************************************
    Start Global States Section Parser
******************************************************************************/
states_section	: STATES_SECTION states_section_content END_STATES_SECTION {
			$$ = $2;
			if (DEBUG)
			    printf("States Section reconized with Success.\n");
		    }
		| error {
		    yyerror("Error in State Section Definitions.\n");
		    YYABORT;
		}
		;

states_section_content	: fs ident state_contents {
			MYSTATES_SEC *state = getNewState();
			if (state == 0) {
			    printf("Could not allocate State 1st stage memory.\n");
			    return (-1);
			}
			state->identifier = $2;
			state->ptr_state_sec = $3;
			$$ = state;
			if (DEBUG)
			    printf("1 stage States Section initialized.\n");
		    }
		| error {
		    yyerror("1 stage State Sections error.\n");
		    YYABORT;
		}
		;

fs		: FINAL_STATE {
			if (DEBUG)
			    printf("Final State specified.\n");
		    }
		| error {
		    yyerror("Final State not Specified.\n");
		    YYABORT;
		}
		;

ident		: ID {
			char *id = (char*) calloc(strlen($1) + 1, sizeof(char));
			strncpy(id, $1, strlen($1));
			*(id + strlen($1)) = '\0';
			$$ = id;
			if (DEBUG)
			    printf("Identifier:%s\n", id);
		    }
		|error  {
		    yyerror("1 stage ID error.\n");
		    YYABORT;
		}
		;

state_contents	: state_content {
			$$ = $1;
			if (DEBUG)
			    printf("States Section Content 2th stage ok.\n");
		    }
		| state_contents state_content {
		    if (noerror) {
			int no = 2;
			MYSTATES_SEC_FIELD *stemp = $$;
			while (stemp->next) {
			    stemp = stemp->next;
			    no++;
			}
			stemp->next = $2;
			if (DEBUG)
			    printf("Assigned %dth States content 2th stage.\n\n", no);
		    }
		}
		| error {
		    yyerror("Error in State content 2th stage.\n");
		    YYABORT;
		}
		;

state_content	: STATE state_id state_fields es {
			MYSTATES_SEC_FIELD *sfstate = getNewStateField();
			if (sfstate == 0) {
			    fprintf(stderr, "Could not allocate state memory 2th stage.\n");
			    return (-1);
			}
			sfstate->identi = $2;
			sfstate->ptrSfield = $3;
			$$ = sfstate;
			if (!strncmp($2, "idle\0", 5)) {
			    sfstate->id = 0;
			}
			else {
			    sfstate->id = id_estado;
			    id_estado++;
			}
			if (DEBUG) {
			    printf("States Section 2 stage ok.\n");
			}
		    }
		| error {
		    yyerror("Error in global State Content 2th stage.\n");
		    YYABORT;
		}
		;

state_id	: ID {
		        char *id = (char*) calloc(strlen($1) + 1, sizeof(char));
		        strncpy(id, $1, strlen($1));
			*(id + strlen($1)) = '\0';
		        $$ = id;
		        if (DEBUG)
			    printf("2 stage State ID:%s.\n", id);
		    }
		| error {
		    yyerror("2 stage ID error.\n");
		    YYABORT;
		}
		;

state_fields	: state_field {
			$$ = $1;
			if (DEBUG)
			    printf("State Content Fields 3th stage.\n");
		    }
		| state_fields state_field {
			int no = 2;
			MYSFIELD *ptrtemp = $$;
			while (ptrtemp->next) {
			    ptrtemp = ptrtemp->next;
			    no++;
			}
			ptrtemp->next = $2;
			if (DEBUG)
			    printf("Assigned %dth States content in 3th stage.\n\n", no);
		    }
		| error {
		    yyerror("Error in State Content Fields 3th stage.\n");
		    YYABORT;
		}
		;

es		: END_STATE {
			if (DEBUG)
			    printf("End State found.\n");
		    }
		| error {
		    yyerror("End State not specified.\n");
		    YYABORT;
		}
		;

state_field	: state_dqid gts identifier {
			MYSFIELD *sfield = getNewSField();
			if (sfield == 0) {
			    fprintf(stderr, "Could not allocate state field memory in 3th stage.\n");
			    return (-1);
			}
			sfield->dqid = $1;
			sfield->id = $3;
			$$ = sfield;
			if (DEBUG)
			    printf("States Field.\n");
		    }
		| error {
		    yyerror("Error in State DQID or in Goto_State or in Identifier");
		    YYABORT;
		}
		;

state_dqid	: DQID {
			char *dqid = (char*) calloc(strlen($1) + 1, sizeof(char));
			strncpy(dqid, $1, strlen($1));
			*(dqid + strlen($1)) = '\0';
			$$ = dqid;
			if (DEBUG)
			    printf("State DQID:%s.\n", dqid);
		    }
		| error {
		    yyerror("Error in State DQID in 3th stage.\n");
		    YYABORT;
		}
		;

gts		: GOTO_STATE {
			if (DEBUG)
			    printf("Goto State ok.\n");
		    }
		| error {
		    yyerror("Goto State not specified.\n");
		    YYABORT;
		}
		;

identifier	: ID {
			char *id = (char*) calloc(strlen($1) + 1, sizeof(char));
			strncpy(id, $1, strlen($1));
			*(id + strlen($1)) = '\0';
			$$ = id;
			if (DEBUG)
			    printf("Identifier:%s\n", id);
		    }
		| error {
		    yyerror("Error in Identifier in 3th stage.\n");
		    YYABORT;
		}
		;

/******************************************************************************
    Start Global COUNTERS Parser
******************************************************************************/
counters	: counter {
		    if (noerror) {
			MYMESSAGES_SEC_C *ptrM = getNewMessage_Sec_C();
			if (ptrM == 0) {
			    printf("Could not allocate state Message_Sec_C memory.\n");
			    return -1;
			}
			if (f1) {
			    ptrM->field = (MYFIELD_COUNTER *) f;
			    if (DEBUG)
				printf("---Pointer Field:%p\n", ptrM->field);
			    f1 = 0;
			}
			if (f2) {
			    ptrM->bit = (MYBIT_COUNTER *) b;
			    if (DEBUG)
				printf("---Pointer Bit:%p\n", ptrM->bit);
			    f2 = 0;
			}
			if (f3) {
			    ptrM->off = (MYNO_OFFSET *) n;
			    if (DEBUG)
			        printf("---Pointer Off:%p\n", ptrM->off);
			    f3 = 0;
			}
			if (f4) {
			    ptrM->lvfield = (MYLFIELD_COUNTER *) lf;
			    if (DEBUG)
			        printf("---Pointer Variable Field:%p\n", ptrM->lvfield);
			    f4 = 0;
			}
			if (f5) {
			    ptrM->ltfield = (MYLFIELD_COUNTER *) tf;
			    if (DEBUG)
				printf("---Pointer Variable Field:%p\n", ptrM->ltfield);
			    f5 = 0;
			}
			if (f6) {
			    ptrM->lvbit = (MYLBIT_COUNTER *) lb;
			    if (DEBUG)
			        printf("---Pointer Variable Bit:%p\n", ptrM->lvbit);
			    f6 = 0;
			}
			if (f7) {
			    ptrM->ltbit = (MYLBIT_COUNTER *) tb;
			    if (DEBUG)
			        printf("---Pointer Variable Bit:%p\n", ptrM->ltbit);
			    f7 = 0;
			}
			$$ = ptrM;
			if (DEBUG)
			    printf("NewMessage_Sec_C created.\n");
		    }
		}
counter		: {
		    $$ = 0;
		}
		| counter field_counters {
		    if (noerror) {
			f1 = 1;
			f = $2;
			if (DEBUG)
			    printf("* Field Counter Ready. *\n");
		    }
		}
		| counter bit_counters {
		    if (noerror) {
			f2 = 1;
			b = $2;
			if (DEBUG)
			    printf("** Bit Counter Ready. **\n");
		    }
		}
		| counter nooffsets	{
		    if (noerror)	{
			f3 = 1;
			n = $2;
			if (DEBUG)
			    printf("*** NoOffset Ready. ***\n");
		    }
		}
		| counter flvs {
		    if (noerror) {
			f4 = 1;
			lf = $2;
			if (DEBUG)
			    printf("* Local Variable Field Counter Ready. *\n");
		    }
		}
		| counter ftvs {
		    if (noerror) {
			f5 = 1;
			tf = $2;
			if (DEBUG)
			    printf("* Trace Variable Field Counter Ready. *\n");
		    }
		}
		| counter blvs {
		    if (noerror) {
			f6 = 1;
			lb = $2;
			if (DEBUG)
			    printf("** Local Variable Bit Counter Ready. **\n");
		    }
		}
		| counter btvs {
		    if (noerror) {
			f7 = 1;
			tb = $2;
			if (DEBUG)
			    printf("** Trace Variable Bit Counter Ready. **\n");
		    }
		}
		;

/******************************************************************************
    Start Global Field Counter Parser
******************************************************************************/
field_counters	: field_counter {
		    $$ = $1;
		    if (DEBUG)
		    printf("Another Field Counter.\n");
		}
		| field_counters field_counter {
		    int no = 2;
		    MYFIELD_COUNTER *ftemp = $$;
		    while (ftemp->next) {
			ftemp = ftemp->next;
			no++;
		    }
		    ftemp->next = $2;
		    if (DEBUG)
			printf("Assigned %dth Field Counter.\n\n", no);
		}
		| error {
		    yyerror("Error in Field Counter specification.\n");
		    YYABORT;
		}
		;

field_counter	: FIELD_COUNTER prot_field field_uint wild_id f_operator dqinf_field {
	    MYFIELD_COUNTER *field = getNewFieldCounter();
	    if (field == NULL) {
		printf("Could not allocate field memory.\n");
		return -1;
	    }
	    field->id = id_filtro;
	    field->prot = $2;
	    field->numi = $3;
	    field->wildid = $4;
	    field->op = $5;
	    field->dq_informal = $6;
	    $$ = field;
	    id_filtro++;
	    if (DEBUG)  {
		printf("---> ID_filtro: `%d'\n", id_filtro);
		printf("FieldCounter.\n");
	    }
	}
	;

prot_field	: PROT_ENC {
		    char *protname = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(protname, $1, strlen($1));
		    *(protname + strlen($1)) = '\0';
		    $$ = protname;
		    if (DEBUG)
			printf("---> Protocol Encapsulation: `%s'\n", protname);
		}
		| error {
		    yyerror("<<<	Field-Protocol Encapsulation error.\n");
		    YYABORT;
		}
		;

field_uint	: UINT {
		    char *fuint = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(fuint, $1, strlen($1));
		    *(fuint + strlen($1)) = '\0';
		    $$ = fuint;
		    if (DEBUG)
		        printf("---> Field_uint: `%s'\n", fuint);
		}
		| error {
		    yyerror("<<<	Field-Uint error.\n");
		    YYABORT;
		}
		;

wild_id		: WID {
	if (noerror)    {
	    char *wild_ide = (char*) calloc(strlen($1) + 1, sizeof(char));
	    strncpy(wild_ide, $1, strlen($1));
	    *(wild_ide + strlen($1)) = '\0';
	    $$ = wild_ide;
	    if (DEBUG)
		printf("---> Wildcard or Identifier: `%s'\n", wild_ide);
	}
    }
    |error	{
	yyerror("<<<	WildCard Identifier error.\n");
 		YYABORT;
   }
f_operator	: {
		    char *op = (char*) calloc(2, sizeof(char));
		    strncpy(op, "=", 1);
		    *(op + 2) = '\0';
		    $$ = op;
		    if (DEBUG)
			printf("---> Operator: `%s'\n", op);
		}
		| OPERATOR {
		    if (noerror) {
			char *op = (char*) calloc(strlen($1) + 1, sizeof(char));
			strncpy(op, $1, strlen($1));
			*(op + strlen($1)) = '\0';
			$$ = op;
			if (DEBUG)
			    printf("---> Operator: `%s'\n", op);
		    } else {
			yyerror("<<<    Error in Operator specification");
			YYABORT;
		    }
		}
		;

dqinf_field	: DQ_INF {
		    char *dqinf_f = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(dqinf_f, $1, strlen($1));
		    *(dqinf_f + strlen($1)) = '\0';
		    $$ = dqinf_f;
		    if (DEBUG)
			printf("---> FiledCounter DQ Informal Text=%s.\n", dqinf_f);
		}
		| error {
		    yyerror("<<<	Field-Double Quotted Informal Text error.\n");
		    YYABORT;
		}
		;

/******************************************************************************
    Start Local Variable Field Counter Parser
******************************************************************************/
ftvs		: ftv {
		    $$ = $1;
		    if (DEBUG)
			printf("Another Local Variable Field Counter.\n");
		}
		| ftvs ftv {
		    int no = 2;
		    MYLFIELD_COUNTER *ftemp = $$;
		    while (ftemp->next)  {
			ftemp = ftemp->next;
			no++;
		    }
		    ftemp->next = $2;
		    if (DEBUG)
		    printf("Assigned %dth Trace Variable Field Counter.\n\n", no);
		}
		| error {
		    yyerror("Error in Field Counter specification.\n");
		    YYABORT;
		}
		;

flvs		: flv {
		    $$ = $1;
		    id_filtro++;
		    if (DEBUG)
			printf("Another Local Variable Field Counter.\n");
		}
		| flvs flv {
		    if (noerror)    {
			int no = 2;
			MYLFIELD_COUNTER *ftemp = $$;
			while (ftemp->next)  {
			    ftemp = ftemp->next;
			    no++;
			}
			ftemp->next = $2;
			if (DEBUG)
			    printf("Assigned %dth Local Variable Field Counter.\n\n", no);
		    }
		}
		| error {
		    yyerror("Error in Field Counter specification.\n");
		    YYABORT;
		}
		;

ftv		: FTV prot_field field_uint wild_id dqinf_field   {
		    MYLFIELD_COUNTER *lf = getNewLFieldCounter();
		    if (lf == NULL) {
			printf("Could not allocate field memory.\n");
			return (-1);
		    }
		    lf->id = id_filtro;
		    lf->prot = $2;
		    lf->numi = $3;
		    lf->varid = $4;
		    lf->dq_informal = $5;
		    $$ = lf;
		    id_filtro++;
		    if (DEBUG) {
			printf("---> ID_filtro: `%d'\n", id_filtro);
			printf("FieldCounter.\n");
		    }
		}
		| error {
		    yyerror("Erro no ftv...\n");
		    YYABORT;
		}
		;

flv		: FLV prot_field field_uint wild_id dqinf_field {
		    MYLFIELD_COUNTER *lf = getNewLFieldCounter();
		    if (lf == NULL) {
			printf("Could not allocate field memory.\n");
			return (-1);
		    }
		    lf->id = id_filtro;
		    lf->prot = $2;
		    lf->numi = $3;
		    lf->varid = $4;
		    lf->dq_informal = $5;
		    lf->loc = 1;
		    $$ = lf;
		    if (DEBUG) {
			printf("---> ID_filtro: `%d'\n", id_filtro);
			printf("FieldCounter.\n");
		    }
		}
		| error {
		    yyerror("Erro no flv...\n");
		    YYABORT;
		}
		;

/******************************************************************************
    Start Global Bit Counter Parser
******************************************************************************/
bit_counters	: bit_counter {
		    $$ = $1;
		    if (DEBUG)
		        printf("Another Bit Counter.\n");
		}
		| bit_counters bit_counter {
		    int no = 2;
			MYBIT_COUNTER *btemp = $$;
			while (btemp->next) {
			    btemp = btemp->next;
			    no++;
			}
			btemp->next = $2;
			if (DEBUG)
			    printf("Assigned %dth Bit Counter.\n\n", no);
		    }
		| error {
		    yyerror("Error in Bit Counter specification.\n");
		    YYABORT;
		}
		;

bit_counter	: BIT_COUNTER prot_bit bit_uinti bit_uintii wild_id b_operator dqid_bit {
		    MYBIT_COUNTER *bit = getNewBitCounter();
		    if (bit == 0) {
			printf("Could not allocate bit memory.\n");
			return (-1);
		    }
		    bit->id = id_filtro;
		    bit->prot = $2;
		    bit->offset = $3;
		    bit->verb_size = $4;
		    bit->wildid = $5;
		    bit->op = $6;
		    bit->dq_informal = $7;
		    $$ = bit;
		    id_filtro++;
		    if (DEBUG) {
			printf("---> ID_filtro: `%d'\n", id_filtro);
			printf("BitCounter.\n");
		    }
		}
		| error {
		    yyerror("Error in Bit Counter.\n");
		    YYABORT;
		}
		;

prot_bit	: PROT_ENC {
		    char *protname = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(protname, $1, strlen($1));
		    *(protname + strlen($1)) = '\0';
		    $$ = protname;
		    if (DEBUG)
			printf("Bit Encapsulation included.\n");
		}
		| error {
		    yyerror("Bit Encapsulation error.\n");
		    YYABORT;
		}
		;

bit_uinti	: UINT {
		    char *bitui = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(bitui, $1, strlen($1));
		    *(bitui + strlen($1)) = '\0';
		    $$ = bitui;
		    if (DEBUG)
			printf("---> Offset: `%s'\n", bitui);
		}
		| error {
		    yyerror("<<<	Offset error.\n");
		    YYABORT;
		}
		;

bit_uintii	: UINT {
		    char *bituii = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(bituii, $1, strlen($1));
		    *(bituii + strlen($1)) = '\0';
		    $$ = bituii;
		    if (DEBUG)
			printf("---> Offset Size: `%s'\n", bituii);
		}
		| error {
		    yyerror("<<<	Offset Size error.\n");
		    YYABORT;
		}
		;

wild_id		: WID {
		    char *wild_ide = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(wild_ide, $1, strlen($1));
		    *(wild_ide + strlen($1)) = '\0';
		    $$ = wild_ide;
		    if (DEBUG)
			printf("---> Wildcard or Identifier: `%s'\n", wild_ide);
		}
		| error {
		    yyerror("<<<	WildCard Identifier error.\n");
		    YYABORT;
		}
		;

b_operator	: {
		    char *op = (char*) calloc(1, 2 * sizeof(char));
		    strncpy(op, "=", 1);
		    *(op + 2) = '\0';
		    $$ = op;
		    if (DEBUG)
			printf("---> Operator: `%s'\n", op);
		}
		| OPERATOR {
		    if (noerror)    {
			char *op = (char*) calloc(strlen($1) + 1, sizeof(char));
			strncpy(op, $1, strlen($1));
			*(op + strlen($1)) = '\0';
			$$ = op;
			if (DEBUG)
			    printf("---> Operator: `%s'\n", op);
		    }
		}
		| error {
		    yyerror("<<<	Error in Operator specification");
		    YYABORT;
		}
		;

dqid_bit	: DQ_INF {
		    char *dqidfield = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(dqidfield, $1, strlen($1));
		    *(dqidfield + strlen($1)) = '\0';
		    $$ = dqidfield;
		    if (DEBUG)
			printf("---> BitCounter DQ Informal Text: `%s'\n", dqidfield);
		}
		| error {
		    yyerror("<<<	Bit-Double Quotted Informal Text error.\n");
		    YYABORT;
		}
		;

/******************************************************************************
    Start Global Variable Bit Counter Parser
******************************************************************************/
btvs		: btv {
		    $$ = $1;
		    if (DEBUG)
			printf("Another Trace Variable Bit Counter.\n");
		}
		| btvs btv {
		    int no = 2;
		    MYLBIT_COUNTER *btemp = $$;
		    while (btemp->next) {
			btemp = btemp->next;
			no++;
		    }
		    btemp->next = $2;
		    if (DEBUG)
			printf("Assigned %dth Trace Variable Bit Counter.\n\n", no);
		}
		| error {
		    yyerror("Error in Bit Counter specification.\n");
		    YYABORT;
		}
		;

btv		: BTV prot_bit bit_uinti bit_uintii wild_id dqid_bit {
		    MYLBIT_COUNTER *bit = getNewLBitCounter();
		    if (bit == 0) {
			printf("Could not allocate bit memory.\n");
			return (-1);
		    }
		    bit->id = id_filtro;
		    bit->prot = $2;
		    bit->offset = $3;
		    bit->verb_size = $4;
		    bit->varid = $5;
		    bit->dq_informal = $6;
		    $$ = bit;
		    id_filtro++;
		    if (DEBUG) {
			printf("---> ID_filtro: `%d'\n", id_filtro);
			printf("Trace Variable BitCounter.\n");
		    }
		}
		| error {
		    yyerror("Error in Trace Variable Bit Counter.\n");
		    YYABORT;
		}
		;

blvs		: blv {
		    $$ = $1;
		    if (DEBUG)
			printf("Another Local Variable Bit Counter.\n");
		}
		| blvs blv {
		    int no = 2;
		    MYLBIT_COUNTER *btemp = $$;
		    while (btemp->next) {
			btemp = btemp->next;
			no++;
		    }
		    btemp->next = $2;
		    if (DEBUG)
			printf("Assigned %dth Local Variable Bit Counter.\n\n", no);
		}
		| error {
		    yyerror("Error in Local Variable Bit Counter specification.\n");
		    YYABORT;
		}
		;

blv		: BLV prot_bit bit_uinti bit_uintii wild_id dqid_bit {
		    MYLBIT_COUNTER *bit = getNewLBitCounter();
		    if (bit == 0) {
			printf("Could not allocate bit memory.\n");
			return (-1);
		   }
		    bit->id = id_filtro;
		    bit->prot = $2;
		    bit->offset = $3;
		    bit->verb_size = $4;
		    bit->varid = $5;
		    bit->dq_informal = $6;
		    bit->loc = 1;
		    $$ = bit;
		    id_filtro++;
		    if (DEBUG) {
			printf("---> ID_filtro: `%d'\n", id_filtro);
			printf("Local Variable BitCounter.\n");
		    }
		}
		| error {
		    yyerror("Error in Local Variable Bit Counter.\n");
		    YYABORT;
		}
		;

/******************************************************************************
    Start Global NoOffSet Parser
******************************************************************************/
nooffsets	: nooffset {
		    $$ = $1;
		    if (DEBUG)
			printf("Another NoOffSet.\n");
		}
		| nooffsets nooffset {
		    int no = 2;
		    MYNO_OFFSET *otemp = $$;
		    while (otemp->next)  {
			otemp = otemp->next;
			no++;
		    }
		    otemp->next = $2;
		    if (DEBUG)
			printf("Assigned %dth NoOffSet.\n\n", no);
		}
		| error {
		    yyerror("Error in NoOffSet specification.\n");
		    YYABORT;
		}
		;

nooffset	: NOOFFSET prot_no verb_id dqid_no {
		    MYNO_OFFSET *nooff = getNewNoOffset();
		    if (nooff == 0) {
			printf("Could not allocate nooffset memory.\n");
			return (-1);
		    }
		    nooff->id = id_filtro;
		    nooff->prot = $2;
		    nooff->verb_id = $3;
		    nooff->dq_informal = $4;
		    $$ = nooff;
		    id_filtro++;
		    if (DEBUG) {
			printf("---> ID_filtro: `%d'\n", id_filtro);
			printf("NoOffSet initialized.\n");
		    }
		}
		| error {
		    yyerror("Error in NoOffset structure.\n");
		    YYABORT;
		}
		;

prot_no		: PROT_ENC  {
		    char *protname = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(protname, $1, strlen($1));
		    *(protname + strlen($1)) = '\0';
		    $$ = protname;
		    if (DEBUG)
			printf("NoOffSet Encapsulation included.\n");
		}
		| error {
		    yyerror("NoOffset Encapsulation error.\n");
		    YYABORT;
		}
		;

verb_id		: VERB_IDENTIFIER {
		    char *verb = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(verb, $1, strlen($1));
		    *(verb + strlen($1)) = '\0';
		    $$ = verb;
		    if (DEBUG)
			printf("---> Wildcard or Identifier: `%s'\n", verb);
		}
		| error {
		    yyerror("NoOffset-Verb id error.\n");
		    YYABORT;
		}
		;

dqid_no		: DQ_INF {
		    char *dqidno = (char*) calloc(strlen($1) + 1, sizeof(char));
		    strncpy(dqidno, $1, strlen($1));
		    *(dqidno + strlen($1)) = '\0';
		    $$ = dqidno;
		    if (DEBUG)
			printf("---> NoOffSet DQID: `%s'\n", dqidno);
		}
		| error {
		    yyerror("NoOffset DQID error.\n");
		    YYABORT;
		}
		;
%%

/*int
yyerror(const char *fmt, ...)
{
        va_list          ap;
        extern char     *infile;

        errors = 1;
        va_start(ap, fmt);
        fprintf(stderr, "%s:%d: ", infile, yylval.lineno);
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
        va_end(ap);
        return (0);
}
*/

int
yyerror(const char *msg)
{
    noerror = 0;

    if (strcmp(msg, "syntax error"))
	fprintf(stderr, "Syntax Error in Line %d :%s\n", yylineno, msg);
    return (0);
}

/*int
yylex(void)
{
    return (0);
}
*/

