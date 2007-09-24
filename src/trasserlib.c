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

/** \file trasserlib.c
 *	Trasser structures initialization and funtion definitions.
 *	Definitions to various structures used to store the elements that compose the PTSL,
 *	and some functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "globals.h"

#include <netinet/in.h>
#include <sys/types.h>
#include "stateful.h"
#include "protocoldir.h"
#include "pedb.h"
#include "tracos.h"

#include "trasserlib.h"
#include "exit_codes.h"


/**
 *  \struct idlist_s
 *  \brief A local structure to help filling the states structures.
 */
struct idlist_s {
	unsigned int    filter_id;
	struct idlist_s *next;
};


/******************************************************************************

    Function that initializes a TRACE Structure

******************************************************************************/
/**
 *	getNewTrace() - Creates a new Trace structure.
 *	Allocs memory and initialize the structure members.
 *	@return mytrace a pointer to the struct MYTRACE allocated.
 *	@see MYTRACE
 */
MYTRACE *
getNewTrace()
{
	MYTRACE *mytrace = (MYTRACE*) calloc(1, sizeof(MYTRACE));

	return mytrace;
}

/******************************************************************************

    Function that initializes a HEADER Structure

******************************************************************************/
/**
 *	getNewHeader() - Creates a new Header structure.
 *	Allocs memory and initialize the structure members.
 *	@return myhead a pointer to the struct MYHEADER allocated.
 *	@see MYHEADER
 */
MYHEADER *
getNewHeader()
{
	MYHEADER *myhead = (MYHEADER*) calloc(1, sizeof(MYHEADER));

	return myhead;
}

/******************************************************************************

  Function that initializes a MESSAGES SECTION Structure

 ******************************************************************************/
/**
 *	getNewMessage() - Creates a new Message Section.
 *	Allocs memory to the Message definitions members.
 *	@return mymessage a pointer to the struct MYMESSAGES_SEC allocated.
 *	@see MYMESSAGES_SEC
 *	@see MYMESSAGES_SEC_C
 */
MYMESSAGES_SEC *
getNewMessage()
{
	MYMESSAGES_SEC *mymessage = (MYMESSAGES_SEC*) calloc(1, sizeof(MYMESSAGES_SEC));

	return mymessage;
}

/**
 *	getNewMessage_Sec_C() - Creates a new structure that store Messages attributes.
 *	Allocs memory to the Messages structures attributes members.
 *	@return ptr a pointer to the struct MYMESSAGES_SEC_C allocated.
 *	@see MYMESSAGES_SEC
 *	@see MYMESSAGES_SEC_C
 */
MYMESSAGES_SEC_C *
getNewMessage_Sec_C()
{
	MYMESSAGES_SEC_C *ptr = (MYMESSAGES_SEC_C*) calloc(1, sizeof(MYMESSAGES_SEC_C));

	return ptr;
};

/******************************************************************************

  Function that initializes a GROUP CONTENT Structure

 ******************************************************************************/
/**
 *	getNewGroup() - Creates a new Group Section.
 *	Allocs memory and initialize the structure members.
 *	@return mygroup a pointer to the struct MYGROUPS_SEC allocated.
 *	@see MYGROUPS_SEC
 */
MYGROUPS_SEC *
getNewGroup()
{
	MYGROUPS_SEC *mygroup = (MYGROUPS_SEC*) calloc(1, sizeof(MYGROUPS_SEC));

	return mygroup;
}

/******************************************************************************

  Function that initializes a STATE CONTENT Structure

 ******************************************************************************/
/**
 *	getNewState() - Creates a new State structure.
 *	Allocs memory a initialize the structure members.
 *	@return mystate a pointer to the struct MYSTATES_SEC allocated.
 *	@see MYSTATES_SEC
 *	@see MYSTATES_SEC_FIELD
 *	@see MYSFIELD
 */
MYSTATES_SEC *
getNewState()
{
	MYSTATES_SEC *mystate = (MYSTATES_SEC*) calloc(1, sizeof(MYSTATES_SEC));

	return mystate;
}

/**
 *	getNewState() - Creates a new State structure.
 *	Allocs memory a initialize the structure members.
 *	@return mysfield a pointer to the struct MYSTATES_SEC_FIELD allocated.
 *	@see MYSTATES_SEC
 *	@see MYSTATES_SEC_FIELD
 *	@see MYSFIELD
 */
MYSTATES_SEC_FIELD *
getNewStateField()
{
	MYSTATES_SEC_FIELD *mysfield = (MYSTATES_SEC_FIELD*) calloc(1, sizeof(MYSTATES_SEC_FIELD));

	return mysfield;
}

/**
 *	getNewState() - Creates a new State structure.
 *	Allocs memory a initialize the structure members.
 *	@return mysfield a pointer to the struct MYSFIELD allocated.
 *	@see MYSTATES_SEC
 *	@see MYSTATES_SEC_FIELD
 *	@see MYSFIELD
 */
MYSFIELD *
getNewSField()
{
	MYSFIELD *mysfield = (MYSFIELD*) calloc(1, sizeof(MYSFIELD));

	return mysfield;
}

/******************************************************************************

  Function that initializes a FIELD COUNTER Structure

 ******************************************************************************/
/**
 *	getNewFieldCounter() - Creates a new Field Counter Structure.
 *	Allocs memory and initialize the Field Counter members.
 *	@return myfield a pointer to the struct MYFIELD_COUNTER allocated.
 *	@see MYFIELD_COUNTER
 *	@see MYLFIELD_COUNTER
 */
MYFIELD_COUNTER *
getNewFieldCounter()
{
	MYFIELD_COUNTER *myfield = (MYFIELD_COUNTER*) calloc(1, sizeof(MYFIELD_COUNTER));

	return myfield;
}

/**
 * 	getNewLFieldCounter() - Creates a new Variable Field Counter Structure.
 * 	Allocs memory and initialize the Variable Field Counter members.
 *	@return mylfield a pointer to the struct MYLFIELD_COUNTER allocated.
 *	@see MYFIELD_COUNTER
 *	@see MYLFIELD_COUNTER
 */
MYLFIELD_COUNTER *
getNewLFieldCounter()
{
	MYLFIELD_COUNTER *mylfield = (MYLFIELD_COUNTER*) calloc(1, sizeof(MYLFIELD_COUNTER));

	return mylfield;
}

/******************************************************************************

  Function that initializes a BIT COUNTER Structure

 ******************************************************************************/
/**
 * 	getNewBitCounter() - Creates a new Bit Counter Structure.
 * 	Allocs memory and initialize the Bit Counter members.
 *	@return mybit a pointer to the struct MYBIT_COUNTER allocated.
 *	@see MYBIT_COUNTER
 *	@see MYLBIT_COUNTER
 */
MYBIT_COUNTER *
getNewBitCounter()
{
	MYBIT_COUNTER *mybit = (MYBIT_COUNTER*) calloc(1, sizeof(MYBIT_COUNTER));

	return mybit;
}

/**
 *	getNewLBitCounter() - BIT COUNTER Local Variable Initialisation.
 *	Allocs memory and initialize the Variable Bit Counter members.
 *	@return mylbit a pointer to the struct MYLBIT_COUNTER allocated.
 *	@see MYBIT_COUNTER
 *	@see MYLBIT_COUNTER
 */
MYLBIT_COUNTER *
getNewLBitCounter()
{
	MYLBIT_COUNTER *mylbit = (MYLBIT_COUNTER*) calloc(1, sizeof(MYLBIT_COUNTER));

	return mylbit;
}

/******************************************************************************

  Function that initializes a NOOFFSET Structure

 ******************************************************************************/
/**
 *	getNewNoOffset() - Creates a NoOffSet Structure.
 *	Allocs memory and initialize the NoOffSet members.
 *	@return myno a pointer to the struct MYNO_OFFSET allocated.
 *	@see MYNO_OFFSET
 */
MYNO_OFFSET *
getNewNoOffset()
{
	MYNO_OFFSET *mynooff = (MYNO_OFFSET*) calloc(1, sizeof(MYNO_OFFSET));

	return mynooff;
}

/**
 *	displayDataStruct() - Show all the elements reconized in a PTSL file.
 *	Esta função é chamada usando como parâmetro um ponteiro para a primeira declaracao
 *	da estrutura que compoe o trace.
 *	A partir deste ponteiro pode-se ler todos os elementos que o compoe isso é claro se
 *	eles foram detectados e criados pelas funcoes getNewXXXXX.
 *	No código abaixo, existe declarado um conjunto de chamadas que varrem as estruturas que
 *	compoe uma descricao PTSL e mostram na tela os elementos reconhecidos da linguagem.
 *	@param traceList is a pointer to the hole trace definition.
 *	@see MYTRACE
 *	@see getNewTrace()
 */
void
displayDataStruct(MYTRACE *traceList)
{
	/* Display DS for Debugging
	 * An important thing TODO is change this function name and remove all the
	 * printf. The objective of this function is to find important data inside
	 * the Trace structures as this data will be used to initialize and
	 * populate the Agent's structures.
	 */

	//    printf("\nMostrando os dados do arquivo Trace:\n");
	if (traceList == NULL) {
		fprintf(stderr, "Pointer to nowhere, things gonna blow up!\n");
		exit (-1);
	}

	MYTRACE *t = traceList;

	while (t)	{
#ifdef DEBUG
		printf("TRACE %s\n", traceList->traceName);

		// Read data that is present inside the HEADER and shows in screen.
		if (t->head) {
			MYHEADER *hPtr = traceList->head;
			printf("Start Header Section.\n");
			if (hPtr->version)
				printf("   Version:%s\n", hPtr->version);
			if (hPtr->description)
				printf("   Description:%s\n", hPtr->description);
			if (hPtr->key)
				printf("   Keyword:%s\n", hPtr->key);
			if (hPtr->port)
				printf("   Port:%s\n", hPtr->port);
			if (hPtr->owner)
				printf("   Owner:%s\n", hPtr->owner);
			if (hPtr->last_update)
				printf("   Last Update:%s\n", hPtr->last_update);
			if (hPtr->reference)
				printf("   Reference:%s\n", hPtr->reference);
			if (hPtr->behave)
				printf("   Behave:%s\n", hPtr->behave);
		}
#endif

		// Read data present inside the MESSAGE Section.
		if (t->msgs_sec)	{
			MYMESSAGES_SEC *tempMesg = t->msgs_sec;
#ifdef DEBUG
			printf("Start Messages Section.\n");
#endif
			while (tempMesg)	{
				t->nr_msgs++;
#ifdef DEBUG
				printf("   Message name:%s\n", tempMesg->messageName);
				printf("   Message type:%s\n", tempMesg->messageType);
				if (tempMesg->timeout) {
					printf("   Message timeout:%s\n", tempMesg->timeout);
				}
#endif

				if (tempMesg->ptrCounter)   {
#ifdef DEBUG
					printf("Start Messages Counters.\n");
#endif
					MYMESSAGES_SEC_C *ptrMC = tempMesg->ptrCounter;
					if (ptrMC)	{
						// Shows Field Counter
						if (ptrMC->field)   {
							ptrMC->filter_type = FLT_FIELDCT;
#ifdef DEBUG
							printf("    Start Field Counter. (%u)\n", FLT_FIELDCT);
#endif
							MYFIELD_COUNTER *ptrF = ptrMC->field;
							while (ptrF)    {
								//				ptrF->id = traceList->nr_tot_filters;
								traceList->nr_tot_filters++;
								tempMesg->nr_filters++;

#ifdef DEBUG
								if (ptrF->prot)
									printf("	Protocol:%s\n", ptrF->prot);
								if (ptrF->numi)
									printf("	OffSet:%s\n", ptrF->numi);
								if (ptrF->wildid)
									printf("    Wild Card:%s\n", ptrF->wildid);
								if (ptrF->op)
									printf("    Operator:%s\n", ptrF->op);
								if (ptrF->dq_informal)
									printf("    Informal Text:%s\n", ptrF->dq_informal);
#endif
								ptrF = ptrF->next;
							}
						}

						// Shows Local Variable Field Counter
						if (ptrMC->lvfield)   {
							ptrMC->filter_type = FLT_VARFIELDCT;
#ifdef DEBUG
							printf("    Start Local Variables Field Counter. (%u)\n", FLT_VARFIELDCT);
#endif
							MYLFIELD_COUNTER *ptrlvF = ptrMC->lvfield;
							while (ptrlvF)    {
								//				ptrlvF->id = traceList->nr_tot_filters;
								traceList->nr_tot_filters++;
								tempMesg->nr_filters++;

#ifdef DEBUG
								if (ptrlvF->prot)
									printf("	Protocol:%s\n", ptrlvF->prot);
								if (ptrlvF->numi)
									printf("	OffSet:%s\n", ptrlvF->numi);
								if (ptrlvF->varid)
									printf("    Variable id:%s\n", ptrlvF->varid);
								printf("    Local:%d\n", ptrlvF->loc);
								if (ptrlvF->dq_informal)
									printf("    Informal Text:%s\n", ptrlvF->dq_informal);
#endif
								ptrlvF = ptrlvF->next;
							}
						}

						// Shows Global Variable Field Counter
						if (ptrMC->ltfield)   {
							ptrMC->filter_type = FLT_VARFIELDCT;
#ifdef DEBUG
							printf("    Start Trace Variables Field Counter. (%u)\n",
									FLT_VARFIELDCT);
#endif
							MYLFIELD_COUNTER *ptrltF = ptrMC->ltfield;
							while (ptrltF)    {
								//				ptrltF->id = traceList->nr_tot_filters;
								traceList->nr_tot_filters++;
								tempMesg->nr_filters++;

#ifdef DEBUG
								if (ptrltF->prot)
									printf("	Protocol:%s\n", ptrltF->prot);
								if (ptrltF->numi)
									printf("	OffSet:%s\n", ptrltF->numi);
								if (ptrltF->varid)
									printf("    Variable id:%s\n", ptrltF->varid);
								printf("    Local:%d\n", ptrltF->loc);
								if (ptrltF->dq_informal)
									printf("    Informal Text:%s\n", ptrltF->dq_informal);
#endif
								ptrltF = ptrltF->next;
							}
						}

						// Shows Bit Counter
						if (ptrMC->bit) {
							ptrMC->filter_type = FLT_BITCT;
#ifdef DEBUG
							printf("    Start Bit Counter. (%u)\n", FLT_BITCT);
#endif
							MYBIT_COUNTER *ptrB = ptrMC->bit;
							while (ptrB)    {
								//				ptrB->id = traceList->nr_tot_filters;
								traceList->nr_tot_filters++;
								tempMesg->nr_filters++;

#ifdef DEBUG
								if (ptrB->prot)
									printf("	Protocol:%s\n", ptrB->prot);
								if (ptrB->offset)
									printf("    OffSet:%s\n", ptrB->offset);
								if (ptrB->verb_size)
									printf("    Size:%s\n", ptrB->verb_size);
								if (ptrB->wildid)
									printf("    Wild Card:%s\n", ptrB->wildid);
								if (ptrB->op)
									printf("    Operator:%s\n", ptrB->op);
								if (ptrB->dq_informal)
									printf("    Informal Text:%s\n", ptrB->dq_informal);
#endif
								ptrB = ptrB->next;
							}
						}

						// Shows Local Variabel Bit Counter
						if (ptrMC->lvbit) {
							ptrMC->filter_type = FLT_VARBITCT;
#ifdef DEBUG
							printf("    Start Local Variables Bit Counter. (%u)\n", FLT_VARBITCT);
#endif
							MYLBIT_COUNTER *ptrlvB = ptrMC->lvbit;
							while (ptrlvB)    {
								//				ptrlvB->id = traceList->nr_tot_filters;
								traceList->nr_tot_filters++;
								tempMesg->nr_filters++;

#ifdef DEBUG
								if (ptrlvB->prot)
									printf("	Protocol:%s\n", ptrlvB->prot);
								if (ptrlvB->offset)
									printf("    OffSet:%s\n", ptrlvB->offset);
								if (ptrlvB->verb_size)
									printf("    Size:%s\n", ptrlvB->verb_size);
								if (ptrlvB->varid)
									printf("    Variable:%s\n", ptrlvB->varid);
								printf("    Local:%d\n", ptrlvB->loc);
								if (ptrlvB->dq_informal)
									printf("    Informal Text:%s\n", ptrlvB->dq_informal);
#endif
								ptrlvB = ptrlvB->next;
							}
						}

						// Shows Global Variable Bit Counter
						if (ptrMC->ltbit) {
							ptrMC->filter_type = FLT_VARBITCT;
#ifdef DEBUG
							printf("    Start Trace Variables Bit Counter. (%u)\n", FLT_VARBITCT);
#endif
							MYLBIT_COUNTER *ptrltB = ptrMC->ltbit;
							while (ptrltB)    {
								//				ptrltB->id = traceList->nr_tot_filters;
								traceList->nr_tot_filters++;
								tempMesg->nr_filters++;

#ifdef DEBUG
								if (ptrltB->prot)
									printf("	Protocol:%s\n", ptrltB->prot);
								if (ptrltB->offset)
									printf("    OffSet:%s\n", ptrltB->offset);
								if (ptrltB->verb_size)
									printf("    Size:%s\n", ptrltB->verb_size);
								if (ptrltB->varid)
									printf("    Variable:%s\n", ptrltB->varid);
								printf("    Local:%d\n", ptrltB->loc);
								if (ptrltB->dq_informal)
									printf("    Informal Text:%s\n", ptrltB->dq_informal);
#endif
								ptrltB = ptrltB->next;
							}
						}

						// Shows NoOffSet
						if (ptrMC->off) {
							ptrMC->filter_type = FLT_NOOFFSET;
#ifdef DEBUG
							printf("    Start NoOffset. (%u)\n", FLT_NOOFFSET);
#endif
							MYNO_OFFSET *ptrO = ptrMC->off;
							while (ptrO)    {
								//				ptrO->id = traceList->nr_tot_filters;
								traceList->nr_tot_filters++;
								tempMesg->nr_filters++;

#ifdef DEBUG
								if (ptrO->prot)
									printf("	Protocol:%s\n", ptrO->prot);
								if (ptrO->verb_id)
									printf("    Wild Card:%s\n", ptrO->verb_id);
								if (ptrO->dq_informal)
									printf("    Informal Text:%s\n", ptrO->dq_informal);
#endif
								ptrO = ptrO->next;
							}
						}
					}
				}
				tempMesg = tempMesg->next;
			}
		}

		// Read data that is present inside the GROUP and shows in screen.
		if (t->groups_sec) {
			MYGROUPS_SEC *tmpGrp = t->groups_sec;
			t->nr_groups++;
#ifdef DEBUG
			printf("Start Groups Section.\n");
#endif
			while (tmpGrp)  {
#ifdef DEBUG
				printf("	Group Name:%s\n", tmpGrp->groupName);
				printf("	Group Message:%s\n", tmpGrp->message);
#endif
				tmpGrp = tmpGrp->next;
			}
		}

		// Read data that is present inside the STATES and shows in screen.
		if (t->states_sec)	{
			MYSTATES_SEC *tmpState = t->states_sec;
#ifdef DEBUG
			printf("Start States Section:\n");
#endif
			while (tmpState)	{
#ifdef DEBUG
				printf("Final State: `%s'\n", tmpState->identifier);
#endif
				if (tmpState->ptr_state_sec)	{
					MYSTATES_SEC_FIELD *tCounter = tmpState->ptr_state_sec;
					while (tCounter)	{
						t->nr_estates++;
#ifdef DEBUG
						printf("    State: `%s'  -- id: %u\n", tCounter->identi, tCounter->id);
#endif
						if (tCounter->ptrSfield)	{
							MYSFIELD *ptr = tCounter->ptrSfield;
							while (ptr)    {
								tCounter->nr_transitions++;
#ifdef DEBUG
								printf("      Identifier: `%s'\n", ptr->dqid);
								printf("      GotoState:  `%s'\n", ptr->id);
#endif
								ptr = ptr->next;
							}
						}
						tCounter = tCounter->next;
					}
				}
				tmpState = tmpState->next;
			}
		}

		printf("Numero de mensagens: %u\n", t->nr_msgs);
		printf("Numero de grupos:    %u\n", t->nr_groups);
		printf("Numero de estados:   %u\n", t->nr_estates);
		printf("Numero de filtros:   %u\n", t->nr_tot_filters);

		t = t->next;
	}
}


/**
 *	freeTrace() - Function that free all the memory allocated by the Parser.
 *	To make this function funtional it should be enable at traaser.y, its
 *	necessary to make a call to this func.
 *	@param traceList is a pointer to the hole trace definition.
 *	@see MYTRACE
 */
void
freeTrace(MYTRACE *traceList)
{
	MYTRACE *tPtr = NULL;

	if (traceList == NULL) {
		fprintf(stderr, "Nothing to deallocate. Exiting...\n");
		exit(-1);
	} else {
		tPtr = traceList;
	}

	while (tPtr)    {
		if (tPtr->head)	{
			MYHEADER *hPtr = tPtr->head;
#ifdef DEBUG
			fprintf(stderr, "Start to release Header members memory!\n");
#endif
			if (hPtr->version)
				free(hPtr->version);
			if (hPtr->description)
				free(hPtr->description);
			if (hPtr->key)
				free(hPtr->key);
			if (hPtr->port)
				free(hPtr->port);
			if (hPtr->owner)
				free(hPtr->owner);
			if (hPtr->last_update)
				free(hPtr->last_update);
			if (hPtr->reference)
				free(hPtr->reference);
			if (hPtr->behave)
				free(hPtr->behave);
		}

		if (tPtr->msgs_sec)   {
			MYMESSAGES_SEC *mPtr = tPtr->msgs_sec;
#ifdef DEBUG
			fprintf(stderr, "Start to release Messages members memory!\n");
#endif
			while (mPtr)	{
				if (mPtr->messageName)
					free(mPtr->messageName);
				if (mPtr->messageType)
					free(mPtr->messageType);
				if (mPtr->timeout)
					free(mPtr->timeout);
				if (mPtr->ptrCounter)   {
					if (mPtr->ptrCounter)   {
						MYMESSAGES_SEC_C *cPtr = mPtr->ptrCounter;
						if (cPtr->field)   {
							MYFIELD_COUNTER *fPtr = cPtr->field;
#ifdef DEBUG
							fprintf(stderr, "Start to release Field Counter memory!\n");
#endif
							while (fPtr)    {
								if (fPtr->prot)
									free(fPtr->prot);
								if (fPtr->numi)
									free(fPtr->numi);
								if (fPtr->wildid)
									free(fPtr->wildid);
								if (fPtr->op)
									free(fPtr->op);
								if (fPtr->dq_informal)
									free(fPtr->dq_informal);
								fPtr->id = 0;
								fPtr = fPtr->next;
							}
						}

						if (cPtr->lvfield)   {
							MYLFIELD_COUNTER *lvfPtr = cPtr->lvfield;
#ifdef DEBUG
							fprintf(stderr, "Start to release Local Field Counter memory!\n");
#endif
							while (lvfPtr)    {
								if (lvfPtr->prot)
									free(lvfPtr->prot);
								if (lvfPtr->numi)
									free(lvfPtr->numi);
								if (lvfPtr->varid)
									free(lvfPtr->varid);
								if (lvfPtr->dq_informal)
									free(lvfPtr->dq_informal);
								lvfPtr->id = 0;
								lvfPtr = lvfPtr->next;
							}
						}

						if (cPtr->ltfield)   {
							MYLFIELD_COUNTER *ltfPtr = cPtr->ltfield;
#ifdef DEBUG
							fprintf(stderr, "Start to release Trace Field Counter memory!\n");
#endif
							while (ltfPtr)    {
								if (ltfPtr->prot)
									free(ltfPtr->prot);
								if (ltfPtr->numi)
									free(ltfPtr->numi);
								if (ltfPtr->varid)
									free(ltfPtr->varid);
								if (ltfPtr->dq_informal)
									free(ltfPtr->dq_informal);
								ltfPtr->id = 0;
								ltfPtr = ltfPtr->next;
							}
						}

						if (cPtr->bit)  {
							MYBIT_COUNTER *bPtr = cPtr->bit;
#ifdef DEBUG
							fprintf(stderr, "Start to release Bit Counter memory!\n");
#endif
							while (bPtr)    {
								if (bPtr->prot)
									free(bPtr->prot);
								if (bPtr->offset)
									free(bPtr->offset);
								if (bPtr->verb_size)
									free(bPtr->verb_size);
								if (bPtr->wildid)
									free(bPtr->wildid);
								if (bPtr->op)
									free(bPtr->op);
								if (bPtr->dq_informal)
									free(bPtr->dq_informal);
								bPtr->id = 0;
								bPtr = bPtr->next;
							}
						}

						if (cPtr->bit)  {
							MYLBIT_COUNTER *lvbPtr = cPtr->lvbit;
#ifdef DEBUG
							fprintf(stderr, "Start to release Local Bit Counter memory!\n");
#endif
							while (lvbPtr)    {
								if (lvbPtr->prot)
									free(lvbPtr->prot);
								if (lvbPtr->offset)
									free(lvbPtr->offset);
								if (lvbPtr->verb_size)
									free(lvbPtr->verb_size);
								if (lvbPtr->varid)
									free(lvbPtr->varid);
								if (lvbPtr->dq_informal)
									free(lvbPtr->dq_informal);
								lvbPtr->id = 0;
								lvbPtr = lvbPtr->next;
							}
						}

						if (cPtr->bit)  {
							MYLBIT_COUNTER *ltbPtr = cPtr->ltbit;
#ifdef DEBUG
							fprintf(stderr, "Start to release Trace Bit Counter memory!\n");
#endif
							while (ltbPtr)    {
								if (ltbPtr->prot)
									free(ltbPtr->prot);
								if (ltbPtr->offset)
									free(ltbPtr->offset);
								if (ltbPtr->verb_size)
									free(ltbPtr->verb_size);
								if (ltbPtr->varid)
									free(ltbPtr->varid);
								if (ltbPtr->dq_informal)
									free(ltbPtr->dq_informal);
								ltbPtr->id = 0;
								ltbPtr = ltbPtr->next;
							}
						}

						if (cPtr->off) {
							MYNO_OFFSET *oPtr = cPtr->off;
#ifdef DEBUG
							fprintf(stderr, "Start to release NoOffSet memory!\n");
#endif
							while (oPtr)	{
								if (oPtr->prot)
									free(oPtr->prot);
								if (oPtr->verb_id)
									free(oPtr->verb_id);
								if (oPtr->dq_informal)
									free(oPtr->dq_informal);
								oPtr = oPtr->next;
							}
						}
					}
				}
				mPtr = mPtr->next;
			}
		}

		if (tPtr->groups_sec)	{
			MYGROUPS_SEC *gPtr = tPtr->groups_sec;
#ifdef DEBUG
			fprintf(stderr, "Start to release Groups memory!\n");
#endif
			while (gPtr)  {
				if (gPtr->groupName)
					free(gPtr->groupName);
				if (gPtr->message)
					free(gPtr->message);
				gPtr = gPtr->next;
			}
		}

		if (tPtr->states_sec)	{
			MYSTATES_SEC *sPtr = tPtr->states_sec;
#ifdef DEBUG
			fprintf(stderr, "Start to release States memory!\n");
#endif
			while (sPtr)	{
				if (sPtr->identifier)
					free(sPtr->identifier);
				if (sPtr->ptr_state_sec)	{
					MYSTATES_SEC_FIELD *scPtr = sPtr->ptr_state_sec;
#ifdef DEBUG
					fprintf(stderr, "Start to release States Content memory!\n");
#endif
					while (scPtr)	{
						if (scPtr->identi)
							free(scPtr->identi);
						if (scPtr->ptrSfield)	{
							MYSFIELD *fscPtr = scPtr->ptrSfield;
							while (fscPtr)    {
								if (fscPtr->dqid)
									free(fscPtr->dqid);
								if (fscPtr->id)
									free(fscPtr->id);
								fscPtr = fscPtr->next;
							}
						}
						scPtr = scPtr->next;
					}
				}
				sPtr = sPtr->next;
			}
		}
		tPtr = tPtr->next;
	}
}

static unsigned int
do_converte_operador(char *oper_str)
{
	if (!strcmp(oper_str, "=")) {
		return OPER_IGUAL;
	}
	if (!strcmp(oper_str, ">")) {
		return OPER_MAIOR;
	}
	if (!strcmp(oper_str, ">=")) {
		return OPER_MAIORIGUAL;
	}
	if (!strcmp(oper_str, "<")) {
		return OPER_MENOR;
	}
	if (!strcmp(oper_str, "<=")) {
		return OPER_MENORIGUAL;
	}
	if (!strcmp(oper_str, "!=")) {
		return OPER_DIFERENTE;
	}

	return OPER_ARMAZENAR;
}


/**
 *  \brief Finds a Message by its double-quoted identifier.
 *
 *  Searches in the MYMESSAGES_SEC structure list.
 *
 *  \param *msg_ptr	Pointer to the MYMESSAGES_SEC list head.
 *  \param *that_ptr	Pointer to the double-quoted identifier to look for.
 *
 *  \return If found, a pointer to the Message; NULL otherwise.
 */
	static MYMESSAGES_SEC *
do_acha_mensagem_pelo_dqid(MYMESSAGES_SEC *msg_ptr, char *that_ptr)
{
	while (msg_ptr != NULL) {
		if (!strcmp(msg_ptr->messageName, that_ptr)) {
			return msg_ptr;
		}

		msg_ptr = msg_ptr->next;
	}

	return NULL;
}


static struct idlist_s *
do_monta_lista_ordenada_filtros(MYMESSAGES_SEC_C *msg_c_ptr)
{
	struct idlist_s *lista_ptr;
	struct idlist_s *last_ptr;
	MYFIELD_COUNTER *field_ptr;
	MYBIT_COUNTER   *bit_ptr;
	unsigned int    flag_repetir;
	unsigned int    em_loop = 20;

	if ((msg_c_ptr == NULL)) {
		fprintf(stderr, "do_monta_lista_ordenada_filtros: NULL\n");
		return NULL;
	}

	field_ptr = msg_c_ptr->field;
	bit_ptr = msg_c_ptr->bit;

	/*
	 *	primeiro incluir todos os filtros na lista
	 *	este primeiro nodo é um nodo dummy
	 */
	lista_ptr = calloc(1, sizeof(struct idlist_s));
	last_ptr = lista_ptr;

	em_loop = 20;
	while ((field_ptr != NULL) && em_loop) {
		em_loop--;
		last_ptr->next = malloc(sizeof(struct idlist_s));

		if ((last_ptr->next == NULL)) {
			fprintf(stderr, "trasserlib.c: memory allocation error on 56667\n");
			return NULL;
		}

		last_ptr = last_ptr->next;
		last_ptr->filter_id = field_ptr->id;
		field_ptr = field_ptr->next;
	}

	em_loop = 20;
	while ((bit_ptr != NULL) && em_loop){
		em_loop--;
		last_ptr->next = malloc(sizeof(struct idlist_s));

		if ((last_ptr->next == NULL)) {
			fprintf(stderr, "trasserlib.c: memory allocation error on 56668\n");
			return NULL;
		}

		last_ptr = last_ptr->next;
		last_ptr->filter_id = bit_ptr->id;

		bit_ptr = bit_ptr->next;
	}

	last_ptr->next = NULL;

	/*
	 *	ordenar, usando bubble
	 */
	do {
		em_loop--;
		flag_repetir = 0;
		last_ptr = lista_ptr->next;
		while (last_ptr != NULL) {
			if ((last_ptr->next != NULL) && (last_ptr->next->filter_id < last_ptr->filter_id)) {
				flag_repetir = last_ptr->filter_id;
				last_ptr->filter_id = last_ptr->next->filter_id;
				last_ptr->next->filter_id = flag_repetir;
				flag_repetir = 1;
			}
			last_ptr = last_ptr->next;
		}
	} while (flag_repetir && em_loop);

	return lista_ptr->next;
}


static unsigned int
do_acha_estado(MYSTATES_SEC *sec_ptr, char *_nome)
{
	char		*nome = strtok(_nome, "\r\n\t ");
	char		*talvez = NULL;
	MYSTATES_SEC_FIELD	*fld_ptr;

	while (sec_ptr != NULL) {
		fld_ptr = sec_ptr->ptr_state_sec;
		while (fld_ptr != NULL) {
			talvez = strtok(fld_ptr->identi, "\r\n\t ");
			if (!strcmp(talvez, nome)) {
				return fld_ptr->id;
			}

			fld_ptr = fld_ptr->next;
		}

		sec_ptr = sec_ptr->next;
	}

	/* forçar um segfault */
	return 0xffffffff;
}


static int
do_converte_direcao(char *dir)
{
	if (!strcasecmp(dir, "client")) return FROM_CLIENT;
	if (!strcasecmp(dir, "server")) return FROM_SERVER;

	return FROM_ANY;
}


static int
do_resolve_enlace(const char *s)
{
	if (s == NULL) {
		return 0;
	}

	if ((strcasecmp(s, "ethernet") == 0) || (strcasecmp(s, "ether") == 0) ||
			(strcasecmp(s, "ether2") == 0)) {
		return 1;
	}

	return 0;
}

static int
do_resolve_rede(const char *s)
{
	if (s == NULL) {
		return 0;
	}

	if ((strcasecmp(s, "ipv4") == 0) || (strcasecmp(s, "ip") == 0)) {
		return 2048;
	}

	return 0;
}

static int
do_resolve_transporte(const char *s)
{
	if (s == NULL) {
		return 0;
	}

	if ((strcasecmp(s, "tcp") == 0)) {
		return 6;
	}

	if ((strcasecmp(s, "udp") == 0)) {
		return 17;
	}

	if ((strcasecmp(s, "icmp") == 0)) {
		return 1;
	}

	return 0;
}


/**
 *	popTrace() - Code that populates Ricardo's structurer.
 *	@param traceList is a pointer to the hole trace definition.
 *	@see MYTRACE
 */
void
popTrace(MYTRACE *traceList)
{
	depende_t		depende[3] = { {0, } };
	descricao_t		descr = {NULL, };
	traco_t		*t_ptr;
	MYFIELD_COUNTER	*field_ptr;
	MYBIT_COUNTER	*bit_ptr;
	u_int		i, timeout;
	MYSTATES_SEC	*state_sec_ptr = traceList->states_sec;
	MYSTATES_SEC_FIELD	*state_fld_ptr;
	MYMESSAGES_SEC	*msg_ptr = traceList->msgs_sec;
	struct idlist_s	*lista = NULL;
	char		*estado_final_str = NULL;
	char		*pode_ser_final_str = NULL;
	char		*enla_str;
	char		*rede_str;
	char		*tran_str;
	u_int		i_deps;
	u_int		f_encaps;

	i = i_deps = timeout = 0;

	/* Fill the struct descricao_s */
	if (traceList->traceName != NULL) {
		descr.nome = strdup(traceList->traceName);
	}
	fprintf(stderr, "Descricao: `%s'\n", descr.nome);

	MYHEADER *tempHead = traceList->head;
	if (tempHead) {
		if (tempHead->version) {
			descr.versao = strdup(tempHead->version);
		}

		if (tempHead->description) {
			descr.descricao = strdup(tempHead->description);
		}

		if (tempHead->key) {
			descr.palavras = strdup(tempHead->key);
		}

		if (tempHead->port) {
			descr.porta = strdup(tempHead->port);
		}

		if (tempHead->owner) {
			descr.criador = strdup(tempHead->owner);
		}

		if (tempHead->last_update) {
			descr.atualizacao = strdup(tempHead->last_update);
		}

		if (tempHead->reference) {
			descr.references = strdup(tempHead->reference);
		}
		/*  FIXME For now this option is not available.
		 * 	if (tempHead->behave)
		 *	    tempHead->behave;
		 */
	}

	/*
	 * - assumindo que o encapsulamento eh ether2.ipv4.tcp.atoi(porta)
	 * - variaveis ainda nao suportadas
	 * XXX
	 * E se a porta, nao for definida dentro do cabecalho dentro do arquivo de
	 *  traco?! Entao teremos lixo ou um valor loco dentro e abaixo no
	 *  preenchimento poderemos ter problemas!!!
	 */

	enla_str = strtok(traceList->head->encap, "./ \t\n\r");
	rede_str = strtok(NULL, "./ \t\n\r");
	tran_str = strtok(NULL, "./ \t\n\r");

	t_ptr = pdir_cria_traco(do_resolve_enlace(enla_str), do_resolve_rede(rede_str),
			do_resolve_transporte(tran_str), atoi(traceList->head->port),
			traceList->nr_estates, traceList->nr_tot_filters, 0, &descr, 0xdeadbeef);
	if (t_ptr == NULL) {
		fprintf(stderr, "Bah, problema serio a vista!!!.\n");
		return;
	}

	/*
	 * agora para cada filtro, precisamos preencher a estrutura do traco
	 * alocado.  os filtros estao dentro das mensagens, entao as mensagens
	 * tambem devem ser percorridas.
	 */
	//    MYMESSAGES_SEC_C	*filter_ptr;

	for (i = 0; i < traceList->nr_msgs; i++, msg_ptr = msg_ptr->next) {
		fprintf(stderr, " | message %u of %u\n", i, traceList->nr_msgs);
		if (msg_ptr->ptrCounter) {
			if (msg_ptr->timeout != NULL) {
				timeout = (u_int) atoi(msg_ptr->timeout);
			}
			if (timeout <= 0) {
				/* default timeout of 10min (600s) */
				timeout = 600000;
			}

			field_ptr = msg_ptr->ptrCounter->field;
			bit_ptr = msg_ptr->ptrCounter->bit;

			while (field_ptr != NULL) {
				/* clever trick to infer encapsulation type */
				strtok(field_ptr->prot, " /\n\r\t");
				f_encaps = 0;
				while (strtok(NULL, " /\n\r\t") != NULL) {
					f_encaps++;
				}
				if (f_encaps > OFF_APLICACAO) {
					fprintf(stderr, "Ooops... filter encapsulation too long!\n");
					abort();
				}

				if (tracos_preenche_mensagem(&(t_ptr->mensagens[field_ptr->id]),
							field_ptr->dq_informal,
							strlen(field_ptr->wildid),
							field_ptr->wildid,
							atoi(field_ptr->numi),
							FLT_FIELDCT,
							CMP_CHAVEPTR_E_PACOTE,
							do_converte_operador(field_ptr->op),
							timeout,
							NULL,
							do_converte_direcao(msg_ptr->messageType),
							f_encaps) == SUCCESS) {
					fprintf(stderr, " +-- filter (FieldCounter) %u OK\n", field_ptr->id);
				}
				else {
					fprintf(stderr, "trasserlib.c: error while initializing filter %u\n",
							field_ptr->id);
				}

				field_ptr = field_ptr->next;
			}

			while (bit_ptr != NULL) {
				/* clever trick to infer encapsulation type */
				strtok(bit_ptr->prot, " /\n\r\t");
				f_encaps = 0;
				while (strtok(NULL, " /\n\r\t") != NULL) {
					f_encaps++;
				}
				if (f_encaps > OFF_APLICACAO) {
					fprintf(stderr, "Ooops... filter encapsulation too long!\n");
					abort();
				}

				if (tracos_preenche_mensagem(&(t_ptr->mensagens[bit_ptr->id]),
							bit_ptr->dq_informal,
							atoi(bit_ptr->verb_size),
							bit_ptr->wildid,
							atoi(bit_ptr->offset),
							FLT_BITCT,
							CMP_CHAVEPTR_E_PACOTE,
							do_converte_operador(bit_ptr->op),
							timeout,
							NULL,
							do_converte_direcao(msg_ptr->messageType),
							f_encaps) == SUCCESS) {
					fprintf(stderr, " +-- filter (BitCounter)   %u OK\n", bit_ptr->id);
				}
				else {
					fprintf(stderr, "trasserlib.c: error while initializing filter %u\n",
							bit_ptr->id);
				}

				bit_ptr = bit_ptr->next;
			}
		}
	}

	/*
	 *	para cada estado
	 *	    para cada 1 das 3 possiveis msgs
	 *		preenche filtro principal
	 *		preencha até 3 dependencias (E logico)
	 *	    feitoria
	 *	feitoria
	 */
	while (state_sec_ptr != NULL) {
		state_fld_ptr = state_sec_ptr->ptr_state_sec;
		estado_final_str = strtok(state_sec_ptr->identifier, "\r\n\t ");
		i = 0;
		while ((state_fld_ptr != NULL) && (i < 3)) {
			pode_ser_final_str = strtok(state_fld_ptr->identi, "\r\n\t ");
			if (!strcmp(pode_ser_final_str, estado_final_str)) {
				if (tracos_preenche_estado_final(t_ptr, &(t_ptr->estados[state_fld_ptr->id])) != SUCCESS) {
					fprintf(stderr, "trasserlib.c: erro ao marcar o estado final\n");
					abort();
				}

				fprintf(stderr, " * estado final encontrado: `%s' == `%s'\n",
						pode_ser_final_str, estado_final_str);
			}

			memset(depende, 0, sizeof(depende));
			msg_ptr = do_acha_mensagem_pelo_dqid(traceList->msgs_sec, state_fld_ptr->ptrSfield->dqid);
			if (msg_ptr != NULL) {
				lista = do_monta_lista_ordenada_filtros(msg_ptr->ptrCounter);
				i_deps = 1;
				if ((lista == NULL)) {
					fprintf(stderr, "trasserlib.c: lista vazia\n");
					abort();
				}
				depende[0].mensagem = &(t_ptr->mensagens[lista->filter_id]);
				if (msg_ptr->nr_filters > 1) {
					depende[0].msg_depende_0 = &(t_ptr->mensagens[lista->next->filter_id]);
					depende[0].nr_msg_depende++;
				}
				if (msg_ptr->nr_filters > 2) {
					depende[0].msg_depende_1 = &(t_ptr->mensagens[lista->next->next->filter_id]);
					depende[0].nr_msg_depende++;
				}
				if (msg_ptr->nr_filters > 3) {
					depende[0].msg_depende_2 = &(t_ptr->mensagens[lista->next->next->next->filter_id]);
					depende[0].nr_msg_depende++;
				}
				if (msg_ptr->nr_filters > 4) {
					fprintf(stderr, "trasserlib.c: somente 4 filtros por enquanto (992912)\n");
				}
			}

			if ((tracos_preenche_estado(&(t_ptr->estados[state_fld_ptr->id]),
							state_fld_ptr->identi,
							i_deps,
							depende,
							&(t_ptr->estados[do_acha_estado(state_sec_ptr, state_fld_ptr->ptrSfield->id)]))
						!= SUCCESS)) {
				fprintf(stderr, "trasserlib.c: erro ao preencher o estado %u\n",
						state_fld_ptr->id);
				abort();
			}

			fprintf(stderr, "estado %u preenchido\n", state_fld_ptr->id);

			i++;
			state_fld_ptr = state_fld_ptr->next;
		}

		state_sec_ptr = state_sec_ptr->next;
	}


#if 0
	/*
	 *	Read data that is present inside the GROUP and shows in screen.
	 */
	MYGROUPS_SEC *tmpGrp = traceList->groups_sec;
	if (tmpGrp) {
		printf("Start Groups Section.\n");
		while (tmpGrp)  {
			printf("    Group Name:%s\n", tmpGrp->groupName);
			printf("    Group Message:%s\n", tmpGrp->message);
			tmpGrp = tmpGrp->next;
		}
	}

	MYSTATES_SEC *tmpState = traceList->states_sec;
	if (tmpState)	{
		printf("Start States Section:\n");
		while (tmpState)	{
			nr_estados++;
			printf("")
				tmpState = tmpState->next;
		}
	}
	//printf(" %s\n",tempMesg->messageName);
	//	printf("Nr tracos=%d", nr_tracos);
	//}
	//	traceList = traceList->next;
	//    }
printf("Numero de mensagens: %d\n", nr_msgs);
#endif
}
