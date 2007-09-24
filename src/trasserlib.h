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

/** \file trasserlib.h
 *	Trasser structures description.
 *	Definitions to various structures used to store the elements that compose the PTSL.
 */

#ifndef	TRASSERLIB_H
#define	TRASSERLIB_H

/******************************************************************************

    FIELD COUNTER Struct Declaration

******************************************************************************/
typedef struct sHeader MYHEADER; /**< Header Declaration */
/**
 * HEADER Declaration.
 * Header is composed of several elements that may or may not apear in a PTSL declaration.
 * @see MYHEADER
 * */
struct sHeader {
	char	*version;	/**< version */
	char	*description;	/**< description */
	char	*key;		/**< keywords */
	char	*port;		/**< port */
	char	*encap;		/**< encapsulation */
	char	*owner;		/**< owner */
	char	*last_update;	/**< last update */
	char	*reference;	/**< reference */
	char	*behave;	/**< behavior */
};

/******************************************************************************

    FIELD COUNTER Struct Declaration

******************************************************************************/
typedef struct sField_Counter MYFIELD_COUNTER; /**< Field Counter Declaration */
/**
 *	FIELD COUNTER Struct Declaration.
 *	Field Counter contains various declaration necessary in the messages section.
 *	@see MYFIELD_COUNTER
 * */
struct sField_Counter {
	unsigned int    id;	    /** unique id used to ease filter access */
	char	    *prot;	    /**< protocol encapsulation */
	char	    *numi;	    /**< offset */
	char	    *wildid;	    /**< wildcard or verb identifier */
	char	    *op;	    /**< operator symbol */
	char	    *dq_informal;   /**< double quotted informal text */
	MYFIELD_COUNTER *next;	    /**< pointer to another field structure */
};

typedef struct sLField_Counter MYLFIELD_COUNTER; /**< Local Field Counter Declaration*/
/**
 *	VARIABLE FIELD COUNTER Struct Declaration.
 *	@see MYLFIELD_COUNTER
 * */
struct sLField_Counter {
	unsigned int	id;		/** unique id used to ease filter access */
	char		*prot;		/**< protocol encapsulation */
	char		*numi;		/**< offset */
	char		*varid;		/**< variable identifier */
	char		*dq_informal;	/**< double quotted informal text */
	unsigned int	loc;		/**< if loc == 0 its a local variable */
	MYLFIELD_COUNTER *next;		/**< pointer to another field structure */
};

/******************************************************************************

    BIT COUNTER Struct Declaration

******************************************************************************/
typedef struct sBit_Counter MYBIT_COUNTER; /**< Bit Counter */
/**
 *	BIT COUNTER Declaration.
 *	Bit Counter Struct members.
 *	@see MYBITCOUNTER
 * */
struct sBit_Counter {
	unsigned int	id;		/** unique id used to ease filter access */
	char		*prot;		/**< protocol encapsulation */
	char		*offset;	/**< offset */
	char		*verb_size;	/**< size */
	char		*wildid;	/**< wildcard or verb identifier */
	char		*op;		/**< operator symbol */
	char		*dq_informal;	/**< double quotted informal text */
	MYBIT_COUNTER	*next;		/**< pointer to another bit structure */
};

typedef struct sLBit_Counter MYLBIT_COUNTER; /**< Local Bit Counter Declaration */
/**
 *	LOCAL BIT COUNTER Declaration.
 *	Local Bit Counter Struct members.
 *	@see MYLBIT_COUNTER
 * */
struct sLBit_Counter {
	unsigned int	id;		/** unique id used to ease filter access */
	char		*prot;		/**< protocol encapsulation */
	char		*offset;	/**< offset */
	char		*verb_size;	/**< size */
	char		*varid;		/**< variable identifier */
	char		*dq_informal;	/**< double quotted informal text */
	unsigned int	loc;		/**< if loc == 0 its a local variable */
	MYLBIT_COUNTER	*next;		/**< pointer to another bit structure */
};

/******************************************************************************

    NOOFFSET Struct Declaration

******************************************************************************/
typedef struct sNo_Offset MYNO_OFFSET; /**< NoOffSet Declaration */
/**
 *	NOOFFSET Declaration.
 *	NoOffSet Struct members.
 *	@see MYNO_OFFSET
 * */
struct sNo_Offset {
	unsigned int	id;		/** unique id used to ease filter access */
	char		*prot;		/**< protocol encapsulation */
	char		*verb_id;	/**< wildcard or verb identifier */
	char		*dq_informal;	/**< double quotted informal text */
	MYNO_OFFSET	*next;		/**< pointer to another nooffset structure */
};

/******************************************************************************

    MESSAGES Section Struct Declaration

******************************************************************************/
typedef struct sMessage_Sec_C MYMESSAGES_SEC_C; /**< Messages Section Declaration */
/**
 *	MESSAGES SECTION Declaration.
 *	Messages Section Struct members definition.
 *	@see MYFIELD_COUNTER
 *	@see MYBIT_COUNTER
 *	@see MYNO_OFFSET
 *	@see MYLFIELD_COUNTER
 *	@see MYLBIT_COUNTER
 *	@see MYMESSAGES_SEC_C
 * */
struct sMessage_Sec_C {
	unsigned int		filter_type;/** filter type code (MSG_BITCT, ...) */
	MYFIELD_COUNTER		*field;	/**< field counter struct */
	MYBIT_COUNTER		*bit;	/**< bit counter struct */
	MYNO_OFFSET		*off;	/**< nooffset struct */
	MYLFIELD_COUNTER	*lvfield;/**< local variable field counter struct */
	MYLFIELD_COUNTER	*ltfield;/**< trace variable field counter struct */
	MYLBIT_COUNTER		*lvbit;	/**< local variable bit counter struct */
	MYLBIT_COUNTER		*ltbit;	/**< trace variable bit counter struct */
	MYMESSAGES_SEC_C	*next;	/**< pointer */
};

typedef struct sMessage_Sec MYMESSAGES_SEC;
/**
 *	MESSAGES Declaration.
 *	Messages
 *	@see MYMESSAGES_SEC
 *	@see MYMESSAGES_SEC_C
 * */
struct sMessage_Sec {
	char			*messageName;	/**< message name */
	char			*messageType;	/**< message type */
	char			*timeout;	/**< message timeout */
	unsigned int		nr_filters;	/** number of filters ((Bit|Field)Counter, Nooffset */
	MYMESSAGES_SEC		*next;	/**< pointer to another message content, used by trasser */
	MYMESSAGES_SEC_C	*ptrCounter;	/**< pointer to counters structures, used by trasser */
};

/******************************************************************************

    GROUPS Section Struct Declaration

******************************************************************************/
typedef struct sGroup_Sec MYGROUPS_SEC; /**< Groups Declaration */
/**
 *	GROUPS Declaration.
 *	Groups Struct members declaration.
 *	@see MYGROUPS_SEC
 * */
struct sGroup_Sec {
	char		*groupName;	/**< message name */
	char		*message;	/**< message description */
	MYGROUPS_SEC	*next;		/**< pointer to another group message description, used by trasser */
};

/******************************************************************************

    STATES Section Struct Declaration

******************************************************************************/
typedef struct sStates_Content_Field MYSFIELD; /**< States Field Declaration */
/**
 * 	MYSFIELD Declaration.
 *	@see MYSFIELD
 * */
struct sStates_Content_Field {
	char		*dqid;	/**< double quotted identifier */
	char		*id;	/**< identifier */
	MYSFIELD	*next;	/**< ptr to another structure, used by trasser */
};

typedef struct sState_Sec_Field MYSTATES_SEC_FIELD; /**< States Section Declaration */
/**
 *	MYSTATES_SEC_FIELD Declaration.
 *	@see MYSFIELD
 *	@see MYSTATES_SEC_FIELD
 * */
struct sState_Sec_Field {
	char			*identi;	/**< state identifier */
	MYSTATES_SEC_FIELD	*next;		/**< pointer to another structure */
	MYSFIELD		*ptrSfield;	/**< pointer to a SFielfd Structure, used by trasser */
	unsigned int		nr_transitions;	/** number of transitions for this state */
	unsigned int		id;		/** state unique identifier */
};

typedef struct sState_Sec MYSTATES_SEC; /**< States Declaration */
/**
 *	STATES Declaration.
 *	States Struct members declaration.
 *	@see MYSTATES_SEC
 *	@see MYSTATES_SEC_FIELD
 * */
struct sState_Sec {
	char			*identifier;	/**< state identifier */
	MYSTATES_SEC		*next;		/**< ptr to another structure, used by trasser */
	MYSTATES_SEC_FIELD	*ptr_state_sec;	/**< pointer to state content field, used by trasser */
};

/******************************************************************************

    TRACE Struct Declaration

******************************************************************************/
typedef struct sTrace MYTRACE; /**< Trace Declaration */
/**
 *	TRACE Struct Declaration.
 *	Here all the members that are part of the PTSL description are defined.
 * */
struct sTrace {
	char		*traceName;	/**< trace script name (Mandatory) */
	unsigned int	trace_id;	/** trace unique identifier */
	unsigned int	nr_estates;	/**< number of states, used by trasser */
	unsigned int	nr_msgs;	/**< number of messages, used by trasser */
	unsigned int	nr_tot_filters; /** total number of filters */
	unsigned int	nr_vars;	/**< number of variables, used by trasser */
	unsigned int	nr_groups;	/**< number of groups, used by trasser */
	MYHEADER	*head;		/**< trace header section (Mandatory) */
	MYMESSAGES_SEC	*msgs_sec;	/**< trace messages_section (Mandatory) */
	MYGROUPS_SEC	*groups_sec;	/**< trace groups_section (Mandatory) */
	MYSTATES_SEC	*states_sec;	/**< trace states_section (Mandatory) */
	MYTRACE		*next;		/**< pointer to another trace structure, used by trasser */
};

/******************************************************************************

    Methods Prototype Declarations

******************************************************************************/
MYTRACE		    *getNewTrace();		// Creates a new Trace
MYHEADER	    *getNewHeader();		// Creates a new Header for a Trace
MYMESSAGES_SEC	    *getNewMessage();		// Creates a new Messages Section
MYMESSAGES_SEC_C    *getNewMessage_Sec_C();	// Creates a new Message Counter
MYGROUPS_SEC	    *getNewGroup();		// Creates a new Groups Section
MYSTATES_SEC	    *getNewState();		// Creates a new States Section
MYSTATES_SEC_FIELD  *getNewStateField();	// Creates a new States Field
MYSFIELD	    *getNewSField();		// Creates a new States Content Field
MYFIELD_COUNTER	    *getNewFieldCounter();	// Creates a new Field Counter
MYLFIELD_COUNTER    *getNewLFieldCounter();	// Creates a new Local Field Counter
MYBIT_COUNTER	    *getNewBitCounter();	// Creates a new Bit Counter
MYLBIT_COUNTER	    *getNewLBitCounter();	// Creates a new Local Bit Counter
MYNO_OFFSET	    *getNewNoOffset();		// Creates a new NoOffset
// Shows the content of Trace
void		    displayDataStruct(MYTRACE *traceList);
// Frees the memory allocated by the parser
void		    freeTrace(MYTRACE *tlist);
// Populates all Trace Structs
void		    popTrace(MYTRACE *tlist);

#endif
