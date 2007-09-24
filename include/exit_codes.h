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

#define	SUCCESS		    0
#define ERROR_NOSUCHENTRY   (-1)    /* entry not found in list/table */
#define ERROR_ALREADYEXISTS (-4)    /* entry already exists in the table */
#define ERROR_FULL	    (-8)    /* list/table is full */
#define ERROR_EMPTY	    (-12)   /* index list is empty */
#define ERROR_LASTENTRY	    (-16)   /* last item in the index list */
#define ERROR_HASH	    (-20)   /* something bad happened in the hash table */
#define ERROR_PKTQUEUE	    (-24)   /* packet queue reported error */
#define ERROR_MALLOC	    (-28)   /* error while malloc'ing memory */
#define ERROR_CALLOC	    (-29)   /* similar, but while calloc'ing memory */
#define ERROR_INDEXLIST	    (-32)   /* FIXME index list returned an error */
#define ERROR_EVILVALUE	    (-36)   /* invalid value passed as parameter */
#define ERROR_IO	    (-40)   /* file or other I/O operation failed */
#define ERROR_THREAD	    (-44)   /* thread creation error */
#define ERROR_ISACTIVE	    (-48)   /* trying to activate an active entry */
#define ERROR_ISINACTIVE    (-52)   /* operation on inactive entry */
#define ERROR_PARAMETER	    (-56)   /* some parameter has an invalid value */

/* trace specific */
#if PTSL
#define TRACE_INIT_ERROR    (-71)   /* PTSL engine initialization error */
#define TRACE_VAR_ERROR	    (-72)   /* generic error with a variable (init or use) */
#define TRACE_MSG_ERROR	    (-73)   /* generic error with a message (init or use) */
#define TRACE_STT_ERROR	    (-74)   /* generic error with a state (init or use) */
#define TRACE_NULL_ERROR    (-75)   /* bug discovered due to NULL pointer use */
#define TRACE_PARSERERROR   (-76)   /* parser error in the supplied PTSL file */
#define TRACE_EXPIRED	    (-78)   /* trace is no longer valid due to time expired */
#define TRACE_NEXTSTATE	    (-82)   /* filters found something wanted */
#define TRACE_MSGNOTFOUND   (-86)   /* trace message was not found in the packet */
#define	TRACE_DIRECTION	    (-90)   /* message/packet direction mismatch */
#define TRACE_LOOP	    (-94)   /* bug in some structure looping the agent forever */
#define TRACE_FETCHERROR    (-95)   /* could not connect to host which has a PTSL file */
#endif

/* packet decoding specific errors */
#define ERROR_LINKLAYER	    (-100)  /* unrecognized link layer protocol */
#define ERROR_NETWORKLAYER  (-101)  /* unrecognized network layer protocol */
#define ERROR_TRANSPLAYER   (-102)  /* unrecognized transport layer protocol */

#define BUG		    (-125)  /* due to error condition, probably a bug */
#define ERROR_REALLYBAD	    (-126)  /* when things went *really* wrong */
#define ERROR_NEEDCODING    (-127)  /* function is not implemented */

