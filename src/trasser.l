/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2004 Diego Wentz Antunes
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
#include "trasserlib.h"
#include "y.tab.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifndef DEBUG
#define DEBUG 0
#endif

int state = 0;
int s = 0;
%}
ID		[a-zA-Z][a-zA-Z0-9" ""_"]*
UINT		[0-9]+
A		[A-Za-z]
DIGIT		[0-9]
ALPHANUM	[a-zA-Z0-9]
UL		"_"
WILDCARD	"*"
DP		":"
SL		"/"
DT		"."
VIRGULA		","
CRLF		\r\n
CR		\x0D
NL		\X0A
ACENTOS1	["á" "à" "ã" "â" "ä" "é" "è" "ê" "ë" "í" "ì" "î" "ï" "ó" "ò" "ô" "õ" "ö" "ú" "ù" "û" "ü" "ç"]*
ACENTOS2	["Á" "À" "Ä" "Â" "Ã" "É" "È" "Ê" "Ë" "Í" "Ì" "Î" "Ï" "Ó" "Ò" "Ô" "Õ" "Ö" "Ú" "Ù" "Ü" "Û" "Ç"]*
CHAR		([a-zA-Z0-9]*[" ""_""\""!""@""#""$""%""&""*""("")""+""-""?""<"">"","".""/""[""\]""{""}""|"]*)*
CHARSP		["a-z""A-Z""0-9""_"\"!""@""#""$""%""&""*""("")""+""-"":""?""<"">"",""."/"[""\]""{""}""|"]*
DDIGIT		{DIGIT}{DIGIT}
TTIME		{DDIGIT}":"{DDIGIT}":"{DDIGIT}
DDATE		{DDIGIT}" "{MONTH}" "{DDIGIT}{DDIGIT}
PROTENC		[a-zA-Z]{ALPHANUM}*("/"[a-zA-Z]{ALPHANUM}*)*
DQID		"\""[a-zA-Z][a-zA-Z0-9" ""_"]*"\""
SDQID		"\""[a-zA-Z][a-zA-Z0-9" ""_"]*"\""
DDQID		"\""[a-zA-Z][a-zA-Z0-9" ""_"]*"\""(",""\""[a-zA-Z][a-zA-Z0-9" ""_"]*"\"")*
KEY		{ID}*(","{ID}*)*
WID		{CHARSP}+("|"[0-9A-F]"|"{CHARSP}+)*
VERB		["/""a-z""A-Z"]["/""a-z""A-Z""0-9"_"","]+
INFT		{CHAR}
INFTT		([-a-zA-Z0-9" ""_"",""-"])*(","[-a-zA-Z0-9" ""_"","])*
VERN		{DIGIT}+"."{DIGIT}+
LAST		(Last" "Update:)
MONTH		([jJ]an|[fF]eb|[mM]ar|[aA]pr|[mM]ay|[jJ]un|[jJ]ul|[aA]ug|[sS]ep|[oO]ct|[nN]ov|[dD]ez)
WKDAY		([Mm]on|[Tt]ue|[Ww]ed|[Tt]hu|[Ff]ri|[Ss]at|[Ss]un)
DTIME		{WKDAY}" "{MONTH}" "{DDIGIT}" "{TTIME}" EST "{DDIGIT}{DDIGIT}
BHAVE		(NoGrabPort|DisableGenericRmon2)
OP		(">"|">="|"<"|"<="|"="|"!="|" ")
%s VER INF UI KWORD MONTHS WKDAYS TY PROT DI DDI M
%s COUNT EG WWID IF INFT UII DDTTIME BE VERBI IDENT STATEDQ
%%
[ \t\n]*	    { }
^"//"(.|\n\t)*      { printf("Comentario!!\n"); }

Trace	{
    BEGIN DI;
    if (DEBUG) printf("L-> Trace.\n");
	strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return STRACE;
}

EndTrace    {
    if (DEBUG)
	printf("L-> Endtrace.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return ENDSTRACE;
}

Version:    {
    BEGIN VER;
    if (DEBUG)
	printf("L-> Version.\n");
    memset(yylval.stval, 0, sizeof(yylval.stval));
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return VERSION;
}

Description:	{
    BEGIN INF;
    if (DEBUG)
	printf("L-> Description.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return DESCRIPTION;
}

Key:	{
    BEGIN KWORD;
    if (DEBUG)
	printf("L-> Key.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return KEY;
}

Port:	{
    BEGIN UI;
    if (DEBUG)
	printf("L-> Port.\n");
    yylval.iValue = atoi(yytext);
    yylval.stval[strlen(yytext)] = '\0';
    return PORT;
}

Owner:	{
    BEGIN INF;
    if (DEBUG)
	printf("L-> Owner.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return OWNER;
}

{LAST}	{
    BEGIN DDTTIME;
    if (DEBUG)
	printf("L-> LastUpdate.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return LAST_UPDATE;
}

Reference:  {
    BEGIN INFT;
    if (DEBUG)
	printf("L-> Reference.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return REFERENCE;
}

Encapsulation:	{
    BEGIN INF;
    if (DEBUG)
	printf("L-> Encapsulation.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return (ENCAP);
}

{BHAVE}	{
    if (DEBUG)
	printf("L-> Behavior.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return BEHAVIOR;
}

MessagesSection	{
    BEGIN M;
    if (DEBUG)
	printf("L-> MsgsSec.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return MESSAGES_SECTION;
}

EndMessagesSection {
    if (DEBUG)
	printf("L-> EMsgSection.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return END_MESSAGES_SECTION;
}

<M>Message {
    BEGIN DI;
    if (DEBUG)
	printf("L-> Message.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return MESSAGE;
}

MessageType: {
    BEGIN TY;
    if (DEBUG) printf("L-> MessageType.\n");
	strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return MESSAGE_TYPE;
}

MessageTimeout: {
    BEGIN UI;
    if (DEBUG) printf("L-> MsgsTimeOut.\n");
	strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return MESSAGE_TIMEOUT;
}

EndMessage  {
    BEGIN M;
    if (DEBUG)
	printf("L-> EndMessage.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return END_MESSAGE;
}

GroupsSection {
    if (DEBUG)
	printf("L-> GroupsSection.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return GROUPS_SECTION;
}

Group {
    BEGIN DI;
    if (DEBUG)
	printf("L-> Group.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return GROUP;
}

Messages:   {
    BEGIN DDI;
    if (DEBUG)
	printf("L-> Messages.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return MESSAGES;
}

EndGroupsSection {
    if (DEBUG)
	printf("L-> EndGroupsSection.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return END_GROUPS_SECTION;
}

<EG>EndGroup {
    if (DEBUG)
	printf("L-> EndGroup.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return END_GROUP;
}

StatesSection {
    if (DEBUG)
	printf("L-> StatesSection.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return STATES_SECTION;
}

FinalState  {
    s = 1;
    BEGIN IDENT;
    if (DEBUG)
	printf("L-> FinalState.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return FINAL_STATE;
}

State	{
    s = 2;
    BEGIN IDENT;
    if (DEBUG)
	printf("L-> State.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return STATE;
}

GotoState   {
    s = 3;
    BEGIN IDENT;
    if (DEBUG)
	printf("L-> GotoState.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return GOTO_STATE;
}

EndState    {
    BEGIN INITIAL;
    if (DEBUG)
	printf("L-> EndState.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return END_STATE;
}

EndStatesSection    {
    if (DEBUG)
	printf("L-> EndStatesSection.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return END_STATES_SECTION;
}

FieldCounter	{
    BEGIN PROT;
    state = 1;
    if (DEBUG)
	printf("L-> FieldC.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return FIELD_COUNTER;
}

BitCounter  {
    BEGIN PROT;
    state = 2;
    if (DEBUG)
	printf("L-> BitC.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return BIT_COUNTER;
}

NoOffSet    {
    BEGIN PROT;
    state = 3;
    if (DEBUG)
	printf("L-> NoOffSet.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return NOOFFSET;
}

FieldCounter_LV	{
    BEGIN PROT;
    state = 1;
    if (DEBUG)
	printf("L-> FLV.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return FLV;
}

BitCounter_LV	{
    BEGIN PROT;
    state = 2;
    if (DEBUG)
	printf("L-> BLV.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return BLV;
}

FieldCounter_TV	{
    BEGIN PROT;
    state = 1;
    if (DEBUG)
	printf("L-> FTV.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return FTV;
}

BitCounter_TV	{
    BEGIN PROT;
    state = 2;
    if (DEBUG)
	printf("L-> BTV.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return BTV;
}

<DI>{DQID} {
    BEGIN INITIAL;
    state = 0;
    if (DEBUG)
	printf("L-> DQID.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return DQID;
}

<PROT>{PROTENC}	{
    if (state == 1)
	BEGIN UI;
    else if (state == 2)
	BEGIN UI;
    else if (state == 3)
	BEGIN VERBI;
    if (DEBUG)
	printf("L-> ProtEnc.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return PROT_ENC;
}

<VER>{VERN} {
    if (DEBUG)
	printf("L-> Versionumber.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return VERSION_NUMBER;
}

<INF>{INFT} {
    if (DEBUG)
	printf("L-> Informal Text.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return INFTEXT;
}

<INFT>{INFTT} {
    if (DEBUG)
	printf("L-> Informals Text.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return INFTEXTT;
}

<UI>{UINT}  {
    if (state == 1) {
	BEGIN WWID;
    } else if (state == 2) {
	BEGIN UII;
    } else if (state == 3) {
	BEGIN IF;
    } if (DEBUG) printf("L-> UnsignedInt.\n");
	strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return UINT;
}

<IDENT>{ID} {
    if (s == 1) {
	BEGIN INITIAL;
    } else if (s == 2) {
	BEGIN DI;
    } else if (s == 3) {
	BEGIN DI;
    } if (DEBUG)
	printf("L-> Identifier.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return ID;
}

<UII>{UINT} {
    BEGIN WWID;
    state = 0;
    if (DEBUG)
	printf("L-> UII.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return UINT;
}

{DIGIT} {
    if (DEBUG)
	printf("L-> Digit.\n");
    yylval.iValue = atoi(yytext);
    yylval.stval[strlen(yytext)] = '\0';
    return DIGIT;
}

<TY>client|server|any {
    if (DEBUG)
	printf("L-> MType.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return MTYPE;
}

<DDI>{DDQID} {
    BEGIN EG;
    if (DEBUG)
	printf("L-> DDQID.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return DDQID;
}

<WWID>{WID} {
    BEGIN IF;
    state = 0;
    if (DEBUG)
	printf("L-> WildCard.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return WID;
}

<DDTTIME>{DTIME} {
    if (DEBUG)
	printf("L-> Date Time.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return DTIME;
}

<IF>"\""{INFT}*"\"" {
    BEGIN INITIAL;
    if (DEBUG)
	printf("L-> DQ_Informal.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return DQ_INF;
}

<KWORD>{KEY} {
    if (DEBUG)
	printf("L-> Keyword.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return KEYWORD;
}

<VERBI>{VERB} {
    BEGIN IF;
    state = 0;
    if (DEBUG)
	printf("L-> Verb Identifier.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return VERB_IDENTIFIER;
}

{OP} {
    if (DEBUG)
	printf("L-> Operator.\n");
    strncpy(yylval.stval, yytext, strlen(yytext));
    yylval.stval[strlen(yytext)] = '\0';
    return OPERATOR;
}
.		return yytext[0];

%%

int yywrap(void)
{
    return 1;
}
