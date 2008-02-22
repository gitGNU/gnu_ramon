/*
 * Ramon - A RMON2 Network Monitoring Agent
 * Copyright (C) 2008  Ricardo Nabinger Sanchez
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
 *
 * $Id$
 */

#ifndef __LOG_H__
#define __LOG_H__

#define Debug(...) debug(__FILE__, __LINE__, __VA_ARGS__)
#define Fatal(...) fatal(__FILE__, __LINE__, __VA_ARGS__)

void debug(const char *, const int, const char *, ...);
void fatal(const char *, const int, const char *, ...);

#endif	/* __LOG_H__ */
