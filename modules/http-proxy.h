/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* http-proxy.h 

   Copyright (C) 2001 Eazel, Inc.

   The Mate Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Mate Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Mate Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
   Boston, MA 02110-1301, USA.

   Authors: 
		 See http-proxy.c
*/

#ifndef HTTP_PROXY_H
#define HTTP_RROXY_H


typedef struct {
	char *host;
	guint port;
	
	char *username;
	char *password;
	
} HttpProxyInfo;


gboolean              proxy_for_uri      (MateVFSToplevelURI * toplevel_uri,
					  HttpProxyInfo *proxy_info);

void                  proxy_init         (void);
void                  proxy_shutdown     (void);

#endif
