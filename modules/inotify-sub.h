/* inotify-helper.h - MATE VFS Monitor using inotify

   Copyright (C) 2006 John McCutchan

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

   Author: John McCutchan <john@johnmccutchan.com>
*/


#ifndef __INOTIFY_SUB_H
#define __INOTIFY_SUB_H

typedef struct {
        MateVFSMethodMonitorCancelFunc cancel_func;  /* Must be first */
	MateVFSURI *uri;
	MateVFSMonitorType type;
	char *pathname;
	char *dirname;
	char *filename;
	guint32 extra_flags;
	gboolean cancelled;
} ih_sub_t;

ih_sub_t	*ih_sub_new		(MateVFSURI *uri, MateVFSMonitorType);
void		 ih_sub_free 	 	(ih_sub_t *sub);

#endif /* __INOTIFY_SUB_H */
