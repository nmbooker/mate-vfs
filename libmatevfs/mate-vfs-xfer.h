/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */

/* mate-vfs-xfer.h - File transfers in the MATE Virtual File System.

   Copyright (C) 1999 Free Software Foundation

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

   Author: Ettore Perazzoli <ettore@comm2000.it> */

#ifndef MATE_VFS_XFER_H
#define MATE_VFS_XFER_H

#include <libmatevfs/mate-vfs-file-info.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * FIXME bugzilla.eazel.com 1205:
 * Split these up into xfer options and xfer actions
 */


/**
 * MateVFSXferOptions:
 * @MATE_VFS_XFER_DEFAULT: Default behavior, which is to do a straight one to one copy.
 * @MATE_VFS_XFER_FOLLOW_LINKS: Follow symbolic links when copying or moving, i.e.
 * 				 the target of symbolic links are copied
 * 				 rather than the symbolic links themselves.
 * 				 Note that this just refers to top-level items.
 * 				 If you also want to follow symbolic links inside
 * 				 directories you operate on, you also have to specify
 * 				 #MATE_VFS_XFER_FOLLOW_LINKS_RECURSIVE.
 * @MATE_VFS_XFER_RECURSIVE: Recursively copy source directories to the target.
 * 			      Equivalent to the cp -r option in GNU cp.
 * @MATE_VFS_XFER_SAMEFS: When copying recursively, this only picks up items on the same file
 * 			   system the same filesystem as their parent directory.
 * @MATE_VFS_XFER_DELETE_ITEMS: This is equivalent to an rmdir() for source directories,
 * 				 and an unlink() operation for all source files.
 * 				 Requires %NULL target URIs.
 * @MATE_VFS_XFER_EMPTY_DIRECTORIES: Remove the whole contents of the passed-in source
 * 				      directories. Requires %NULL target URIs.
 * @MATE_VFS_XFER_NEW_UNIQUE_DIRECTORY: This will create a directory if it doesn't exist
 * 					 in the destination area (i.e. mkdir ()).
 * @MATE_VFS_XFER_REMOVESOURCE: This makes a copy operation equivalent to a mv, i.e. the
 * 				 files will be moved rather than copied. If applicable, this
 * 				 will use rename(), otherwise (i.e. across file systems),
 * 				 it will fall back to a copy operation followed by a source
 * 				 file deletion.
 * @MATE_VFS_XFER_USE_UNIQUE_NAMES: When this option is present, and a name collisions on
 * 				     the target occurs, the progress callback will be asked
 * 				     for a new name, until the newly provided name doesn't
 * 				     conflict or the request callback transfer cancellation.
 * @MATE_VFS_XFER_LINK_ITEMS: Executes a symlink operation for each of the source/target URI pairs,
 * 			       i.e. similar to GNU ln -s source target.
 * 			       NB: The symlink target has to be specified as source URI,
 * 			       	   and the symlink itself as target URI.
 * @MATE_VFS_XFER_FOLLOW_LINKS_RECURSIVE: This means that when doing a copy operation, symbolic
 * 					   links in subdirectories are dereferenced. This is
 * 					   typically used together with #MATE_VFS_XFER_FOLLOW_LINKS_RECURSIVE.
 * @MATE_VFS_XFER_TARGET_DEFAULT_PERMS: This means that the target file will not have the same
 * 					 permissions as the source file, but will instead have
 * 					 the default permissions of the destination location.
 * 					 This is useful when copying from read-only locations (CDs).
 * @MATE_VFS_XFER_UNUSED_1: Unused.
 * @MATE_VFS_XFER_UNUSED_2: Unused.
 *
 * These options control the way mate_vfs_xfer_uri(), mate_vfs_xfer_uri_list(),
 * mate_vfs_xfer_delete_list() and mate_vfs_async_xfer() work.
 *
 * At a first glance the #MateVFSXferOptions semantics are not very intuitive.
 *
 * There are two types of #MateVFSXferOptions: Those that define an operation,
 * i.e. describe what to do, and those that influence how to execute the
 * operation.
 *
 * <table frame="none">
 *  <title>Operation Selection</title>
 *  <tgroup cols="3" align="left">
 *   <?dbhtml cellpadding="10" ?>
 *   <colspec colwidth="1*"/>
 *   <colspec colwidth="1*"/>
 *   <colspec colwidth="1*"/>
 *   <colspec colwidth="1*"/>
 *   <thead>
 *    <row>
 *     <entry>#MateVFSXferOptions entry</entry>
 *     <entry>Operation</entry>
 *     <entry>UNIX equivalent</entry>
 *     <entry>Comments</entry>
 *    </row>
 *   </thead>
 *   <tbody>
 *    <row>
 *     <entry>#MATE_VFS_XFER_DEFAULT</entry>
 *     <entry>Copy</entry>
 *     <entry><literal>cp</literal></entry>
 *    </row>
 *    <row>
 *     <entry>#MATE_VFS_XFER_REMOVESOURCE</entry>
 *     <entry>Move</entry>
 *     <entry><literal>mv</literal></entry>
 *    </row>
 *    <row>
 *     <entry>#MATE_VFS_XFER_LINK_ITEMS</entry>
 *     <entry>Link</entry>
 *     <entry><literal>ln -s</literal></entry>
 *    </row>
 *    <row>
 *     <entry>#MATE_VFS_XFER_NEW_UNIQUE_DIRECTORY</entry>
 *     <entry>Make Unique Directory</entry>
 *     <entry><literal>mkdir</literal></entry>
 *     <entry>implies #MATE_VFS_XFER_USE_UNIQUE_NAMES</entry>
 *    </row>
 *    <row>
 *     <entry>#MATE_VFS_XFER_DELETE_ITEMS</entry>
 *     <entry>Remove</entry>
 *     <entry><literal>rm -r</literal></entry>
 *    </row>
 *    <row>
 *     <entry>#MATE_VFS_XFER_EMPTY_DIRECTORIES</entry>
 *     <entry>Remove Directory Contents</entry>
 *     <entry>foreach file: <literal>( cd file && rm -rf * )</literal></entry>
 *     <entry>used to empty trash</entry>
 *    </row>
 *   </tbody>
 *  </tgroup>
 * </table>
 *
 * <note>
 *  <para>
 *    Because #MATE_VFS_XFER_DEFAULT maps to %0, it will always be present.
 *    Thus, not explicitly specifying any operation at all, or just specifying
 *    #MATE_VFS_XFER_DEFAULT will both execute a copy.
 *  </para>
 *  <para>
 *    If an operation other than #MATE_VFS_XFER_DEFAULT is
 *    specified, it will override the copy operation, but you may only specify
 *    <emphasis>one</emphasis> of the other operations at a time.
 *  </para>
 *  <para>
 *    This unintuitive operation selection unfortunately poses an API weakness
 *    and an obstacle in client development, and will be modified in a later
 *    revision of this API.
 *  </para>
 * </note>
 */
typedef enum {
	MATE_VFS_XFER_DEFAULT = 0,
	MATE_VFS_XFER_UNUSED_1 = 1 << 0,
	MATE_VFS_XFER_FOLLOW_LINKS = 1 << 1,
	MATE_VFS_XFER_UNUSED_2 = 1 << 2,
	MATE_VFS_XFER_RECURSIVE = 1 << 3,
	MATE_VFS_XFER_SAMEFS = 1 << 4,
	MATE_VFS_XFER_DELETE_ITEMS = 1 << 5,
	MATE_VFS_XFER_EMPTY_DIRECTORIES = 1 << 6,
	MATE_VFS_XFER_NEW_UNIQUE_DIRECTORY = 1 << 7,
	MATE_VFS_XFER_REMOVESOURCE = 1 << 8,
	MATE_VFS_XFER_USE_UNIQUE_NAMES = 1 << 9,
	MATE_VFS_XFER_LINK_ITEMS = 1 << 10,
	MATE_VFS_XFER_FOLLOW_LINKS_RECURSIVE = 1 << 11,
	MATE_VFS_XFER_TARGET_DEFAULT_PERMS = 1 << 12
} MateVFSXferOptions;

/**
 * MateVFSXferProgressStatus:
 * @MATE_VFS_XFER_PROGRESS_STATUS_OK: The file transfer is progressing normally.
 * @MATE_VFS_XFER_PROGRESS_STATUS_VFSERROR: A VFS error was detected.
 * @MATE_VFS_XFER_PROGRESS_STATUS_OVERWRITE: The current target file specified by the
 * 					      #MateVFSXferProgressInfo's %target_name
 * 					      field already exists.
 * @MATE_VFS_XFER_PROGRESS_STATUS_DUPLICATE: The current target file specified by the
 * 					      #MateVFSXferProgressInfo's %target_name
 * 					      field already exists, and the progress
 * 					      callback is asked to supply a new unique name.
 *
 * The difference between #MATE_VFS_XFER_PROGRESS_STATUS_OVERWRITE and
 * #MATE_VFS_XFER_PROGRESS_STATUS_DUPLICATE is that they will be issued
 * at different occassions, and that the return value will be interpreted
 * differently. For details, see #MateVFSXferProgressCallback.
 **/
typedef enum {
	MATE_VFS_XFER_PROGRESS_STATUS_OK = 0,
	MATE_VFS_XFER_PROGRESS_STATUS_VFSERROR = 1,
	MATE_VFS_XFER_PROGRESS_STATUS_OVERWRITE = 2,
	MATE_VFS_XFER_PROGRESS_STATUS_DUPLICATE = 3
} MateVFSXferProgressStatus;

/**
 * MateVFSXferOverwriteMode:
 * @MATE_VFS_XFER_OVERWRITE_MODE_ABORT: Abort the transfer when a target file already exists,
 * 					 returning the error #MATE_VFS_ERROR_FILEEXISTS.
 * @MATE_VFS_XFER_OVERWRITE_MODE_QUERY: Query the progress callback with the
 * 					 #MateVFSXferProgressInfo's status field
 * 					 set to #MATE_VFS_XFER_PROGRESS_STATUS_VFSERROR when
 * 					 a target file already exists.
 * @MATE_VFS_XFER_OVERWRITE_MODE_REPLACE: Replace existing target files silently.
 * 					   Don't worry be happy.
 * @MATE_VFS_XFER_OVERWRITE_MODE_SKIP: Skip source files when its target already exists.
 *
 * This is passed to mate_vfs_xfer_uri(), mate_vfs_xfer_uri_list(),
 * mate_vfs_xfer_delete_list() and mate_vfs_async_xfer() and specifies
 * what action should be taken when a target file already exists.
 **/
typedef enum {
	MATE_VFS_XFER_OVERWRITE_MODE_ABORT = 0,
	MATE_VFS_XFER_OVERWRITE_MODE_QUERY = 1,
	MATE_VFS_XFER_OVERWRITE_MODE_REPLACE = 2,
	MATE_VFS_XFER_OVERWRITE_MODE_SKIP = 3
} MateVFSXferOverwriteMode;

/**
 * MateVFSXferOverwriteAction:
 * @MATE_VFS_XFER_OVERWRITE_ACTION_ABORT: abort the transfer
 * @MATE_VFS_XFER_OVERWRITE_ACTION_REPLACE: replace the existing file
 * @MATE_VFS_XFER_OVERWRITE_ACTION_REPLACE_ALL: replace the existing file, and all future files
 * without prompting the callback.
 * @MATE_VFS_XFER_OVERWRITE_ACTION_SKIP: don't copy over the existing file
 * @MATE_VFS_XFER_OVERWRITE_ACTION_SKIP_ALL: don't copy over the existing file, and all future
 * files without prompting the callback.
 *
 * This defines the actions to perform before a file is being overwritten
 * (i.e., these are the answers that can be given to a replace query).
 **/
typedef enum {
	MATE_VFS_XFER_OVERWRITE_ACTION_ABORT = 0,
	MATE_VFS_XFER_OVERWRITE_ACTION_REPLACE = 1,
	MATE_VFS_XFER_OVERWRITE_ACTION_REPLACE_ALL = 2,
	MATE_VFS_XFER_OVERWRITE_ACTION_SKIP = 3,
	MATE_VFS_XFER_OVERWRITE_ACTION_SKIP_ALL = 4
} MateVFSXferOverwriteAction;

/**
 * MateVFSXferErrorMode:
 * @MATE_VFS_XFER_ERROR_MODE_ABORT: abort the transfer when an error occurs
 * @MATE_VFS_XFER_ERROR_MODE_QUERY: query the progress callback with the
 * 				     #MateVFSXferProgressInfo's status field
 * 				     set to #MATE_VFS_XFER_PROGRESS_STATUS_VFSERROR.
 *
 * This is passed to mate_vfs_xfer_uri(), mate_vfs_xfer_uri_list(),
 * mate_vfs_xfer_delete_list() and mate_vfs_async_xfer() and specifies
 * what action should be taken when transfer errors are detected.
 *
 * The progress callback is either a #MateVFSXferProgressCallback for synchronous
 * Xfer operations, or a #MateVFSAsyncXferProgressCallback for asynchronous operations.
 **/
typedef enum {
	MATE_VFS_XFER_ERROR_MODE_ABORT = 0,
	MATE_VFS_XFER_ERROR_MODE_QUERY = 1
} MateVFSXferErrorMode;

/**
 * MateVFSXferErrorAction:
 * @MATE_VFS_XFER_ERROR_ACTION_ABORT: interrupt Xfer and return %MATE_VFS_ERROR_INTERRUPTED.
 * @MATE_VFS_XFER_ERROR_ACTION_RETRY: retry the failed operation.
 * @MATE_VFS_XFER_ERROR_ACTION_SKIP: skip the failed operation, and continue Xfer normally.
 *
 * This defines the possible actions to be performed after a VFS error has occurred, i.e.
 * when a MateVFS file operation issued during the transfer returned a result that is not
 * equal to #MATE_VFS_OK.
 *
 * It is returned by the progress callback which is either a #MateVFSXferProgressCallback
 * for synchronous Xfer operations, or a #MateVFSAsyncXferProgressCallback for asynchronous
 * operations.
 **/
typedef enum {
	MATE_VFS_XFER_ERROR_ACTION_ABORT = 0,
	MATE_VFS_XFER_ERROR_ACTION_RETRY = 1,
	MATE_VFS_XFER_ERROR_ACTION_SKIP = 2
} MateVFSXferErrorAction;

/**
 * MateVFSXferPhase:
 * @MATE_VFS_XFER_PHASE_INITIAL: initial phase.
 * @MATE_VFS_XFER_CHECKING_DESTINATION: destination is checked for being able to handle copy/move.
 * @MATE_VFS_XFER_PHASE_COLLECTING: source file list is collected.
 * @MATE_VFS_XFER_PHASE_READYTOGO: source file list has been collected (*).
 * @MATE_VFS_XFER_PHASE_OPENSOURCE: source file is opened for reading.
 * @MATE_VFS_XFER_PHASE_OPENTARGET: target file, directory or symlink is created, or opened for copying.
 * @MATE_VFS_XFER_PHASE_COPYING: data is copied from source file to target file (*).
 * @MATE_VFS_XFER_PHASE_MOVING: source file is moved to target (M).
 * @MATE_VFS_XFER_PHASE_READSOURCE: data is read from a source file, when copying.
 * @MATE_VFS_XFER_PHASE_WRITETARGET: data is written to a target file, when copying.
 * @MATE_VFS_XFER_PHASE_CLOSESOURCE: source file is closed, when copying
 * @MATE_VFS_XFER_PHASE_CLOSETARGET: target file is closed, when copying.
 * @MATE_VFS_XFER_PHASE_DELETESOURCE: source file is deleted.
 * @MATE_VFS_XFER_PHASE_SETATTRIBUTES: target file attributes are set.
 * @MATE_VFS_XFER_PHASE_FILECOMPLETED: one file was completed, ready for next file.
 * @MATE_VFS_XFER_PHASE_CLEANUP: cleanup after moving (i.e. source files deletion).
 * @MATE_VFS_XFER_PHASE_COMPLETED: operation finished (*).
 *
 * Specifies the current phase of an Xfer operation that was
 * initiated using mate_vfs_xfer_uri(), mate_vfs_xfer_uri_list(),
 * mate_vfs_xfer_delete_list() or mate_vfs_async_xfer().
 *
 * Whenever the Xfer phase is in a phase that is highlighted with a
 * (*), the #MateVFSXferProgressCallback respectively
 * #MateVFSAsyncXferProgressCallback is never invoked with a
 * #MateVFSXferProgressStatus other than %MATE_VFS_XFER_PROGRESS_STATUS_OK.
 *
 **/
typedef enum {
	MATE_VFS_XFER_PHASE_INITIAL,
	MATE_VFS_XFER_CHECKING_DESTINATION,
	MATE_VFS_XFER_PHASE_COLLECTING,
	MATE_VFS_XFER_PHASE_READYTOGO,
	MATE_VFS_XFER_PHASE_OPENSOURCE,
	MATE_VFS_XFER_PHASE_OPENTARGET,
	MATE_VFS_XFER_PHASE_COPYING,
	MATE_VFS_XFER_PHASE_MOVING,
	MATE_VFS_XFER_PHASE_READSOURCE,
	MATE_VFS_XFER_PHASE_WRITETARGET,
	MATE_VFS_XFER_PHASE_CLOSESOURCE,
	MATE_VFS_XFER_PHASE_CLOSETARGET,
	MATE_VFS_XFER_PHASE_DELETESOURCE,
	MATE_VFS_XFER_PHASE_SETATTRIBUTES,
	MATE_VFS_XFER_PHASE_FILECOMPLETED,
	MATE_VFS_XFER_PHASE_CLEANUP,
	MATE_VFS_XFER_PHASE_COMPLETED,
	MATE_VFS_XFER_NUM_PHASES
} MateVFSXferPhase;

/**
 * MateVFSXferProgressInfo:
 * @status: A #MateVFSXferProgressStatus describing the current status.
 * @vfs_status: A #MateVFSResult describing the current VFS status.
 * @phase: A #MateVFSXferPhase describing the current transfer phase.
 * @source_name: The Currently processed source URI.
 * @target_name: The Currently processed target URI.
 * @file_index: The index of the currently processed file.
 * @files_total: The total number of processed files.
 * @file_size: The size of the currently processed file in bytes.
 * @bytes_total: The total size of all files to transfer in bytes.
 * @bytes_copied: The number of bytes that has been transferred
 * 		  from the current file.
 * @total_bytes_copied: The total number of bytes that has been transferred.
 * @duplicate_name: The name specifying a duplicate filename.
 * 		    It acts as pointer to both input and output
 * 		    data. It is only valid input data if @status is
 * 		    MATE_VFS_XFER_PROGRESS_STATUS_DUPLICATE,
 * 		    in which case @duplicate_count and @duplicate_name
 * 		    should be used by the #MateVFSXferProgressCallback
 * 		    to pick a new unique target name.
 * 		    If the callback wants to retry with a new unique name
 * 		    it is supposed to free the old @duplicate_name
 * 		    set it to a valid string describing the new file name.
 * @duplicate_count: The number of conflicts that ocurred when the
 * 		     current @duplicate_name was set.
 * @top_level_item: This flag signals that the currently
 * 		    processed file is a top level item.
 * 		    If it is %TRUE, one of the files passed to
 * 		    mate_vfs_xfer_uri(), mate_vfs_xfer_uri_list(),
 * 		    mate_vfs_xfer_delete_list() or mate_vfs_async_xfer()
 * 		    is currently processed.
 * 		    If it is %FALSE, a file or directory that is inside
 * 		    a directory specified by the passed in source list
 * 		    is currently processed.
 *
 * Provides progress information for the transfer operation.
 * This is especially useful for interactive programs.
 **/
typedef struct {
	/*< public > */
	MateVFSXferProgressStatus status;

	MateVFSResult vfs_status;

	MateVFSXferPhase phase;

	/* Source URI. FIXME bugzilla.eazel.com 1206: change name? */
	gchar *source_name;

	/* Destination URI. FIXME bugzilla.eazel.com 1206: change name? */
	gchar *target_name;

	gulong file_index;

	gulong files_total;

	MateVFSFileSize bytes_total;

	MateVFSFileSize file_size;

	MateVFSFileSize bytes_copied;

	MateVFSFileSize total_bytes_copied;

	gchar *duplicate_name;

	int duplicate_count;

	gboolean top_level_item;

	/* Reserved for future expansions to MateVFSXferProgressInfo
	 * without having to break ABI compatibility */
	/*< private >*/
	void *reserved1;
	void *reserved2;
} MateVFSXferProgressInfo;

/**
 * MateVFSXferProgressCallback:
 * @info: The #MateVFSXferProgressInfo associated with this transfer operation.
 * @user_data: The user data passed to mate_vfs_xfer_uri(), mate_vfs_xfer_uri_list(),
 * 	       mate_vfs_xfer_delete_list() or mate_vfs_async_xfer().
 *
 * This is the prototype for functions called during a transfer operation to
 * report progress.
 *
 * The interpretation of the return value of the callback depends on the
 * MateVFSXferProgressStaus %status field of MateVFSXferProgressInfo,
 * some status/return value combinations require modification of
 * particular @info fields.
 *
 * <table frame="none">
 *  <title>Status/Return Value Overview</title>
 *  <tgroup cols="3" align="left">
 *   <?dbhtml cellpadding="10" ?>
 *   <colspec colwidth="1*"/>
 *   <colspec colwidth="1*"/>
 *   <colspec colwidth="1*"/>
 *   <colspec colwidth="1*"/>
 *   <thead>
 *    <row>
 *     <entry>#MateVFSXferProgressStatus status</entry>
 *     <entry>Status</entry>
 *     <entry>Only If</entry>
 *     <entry>Return Value Interpretation</entry>
 *    </row>
 *   </thead>
 *   <tbody>
 *    <row>
 *     <entry>#MATE_VFS_XFER_PROGRESS_STATUS_OK</entry>
 *     <entry>OK</entry>
 *     <entry></entry>
 *     <entry>%0: abort, otherwise continue</entry>
 *    </row>
 *    <row>
 *     <entry>#MATE_VFS_XFER_PROGRESS_STATUS_VFSERROR</entry>
 *     <entry>VFS Error Ocurred</entry>
 *     <entry>#MateVFSXferErrorMode is #MATE_VFS_XFER_ERROR_MODE_QUERY</entry>
 *     <entry>MateVFSXferErrorAction</entry>
 *    </row>
 *    <row>
 *     <entry>#MATE_VFS_XFER_PROGRESS_STATUS_OVERWRITE</entry>
 *     <entry>Conflict Ocurred, Overwrite?</entry>
 *     <entry>
 *            #MateVFSXferOverwriteMode is #MATE_VFS_XFER_OVERWRITE_MODE_QUERY,
 *            #MateVFSXferOptions does not have #MATE_VFS_XFER_USE_UNIQUE_NAMES.
 *     </entry>
 *     <entry>MateVFSXferOverwriteAction</entry>
 *    </row>
 *    <row>
 *     <entry>#MATE_VFS_XFER_PROGRESS_STATUS_DUPLICATE</entry>
 *     <entry>Conflict Ocurred, New Target Name?</entry>
 *     <entry>#MateVFSXferOptions does have #MATE_VFS_XFER_USE_UNIQUE_NAMES.</entry>
 *     <entry>%0: abort, otherwise retry with new %duplicate_name in @info (free the old one!).</entry>
 *    </row>
 *   </tbody>
 *  </tgroup>
 * </table>
 *
 * <note>
 * Each #MateVFSXferProgressStatus provides one value signalling abortion that maps to %0.
 * Therefore, returning %0 will always abort the Xfer. On abortion, if the @info's %vfs_status
 * is #MATE_VFS_OK, the Xfer operation result will be set to #MATE_VFS_ERROR_INTERRUPTED,
 * otherwise the operation result will be set to %vfs_status to distinguish completely
 * user-driven aborts from those involving a problem during the Xfer.
 * </note>
 *
 * Returns: Whether the process should be aborted, or whether a special action should be taken.
 **/
typedef gint (* MateVFSXferProgressCallback) 	(MateVFSXferProgressInfo *info,
						 gpointer user_data);

/**
 * MateVFSProgressCallbackState:
 *
 * Private structure encapsulating the entire state information of the xfer process.
 **/
typedef struct _MateVFSProgressCallbackState {
	/*< private >*/

	/* xfer state */
	MateVFSXferProgressInfo *progress_info;

	/* Callback called for every xfer operation. For async calls called
	   in async xfer context. */
	MateVFSXferProgressCallback sync_callback;

	/* Callback called periodically every few hundred miliseconds
	   and whenever user interaction is needed. For async calls
	   called in the context of the async call caller. */
	MateVFSXferProgressCallback update_callback;

	/* User data passed to sync_callback. */
	gpointer user_data;

	/* Async job state passed to the update callback. */
	gpointer async_job_data;

	/* When will update_callback be called next. */
	gint64 next_update_callback_time;

	/* When will update_callback be called next. */
	gint64 next_text_update_callback_time;

	/* Period at which the update_callback will be called. */
	gint64 update_callback_period;


	/* Reserved for future expansions to MateVFSProgressCallbackState
	 * without having to break ABI compatibility */
	void *reserved1;
	void *reserved2;

} MateVFSProgressCallbackState;

MateVFSResult mate_vfs_xfer_uri_list    (const GList                  *source_uri_list,
					   const GList                  *target_uri_list,
					   MateVFSXferOptions           xfer_options,
					   MateVFSXferErrorMode         error_mode,
					   MateVFSXferOverwriteMode     overwrite_mode,
					   MateVFSXferProgressCallback  progress_callback,
					   gpointer                      data);
MateVFSResult mate_vfs_xfer_uri         (const MateVFSURI            *source_uri,
					   const MateVFSURI            *target_uri,
					   MateVFSXferOptions           xfer_options,
					   MateVFSXferErrorMode         error_mode,
					   MateVFSXferOverwriteMode     overwrite_mode,
					   MateVFSXferProgressCallback  progress_callback,
					   gpointer                      data);
MateVFSResult mate_vfs_xfer_delete_list (const GList                  *source_uri_list,
					   MateVFSXferErrorMode         error_mode,
					   MateVFSXferOptions           xfer_options,
					   MateVFSXferProgressCallback  progress_callback,
					   gpointer                      data);

#ifdef __cplusplus
}
#endif

#endif /* MATE_VFS_XFER_H */
