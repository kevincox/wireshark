/* hostlist_table.h   2004 Ian Schorr
 * modified from endpoint_talkers_table   2003 Ronnie Sahlberg
 * Helper routines common to all host talkers taps.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __HOSTLIST_TABLE_H__
#define __HOSTLIST_TABLE_H__

#include <ui/conversation_ui.h>

/** @file
 *  Hostlist definitions.
 */

/** Conversation types */
/* Sort alphabetically by title */
typedef enum {
    CONV_TYPE_ETHERNET,
    CONV_TYPE_FIBRE_CHANNEL,
    CONV_TYPE_FDDI,
    CONV_TYPE_IPV4,
    CONV_TYPE_IPV6,
    CONV_TYPE_IPX,
    CONV_TYPE_JXTA,
    CONV_TYPE_NCP,
    CONV_TYPE_RSVP,
    CONV_TYPE_SCTP,
    CONV_TYPE_TCP,
    CONV_TYPE_TOKEN_RING,
    CONV_TYPE_UDP,
    CONV_TYPE_USB,
    CONV_TYPE_WLAN,
    N_CONV_TYPES
} conversation_type_e;


/** Hostlist information */
typedef struct _hostlist_talker_t {
	address myaddress;      /**< address */
	conversation_type_e   sat;            /**< address type */
	guint32 port_type;      /**< port_type (e.g. PT_TCP) */
	guint32 port;           /**< port */

	guint64 rx_frames;      /**< number of received packets */
	guint64 tx_frames;      /**< number of transmitted packets */
	guint64 rx_bytes;       /**< number of received bytes */
	guint64 tx_bytes;       /**< number of transmitted bytes */

        gboolean modified;      /**< new to redraw the row */
        GtkTreeIter iter;
        gboolean iter_valid;    /**< not a new row */

} hostlist_talker_t;

#define NUM_BUILTIN_COLS 8
#ifdef HAVE_GEOIP
# define NUM_GEOIP_COLS 13
#else
# define NUM_GEOIP_COLS 0
#endif
#define NUM_HOSTLIST_COLS (NUM_BUILTIN_COLS + NUM_GEOIP_COLS)

/** Hostlist widget */
typedef struct _hostlist_table {
	const char          *name;              /**< the name of the table */
	const char          *filter;            /**< the filter used */
	gboolean             use_dfilter;       /**< use display filter */
	GtkWidget           *win;               /**< GTK window */
	GtkWidget           *page_lb;           /**< page label */
	GtkWidget           *name_lb;           /**< name label */
	GtkWidget           *scrolled_window;   /**< the scrolled window */
	GtkTreeView         *table;             /**< the GTK table */
	const char          *default_titles[NUM_HOSTLIST_COLS]; /**< Column headers */
	GtkWidget           *menu;              /**< context menu */
	gboolean            has_ports;          /**< table has ports */
	guint32             num_hosts;          /**< number of hosts (0 or 1) */
	GArray              *hosts;             /**< array of host values */
	GHashTable          *hashtable;         /**< conversations hash table */
	gboolean 	    fixed_col;      	/**< if switched to fixed column */
	gboolean            resolve_names;      /**< resolve address names? */
	gboolean            geoip_visible;      /**< if geoip columns are visible */
} hostlist_table;

/** Register the hostlist table for the multiple hostlist window.
 *
 * @param hide_ports hide the port columns
 * @param table_name the table name to be displayed
 * @param tap_name the registered tap name
 * @param filter the optional filter name or NULL
 * @param packet_func the function to be called for each incoming packet
 */
extern void register_hostlist_table(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func);

/** Init the hostlist table for the single hostlist window.
 *
 * @param hide_ports hide the port columns
 * @param table_name the table name to be displayed
 * @param tap_name the registered tap name
 * @param filter the optional filter name or NULL
 * @param packet_func the function to be called for each incoming packet
 */
extern void init_hostlist_table(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func);

/** Callback for "Endpoints" statistics item.
 *
 * @param w unused
 * @param d unused
 */
extern void init_hostlist_notebook_cb(GtkWidget *w, gpointer d);

/** Add some data to the table.
 *
 * @param hl the table to add the data to
 * @param addr address
 * @param port port
 * @param sender TRUE, if this is a sender
 * @param num_frames number of packets
 * @param num_bytes number of bytes
 * @param sat address type
 * @param port_type the port type (e.g. PT_TCP)
 */
void add_hostlist_table_data(hostlist_table *hl, const address *addr,
                             guint32 port, gboolean sender, int num_frames, int num_bytes, conversation_type_e sat, int port_type);

#endif /* __HOSTLIST_TABLE_H__ */
