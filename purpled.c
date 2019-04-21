/*
 * purpleD
 *
 * A daemon program to provide a socket interface into libpurple.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 *
 */

#include "purple.h"

//#include <sys/mman.h>
//	#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
//#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
//#include <fcntl.h>

#include <pwd.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "defines.h"
//#include "config.h"

/**
 * The following eventloop functions are used in both pidgin and purple-text.
 * If your application uses glib mainloop, you can safely use this verbatim.
 */
#define PURPLE_GLIB_READ_COND  (G_IO_IN | G_IO_HUP | G_IO_ERR)
#define PURPLE_GLIB_WRITE_COND (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL)

typedef struct _PurpleGLibIOClosure {
	PurpleInputFunction function;
	guint result;
	gpointer data;
} PurpleGLibIOClosure;

static void purple_glib_io_destroy(gpointer data)
{
	g_free(data);
}

static gboolean purple_glib_io_invoke(GIOChannel *source,
				      GIOCondition condition, gpointer data)
{
	PurpleGLibIOClosure *closure = data;
	PurpleInputCondition purple_cond = 0;

	if (condition & PURPLE_GLIB_READ_COND)
		purple_cond |= PURPLE_INPUT_READ;
	if (condition & PURPLE_GLIB_WRITE_COND)
		purple_cond |= PURPLE_INPUT_WRITE;

	closure->function(closure->data, g_io_channel_unix_get_fd(source),
			  purple_cond);

	return TRUE;
}

static guint glib_input_add(gint fd, GIOCondition cond, gpointer function)
{
	GIOChannel *channel;

	channel = g_io_channel_unix_new(fd);
	g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, cond,
			    function, 0, purple_glib_io_destroy);
	g_io_channel_unref(channel);

	return 0;
}

static guint purple_glib_input_add(gint fd, PurpleInputCondition condition,
				   PurpleInputFunction function, gpointer data)
{
	PurpleGLibIOClosure *closure = g_new0(PurpleGLibIOClosure, 1);
	GIOChannel *channel;
	GIOCondition cond = 0;

	closure->function = function;
	closure->data = data;

	if (condition & PURPLE_INPUT_READ)
		cond |= PURPLE_GLIB_READ_COND;
	if (condition & PURPLE_INPUT_WRITE)
		cond |= PURPLE_GLIB_WRITE_COND;

	channel = g_io_channel_unix_new(fd);
	closure->result = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, cond,
					      purple_glib_io_invoke, closure,
					      purple_glib_io_destroy);
	g_io_channel_unref(channel);

	return closure->result;
}

static PurpleEventLoopUiOps glib_eventloops =
{
	g_timeout_add,
	g_source_remove,
	purple_glib_input_add,
	g_source_remove,
	NULL,
#if GLIB_CHECK_VERSION(2,14,0)
	g_timeout_add_seconds,
#else
	NULL,
#endif
	/* padding */
	NULL,
	NULL,
	NULL
};
/*** End of the eventloop functions. ***/

void client_command(client* ptr, char *mesg);
void purpld_proccess_client(client* ptr);
void purpld_client_send(client* ptr, const char *mesg);

int total_c = 0;
int listenfd;
GList *clients = NULL;
struct purpld_dirs purpld_dirs;

void purpld_inform_client(PurpleAccount *account, char *message) {
	GList *iter;
	for (iter = clients; iter; iter = iter->next) {
		client *cli = iter->data;
		// TODO: if account IN cli->accounts THEN
		purpld_client_send(cli, message);
		// ENDIF
	}
}

/*** Account uiops ***/
static void*
purpld_accounts_request_authorize(PurpleAccount *account,
				  const char *remote_user, const char *id,
				  const char *alias, const char *message,
				  gboolean on_list,
				  PurpleAccountRequestAuthorizationCb auth_cb,
				  PurpleAccountRequestAuthorizationCb deny_cb,
				  void *user_data)
{
	auth_cb(user_data);
	return NULL;
}

static PurpleAccountUiOps purpld_accounts_uiops =
{
	NULL, //notify_added
	NULL, //status changed
	NULL, //request_add,
	purpld_accounts_request_authorize,
	NULL, //close_account_request
	NULL,
	NULL,
	NULL,
	NULL
};

/*** Notify uiops ***/
#if 0
static void *
purpld_notify_message(PurpleNotifyMsgType type, const char *title, const char *primary, const char *secondary)
{
	char mes[PD_STRING];
	sprintf(mes, "%s %s %s \n", title, primary, secondary);
	purpld_inform_client( 0, mes );
}
#endif

static void *
purpld_notify_userinfo(PurpleConnection *gc, const char *who,
		       PurpleNotifyUserInfo *user_info)
{
	GList *iter;
	int n;

	PurpleAccount *account = purple_connection_get_account(gc);
	n = g_list_index(purple_accounts_get_all(), account);

	for (iter = purple_notify_user_info_get_entries(user_info); iter;
	     iter=iter->next) {
		PurpleNotifyUserInfoEntry *ent = iter->data;
		gchar *info = g_strdup_printf(
				//"%s = %s\r\n",
				"info: %d %s %s = %s\r\n", n, who,
				//"message: %d (%s) %d %s: %s = %s\r\n", n,
				//purple_conversation_get_name(conv),
				//who,
				//(int) time(NULL),
				//who,
				purple_notify_user_info_entry_get_label(ent),
				purple_notify_user_info_entry_get_value(ent));
		//TODO: resolve bottle-neck - inform_client shouldn't be in loop
		purpld_inform_client(account, info);
		g_free(info);
	}

	//info = purple_notify_user_info_get_text_with_newline(user_info, "<BR>");
	//	printf ("we got some info! [%d] %s\n", g_list_length(user_info->data), info);
	//	g_free(info);
	return NULL;
}

static PurpleNotifyUiOps purpld_notify_uiops =
{
	NULL, //purpld_notify_message,			/* message */
	NULL,						/* email */
	NULL,						/* emails */
	NULL,						/* formatted */
	NULL,						/* search */
	NULL,						/* search new rows */
	purpld_notify_userinfo,				/* user_info ! */
	NULL,						/* uri */
	NULL,						/* close! */
	NULL,
	NULL,
	NULL,
	NULL
};

/*** Request uiops ***/
static void*
purpld_request_file(const char *title, const char *filename,
		    gboolean savedialog, GCallback ok_cb, GCallback cancel_cb,
		    PurpleAccount *account, const char *who,
		    PurpleConversation *conv, void *user_data)
{
	PurpleXfer *xfer = user_data;
	PurpleRequestFileCb callback = (gpointer)ok_cb;
	int n = 0;
	gchar *dir;

	dir = g_build_filename(purpld_dirs.file_dir, account->alias, who, NULL);
	if (!g_file_test(dir, G_FILE_TEST_IS_DIR)) {
		g_mkdir_with_parents(dir, S_IRUSR | S_IWUSR | S_IXUSR);
	}
	gchar *path;
	path = g_build_filename(dir, xfer->filename, NULL);

	n = g_list_index(purple_accounts_get_all(), account);
	gchar *msg = g_strdup_printf("info: %d) FILE %d %s %s\r\n", n,
				     (int) time(NULL), who, path);
	purpld_inform_client(account, msg) ;
#if 1
	if (!conv) {
		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
							     who, account );
		if (!conv)
			conv = purple_conversation_new(PURPLE_CONV_TYPE_IM,
						       account, who);
	}
	purple_conversation_write(conv, who, msg, PURPLE_MESSAGE_RECV,
				  time(NULL));
#endif
	g_free(msg);
	callback(xfer, path);

	g_free(path);
	g_free(dir);
	return NULL;
}

static void*
purpld_request_input (const char *title, const char *primary,
		      const char *secondary, const char *default_value,
		      gboolean multiline, gboolean masked, gchar *hint,
		      const char *ok_text, GCallback ok_cb,
		      const char *cancel_text, GCallback cancel_cb,
		      PurpleAccount *account, const char *who,
		      PurpleConversation *conv, void *user_data)
{

	printf("libpurple input request: \"%s - %s - %s - %s\"\n", title,
	       primary, secondary, default_value);

	PurpleRequestInputCb callback = (PurpleRequestInputCb)ok_cb;
	callback(user_data, default_value);
	return NULL;
}

static void*
purpld_request_action(const char *title, const char *primary,
		      const char *secondary, int default_value,
		      PurpleAccount *account, const char *who,
		      PurpleConversation *conv, void *user_data,
		      size_t actioncount, va_list actions)
{
	gboolean done = FALSE;
	int i;

	printf("libpurple request:\"%s - %s  - %s\"", title, primary, secondary);
	for (i = 0; i < actioncount; i++)
	{
		const char *text = va_arg(actions, const char *);
		PurpleRequestActionCb callback = va_arg(actions,
							PurpleRequestActionCb);
		/* Hack -- what if it's not called accept next time? */
		if (!strcmp(text, "Accept") || !strcmp(text, "_Accept") ||
		    !strcmp(text, "Yes") || !strcmp(text, "_Yes")) {
			printf(" [ok] \n");
			callback(user_data, i);
			done = TRUE;
			break;
		}
		//printf ("\n %s \n", text);
	}
	if (!done) {
		printf (" [fail] \n");
	}
	return NULL;
}

static PurpleRequestUiOps purpld_request_uiops =
{
	purpld_request_input,
	NULL,		// _request_choice,
	purpld_request_action,
	NULL,		//_request_fields,
	purpld_request_file,
	NULL,		//_close_request,
	NULL,		//_request_folder,
	NULL,
	NULL,
	NULL,
	NULL
};

/*** Conversation uiops ***/
static void
purpld_write_conv(PurpleConversation *conv, const char *who, const char *alias,
			const char *message, PurpleMessageFlags flags,
			time_t mtime)
{
	PurpleAccount *account;
	gchar *buf;
	int n;

	account = purple_conversation_get_account(conv);

	n = g_list_index(purple_accounts_get_all(), account);
	buf = g_strdup_printf("message: %d (%s) %d %s: %s\r\n", n,
			      purple_conversation_get_name(conv), (int) mtime,
			      who, message);
	purpld_inform_client(account, buf);
	g_free(buf);
}

static PurpleConversationUiOps purpld_conv_uiops =
{
	NULL,                      /* create_conversation  */
	NULL,                      /* destroy_conversation */
	NULL,                      /* write_chat           */
	NULL,                      /* write_im             */
	purpld_write_conv,         /* write_conv           */
	NULL,                      /* chat_add_users       */
	NULL,                      /* chat_rename_user     */
	NULL,                      /* chat_remove_users    */
	NULL,                      /* chat_update_user     */
	NULL,                      /* present              */
	NULL,                      /* has_focus            */
	NULL,                      /* custom_smiley_add    */
	NULL,                      /* custom_smiley_write  */
	NULL,                      /* custom_smiley_close  */
	NULL,                      /* send_confirm         */
	NULL,
	NULL,
	NULL,
	NULL
};

#if 0
static void
purpld_ui_init(void)
{
	/**
	 * This should initialize the UI components for all the modules. Here we
	 * just initialize the UI for conversations.
	 */
	purple_conversations_set_ui_ops(&purpld_conv_uiops);
}

static PurpleCoreUiOps purpld_core_uiops =
{
	NULL,
	NULL,
	purpld_ui_init,
	purpld_ui_quit,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};
#endif

char *strleft(char *str, int len, int off) {
	int i;
	for (i = off; i < len; i++)
		str[i-off] = str[i];
	str[len-off] = '\0';
	return str;
}

int strpos(char *str, char substr) {
	int i;
	for (i=0; str[i]; i++)
		if (str[i] == substr)
			return i;
	return -1;
}

int strrpos(char *str, char substr, int len) {
	int i;
	for (i=len; i>0; i--)
		if (str[i] == substr)
			return i;
	return -1;
}

int strcrep(char *str, char src, char dst) {
	char *ptr = str;
	while (*ptr != '\0') {
		if(*ptr == src)
			*ptr = dst;
		ptr++;
	}
    return 0;
}

static gint find_account(gconstpointer a, gconstpointer b) {
	PurpleAccount *account = (PurpleAccount *)a;
	if (account->alias && !g_strcmp0(account->alias, (char*)b)) return 0;
	return 1;
}

static gint find_client(gconstpointer a, gconstpointer b) {
	int* connfd2 = (int*) b;
	client *cli = (client *)a;
	if (cli->connfd == *connfd2) return 0;
	return 1;
}

void client_set_instance(client* ptr) {
	GList *iter;
	client *cli;
	int min_i = 0, min_a = 0;
	time_t max_c = 0;
	for (iter = g_list_first(clients);iter;iter = iter->next) {
		cli = iter->data;
		if (cli != ptr && !strcmp(cli->user, ptr->user)) {
			if (cli->instance > min_i)
				min_i = cli->instance;
			if (cli->instance < min_a || min_a == 0)
				min_a = cli->instance;
			if (cli->lastcollect > max_c)
				max_c = cli->lastcollect;
		}
	}
	if (!max_c)
		max_c = time(NULL);
	ptr->lastcollect = max_c;
	if (min_a > 1)
		ptr->instance = min_a - 1;
	else
		ptr->instance = min_i + 1;
}

gboolean respond_to_login(client* ptr, char *mesg, char **args,
			  gpointer user_data) {
	if (!ptr->auth || !ptr->instance) {
		if (!strcasecmp(args[0], "USER") ) {
			if (args[1]) {
				strcpy(ptr->user, args[1]);
				if (args[2]) {
					strcpy(ptr->host, args[2]);
					if (args[3])
						strcpy(ptr->server, args[3]);
				}
			}
		} else {
			if (args[1]) {
				strcpy(ptr->pass, args[1]);
			}
		}
	}

	if (ptr->conntype == CONNECTION_IRC) {
		sprintf(mesg, ":%s 001 %s :purpleD\n", ptr->server, ptr->user);
		send(ptr->connfd, mesg, strlen(mesg), 0);

		sprintf(mesg, ":%s!%s@%s JOIN :&root\n", ptr->user, ptr->host,
			ptr->server);
		send(ptr->connfd, mesg, strlen(mesg), 0);

		sprintf(mesg, ":%s 353 %s = &root :@daemon %s\n", ptr->server,
			ptr->user, ptr->user);
		send(ptr->connfd, mesg, strlen(mesg), 0);

		//->send(ptr->connfd, ":localhost 001 driedfruit\n", strlen(":localhost 001 driedfruit\n"), 0);
		//send(connfd, ":localhost 374 :NO MOTD\n", strlen(":localhost 001 :Welcome\n"), 0);
		//send(connfd, ":localhost USER driedfruit driedfruit localhost :&root\n", strlen("localhost USER driedfruit driedfruit localhost :&root\n"), 0);
		//->send(ptr->connfd, ":driedfruit!driedfruit@localhost JOIN :&root\n", strlen(":driedfruit!driedfruit@localhost JOIN :&root\n"), 0);
		//->send(ptr->connfd, ":localhost 353 driedfruit = &root :@daemon driedfruit\n", strlen(":localhost 353 driedfruit = &root :@daemon driedfruit\n"), 0);
	}

	client_set_instance(ptr);
	ptr->auth = TRUE;

	return TRUE;
}

gboolean respond_irc_generic(client* ptr, char *mesg, char **args,
			     gpointer user_data) {
#if 0
	printf ("IRC:\n");
	int i = 0;
	for (i = 0; args[i]; i++) {
		printf ("%c) %s\n", 64+i, args[i]);
	}
#endif
	if (!strcasecmp(args[0], "NICK") ) {
		ptr->conntype = CONNECTION_IRC;
		strcpy(ptr->user, args[1]);
	} else if (!strcmp(args[0], "PRIVMSG") && !strcmp(args[1], "&root") ) {
		char buf[PD_SMALL_BUFFER];
		strcpy(buf, args[2]);
		if (buf[0] == ':') strleft(buf, strlen(buf),1);
		client_command(ptr, buf) ;
	} else if (!strcmp(args[0], "PING")) {
		sprintf(mesg, "PONG %s\n", args[1]);
		send(ptr->connfd, mesg, strlen(mesg), 0);
	}
	return TRUE;
}

gboolean respond_http_command(client* ptr, char *mesg, char **args,
			      gpointer user_data) {
	char buf[PD_SMALL_BUFFER];
	strcpy(buf, args[1]);
	client_command(ptr, buf) ;
	return TRUE;
}

gboolean respond_http_content(client* ptr, char *mesg, char **args,
			      gpointer user_data) {
	ptr->conntype = CONNECTION_HTTP;
	ptr->content_length = atoi(args[1]);
	if (strlen(ptr->buffer) == ptr->content_length) {
		strcat(ptr->buffer, "\n");
	}
	purpld_proccess_client(ptr);
	return TRUE;
}
gboolean respond_http_generic(client* ptr, char *mesg, char **args,
			      gpointer user_data) {
#if 0
	printf ("HTTP:\n");
	int i = 0;
	for (i = 0; args[i]; i++) {
		printf ("%c) %s\n", 64+i, args[i]);
	}
#endif
	ptr->conntype = CONNECTION_HTTP;
	gchar *msg;
	msg = g_strdup_printf("%s 200 OK\r\n", args[2]);
	purpld_client_send(ptr, msg);
	g_free(msg);

	msg = g_strdup_printf("Content-type: text/html\r\n\r\n");
	purpld_client_send(ptr, msg);
	g_free(msg);

	/* Get command from GET */
	if (strlen(args[1]) > 1) {
		char buf[PD_SMALL_BUFFER];
		bzero(&buf, PD_SMALL_BUFFER);
		strcpy(buf, args[1]);
		strcrep(buf, '+', ' ');
		strleft(buf, strlen(buf),1);
		client_command(ptr, buf) ;
	}
	ptr->kill = TRUE;
	return TRUE;
}

gboolean respond_generic_dummy(client* ptr, char *mesg, char **args,
			       gpointer user_data) {

	int i = 0;

	printf ("Command parser sample function.\n");
	for (i = 0; args[i]; i++) {
		if (ptr->conntype == CONNECTION_IRC && args[i][0] == ':')
			strleft(args[i], strlen(args[i]),1);
		printf ("%c) %s\n", 63+i, args[i]);
	}

	return TRUE;
}

gboolean respond_command_ver(client* ptr, char *mesg, char **args,
			     gpointer user_data) {
	gchar *buf;

	buf = g_strdup_printf ("info: purpled %d.%d.%d/%c, libpurple %d.%d.%d\r\n",
			       PURPLED_VERSION_MAJOR, PURPLED_VERSION_MINOR,
			       PURPLED_VERSION_MICRO, PURPLED_VERSION_STATE,
			       PURPLE_MAJOR_VERSION, PURPLE_MINOR_VERSION,
			       PURPLE_MICRO_VERSION);

	purpld_client_send(ptr, buf);
	g_free(buf);
	return TRUE;
}

gboolean respond_command_who(client* ptr, char *mesg, char **args,
			     gpointer user_data) {
	GList *iter;
	client *cli;
	gchar *buf;

	for (iter = g_list_first(clients);iter;iter = iter->next) {
		cli = iter->data;
        char *conn_type = (cli->conntype == CONNECTION_IRC ? "irc" :
			   (cli->conntype == CONNECTION_HTTP ? "http" : "raw"));
        char *cli_addr = inet_ntoa(cli->addr.sin_addr);
		buf = g_strdup_printf ("info: %10s/%s%d %s\r\n",
				       (cli->user[0] ? cli->user : "????"),
				       conn_type, cli->instance, cli_addr);
		purpld_client_send(ptr, buf);
		g_free(buf);
	}

	return TRUE;
}

gboolean respond_account_join(client* ptr, char *mesg, char **args,
			      gpointer user_data) {
	PurpleAccount *account = user_data;
	GHashTable *comps = NULL;
	PurpleChat *chat;

	PurpleConnection *con = purple_account_get_connection(account);
	PurplePluginProtocolInfo *info =
		PURPLE_PLUGIN_PROTOCOL_INFO(purple_connection_get_prpl(con));

	if (!purple_account_is_connected(account))
		return TRUE;
	if (info->chat_info_defaults != NULL)
		comps = info->chat_info_defaults(con, args[1]);

	chat = purple_blist_find_chat(account, args[1]);
	if (!chat) {
		chat = purple_chat_new(account, args[1], comps);
		purple_blist_add_chat(chat, NULL, NULL);
	} else {
		comps = purple_chat_get_components(chat);
		/*GList *keys = g_hash_table_get_keys(comps);
		for (; keys; keys = keys->next) {
		 printf("%s \n", keys->data);
		}*/
	}
	serv_join_chat(con, comps);
	//if (comps != NULL)
		//g_hash_table_destroy(comps);
	return TRUE;
}

gboolean respond_account_part(client* ptr, char *mesg, char **args,
			      gpointer user_data) {
	PurpleAccount *account = user_data;
	/* PurpleConnection *con = purple_account_get_connection(account); */
	PurpleChat *chat = NULL;
	PurpleConversation *conv = NULL;

	chat = purple_blist_find_chat(account, args[1]);
	if (chat) {
		purple_blist_remove_chat(chat);
	}

	conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
						     args[1], account );
	if (conv) {
		purple_conversation_destroy(conv);
	}
	return TRUE;
}

gboolean respond_account_forget(client* ptr, char *mesg, char **args,
				gpointer user_data) {
	PurpleAccount *account = user_data;
	PurpleConnection *con = purple_account_get_connection(account);
	PurpleBuddy *buddy;
	PurpleGroup *grp = NULL;

	if (!con || purple_account_is_connecting(account)) {
		return TRUE;
	}

	buddy = purple_find_buddy(account, args[1]);
	if (buddy) {
		grp = purple_buddy_get_group(buddy);
		purple_account_remove_buddy(account, buddy, grp);
		purple_blist_remove_buddy(buddy);
	}
	return TRUE;
}

gboolean respond_account_send(client* ptr, char *mesg, char **args,
			      gpointer user_data) {
	PurpleAccount *account = user_data;
	PurpleConnection *con = purple_account_get_connection(account);
	PurpleConversation *conv = NULL;
	PurpleBuddy *buddy;

	if (!con || purple_account_is_connecting(account)) {
		gchar *error = g_strdup_printf(
			"error: Failed to message \"%s\": Account %s offline\r\n",
			args[1], account->username);
		purpld_client_send(ptr, error);
		g_free(error);
		return TRUE;
	}

	if (purple_account_get_ui_bool(account, UI_ID, "log_self", FALSE)) {
		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
							     args[1], account);
		if (!conv)
			conv = purple_find_conversation_with_account(
							PURPLE_CONV_TYPE_ANY,
							args[1], account);
		if (!conv)
			conv = purple_conversation_new(PURPLE_CONV_TYPE_IM,
						       account, args[1]);
	}

	if (purple_account_get_ui_bool(account, UI_ID, "add_buddy_on_send",
				       TRUE)) {
		buddy = purple_find_buddy(account, args[1]);
		if (!buddy) {
			buddy = purple_buddy_new(account, args[1], NULL);
			purple_blist_add_buddy(buddy, NULL, NULL, NULL);
			purple_account_add_buddy(account, buddy);
		}
	}

	PurpleMessageFlags flags = PURPLE_MESSAGE_SEND;
	time_t mtime = time(NULL);

	serv_send_im (con, args[1], args[2], flags);

	//purple_conv_im_write 	(	 conv, args[1],  args[2], flags, mtime );
	//purple_conversation_present(conv);
	if (conv)
		purple_conversation_write (conv, args[1], args[2], flags, mtime);

	return TRUE;
}

gboolean respond_account_check(client* ptr, char *mesg, char **args,
			       gpointer user_data) {
	PurpleAccount *account = user_data;
	PurpleConnection *con = purple_account_get_connection(account);
	int n = g_list_index(purple_accounts_get_all(), account);

	if (!con || purple_account_is_connecting(account))		{
		gchar *error = g_strdup_printf(
			"error: Failed to check \"%s\": Account %s offline\r\n",
			args[1], account->username);
		purpld_client_send(ptr, error);
		g_free(error);
		return TRUE;
	}

	PurpleBuddyIcon *bicon = purple_buddy_icons_find(account, args[1]);
	if (bicon) {
		gchar *info = g_strdup_printf(
			//"message: %d (%s) %d %s: Buddy-Icon = %s %s\r\n", n,
			//args[1], (int) time(NULL), args[1],
			"info: %d Buddy-Icon = %s %s\r\n", n,
			purple_buddy_icon_get_checksum(bicon),
			purple_buddy_icon_get_extension(bicon));
		purpld_client_send(ptr, info);
		g_free(info);
	}

	serv_get_info (con, args[1]);

	return TRUE;
}

gboolean respond_account_collect(client* ptr, char *mesg, char **args,
				 gpointer user_data) {
	PurpleAccount *account = user_data;
	PurpleConversation *conv;
	GList *iter1, *iter2;
	GList *history;
	gchar *buf;
	int n;

	if (args[1]) ptr->lastcollect = atoi(args[1]);
	for (iter1 = purple_get_conversations(); iter1; iter1=iter1->next) {
		conv = iter1->data;
		PurpleAccount *ac = purple_conversation_get_account(conv);
		if (ac != account) continue;
		/* get history and reverse order of messages */
		history = purple_conversation_get_message_history(conv);
		history = g_list_reverse(g_list_copy(history));
		for(iter2 = history; iter2; iter2 = iter2->next) {
			/* send each message in history to client */
			PurpleConvMessage *msg = iter2->data;

			/* skip already collected messages */
			if (msg->when < ptr->lastcollect)
				continue;

			n = g_list_index(purple_accounts_get_all(), account);
			buf = g_strdup_printf("collect: %d (%s) %d %s %s\r\n",
					n, purple_conversation_get_name(conv),
					(int) msg->when, msg->who, msg->what);
			purpld_client_send(ptr, buf);
			g_free(buf);
		}
		/* free temporary history copy */
		g_list_free(history);

	}
	ptr->lastcollect = time(NULL);
	return TRUE;
}

gboolean respond_account_delete(client* ptr, char *mesg, char **args,
				gpointer user_data) {
	PurpleAccount *account = user_data;

	purple_accounts_delete(account);

	return TRUE;
}

gboolean respond_account_buddies(client* ptr, char *mesg, char **args,
				 gpointer user_data) {
	/* Returns the buddy list for the specified account */
	PurpleAccount *account = user_data;

	GSList *buddies;
	PurpleBuddy *buddy;
	gchar *buf;
	int n;

	for (buddies = purple_find_buddies(account, NULL); buddies;
	     buddies = buddies->next){
		buddy = buddies->data;
		PurplePresence *presence = purple_buddy_get_presence(buddy);
		PurpleStatus *status =
			purple_presence_get_active_status(presence);

		if (args[1] != NULL && strcmp(args[1], "online") == 0 &&
		    strcmp(purple_status_get_name(status), "Available") != 0) {
			/* Return Available users only */
			continue;
		}

		n = g_list_index(purple_accounts_get_all(), account);
		buf = g_strdup_printf("buddy: %d status: %s name: %s alias: %s",
				      n, purple_status_get_name(status),
				      purple_buddy_get_name(buddy),
				      purple_buddy_get_alias(buddy));
		purpld_client_send(ptr, buf);
		purpld_client_send(ptr, "\r\n");
		g_free(buf);
	}
	g_slist_free(buddies);
	return TRUE;
}

gboolean respond_account_enable(client* ptr, char *mesg, char **args,
				gpointer user_data) {
	PurpleAccount *account = user_data;

	purple_account_set_enabled(account, UI_ID, TRUE);

	return TRUE;
}

gboolean respond_account_disable(client* ptr, char *mesg, char **args,
				 gpointer user_data) {
	PurpleAccount *account = user_data;

	purple_account_set_enabled(account, UI_ID, FALSE);

	return TRUE;
}

gboolean respond_account_up(client* ptr, char *mesg, char **args,
			    gpointer user_data) {
	PurpleAccount *account = user_data;

	purple_account_set_status(account, "available", TRUE, 0, NULL);

	return TRUE;
}

gboolean respond_account_down(client* ptr, char *mesg, char **args,
			      gpointer user_data) {
	PurpleAccount *account = user_data;

	purple_account_set_status(account, "offline", TRUE, 0, NULL);

	return TRUE;
}

gboolean respond_account_status(client* ptr, char *mesg, char **args,
				gpointer user_data) {
	PurpleAccount *account = user_data;
	gchar *buf;

	if (!args[1])
		return TRUE;

	/* check subcommand */
	if (!strcmp(args[1], "get")) {
		/* retrieve current status */
		PurplePresence *pres = purple_account_get_presence(account);
		PurpleStatus *stat = purple_presence_get_active_status(pres);
		int n = g_list_index(purple_accounts_get_all(), account);

		buf = g_strdup_printf("status: account %d status: %s\r\n", n,
				      purple_status_get_name(stat));
		purpld_client_send(ptr, buf);
		g_free(buf);
		return TRUE;
	} else if (!strcmp(args[1], "set")) {
		/* set current status */
		if (!args[2])
			return TRUE;
		purple_account_set_status(account, args[2], TRUE, 0, NULL);
	}

	return TRUE;
}

gboolean respond_account_set(client* ptr, char *mesg, char **args,
			     gpointer user_data) {
	PurpleAccount *account = user_data;
	/*PurpleSavedStatus *status;*/
	gchar extra = '*';
	gchar *buf;
	int n;

	if (!strcmp(args[0], "useti")) {
		extra = 'U';
		purple_account_set_ui_int(account, UI_ID, args[1],
					  atoi(args[2]));
	} else if (!strcmp(args[0], "usetb")) {
		extra = 'U';
		purple_account_set_ui_bool (account, UI_ID, args[1],
					    atoi(args[2]));
	} else if (!strcmp(args[0], "uset")) {
		extra = 'U';
		purple_account_set_ui_string (account, UI_ID, args[1], args[2]);
	} else if (!strcmp(args[1], "alias") || !strcmp(args[1], "name")) {
		purple_account_set_alias(account, args[2]);
	} else if (!strcmp(args[1], "password") || !strcmp(args[1], "pass")) {
		purple_account_set_password(account, args[2]);
		purple_account_set_remember_password(account, TRUE);
	} else if (!strcmp(args[1], "username") || !strcmp(args[1], "login")) {
		purple_account_set_username(account, args[2]);
	} else if (!strcmp(args[1], "buddy_icon_path")) {
		purple_account_set_buddy_icon_path(account, args[2]);
	} else if (!strcmp(args[1], "user_info")) {
		purple_account_set_user_info(account, args[2]);
	} else {
		extra = ' ';
		if (!strcmp(args[0], "seti")) {
			purple_account_set_int (account, args[1],
						atoi(args[2]));
		} else if (!strcmp(args[0], "setb")) {
			purple_account_set_bool (account, args[1],
						 atoi(args[2]));
		} else {
			purple_account_set_string (account, args[1], args[2]);
		}
	}

	//account = purple_account_find(username, info->id);
	//PurpleAccount * 	purple_accounts_find (const char *name, const char *protocol)

	n = g_list_index(purple_accounts_get_all(), account);
	buf = g_strdup_printf("info: %d %c %s = %s\r\n", n, extra, args[1],
			      args[2]);
	purpld_client_send(ptr, buf);
	g_free(buf);
	return TRUE;
}

gboolean respond_account_add(client* ptr, char *mesg, char **args,
			     gpointer user_data) {
	GList *iter;
	int i;

	for (i = 0; args[i]; i++);
	if (i < 3)
		return TRUE;
	for (iter = purple_plugins_get_protocols(); iter; iter = iter->next) {
		PurplePlugin *plugin = iter->data;
		PurplePluginInfo *info = plugin->info;

		/*if (info && info->name) {
			printf("\t%d: %s\n", i++, info->name);
			//names = g_list_append(names, info->id);
		}*/

		if (!g_ascii_strcasecmp(args[1], info->name)) {
			PurpleAccount *account;
			/*PurpleSavedStatus *status;*/

			/* Create the account */
			account = purple_account_new(args[2], info->id);
			if (!account) {
				printf("Failed to create an account\n");
				return TRUE;
			}
			/* Get the password for the account */
			if (args[3]) {
				purple_account_set_password(account, args[3]);
				purple_account_set_remember_password(account,
								     TRUE);
			}

			/* It's necessary to enable the account first. */
			purple_account_set_enabled(account, UI_ID, TRUE);

			purple_accounts_add(account);

			break;
		}
	}
	return TRUE;
}

gboolean respond_account_list(client* ptr, char *mesg, char **args,
			      gpointer user_data) {
	GList *iter;
	int n;
	char tmp[PD_STRING];

	//sprintf(tmp, "Accounts: \n");
	//purpld_client_send(ptr, tmp);

	n = 0;
	for (iter = purple_accounts_get_all(); iter; iter = iter->next) {
		PurpleAccount *account = iter->data;
		PurplePresence *pres = purple_account_get_presence(account);
		PurpleStatus *stat = purple_presence_get_active_status (pres);
		sprintf(tmp, "account: %d %s %s %s [%s]\r\n", n,
			purple_account_get_alias(account),
			purple_account_get_protocol_name(account),
			account->username,
			(purple_account_is_connected(account) ?
			 purple_status_get_name(stat) :
			 (purple_account_is_connecting(account) ? "Connecting" :
			  "Offline")));
		purpld_client_send(ptr, tmp);
		n++;
	}

	return TRUE;
}

gboolean purpld_parse_command(client* ptr, char *mesg, PurpldCommandOps* ops,
			      int ops_len, gpointer user_data) {
	/* Paranoia to ease ops-coder's life later */
	if (!mesg || mesg[0] == '\0')
		return FALSE;
	gboolean done = FALSE;
	int i, j, n;
	n = strlen(mesg);
	for (i = 0; i < ops_len; i++) {
		if (!g_ascii_strncasecmp(mesg, ops[i].name,
					 (j = strlen(ops[i].name))) &&
		    (n <= j || mesg[j] == ' ')) {
			gchar **chunks = g_strsplit(mesg, " ", ops[i].max);
			done = (ops[i].call_back)(ptr, mesg, chunks, user_data);
			g_strfreev(chunks);
			if (done)
				break;
		}
	}
	return done;
}

gboolean respond_process_account(client* ptr, char *mesg, char **args,
				 gpointer user_data) {
	static PurpldCommandOps cli_commands[] = {
		{ "list",	respond_account_list,		0 },
		{ "add",	respond_account_add,		0 },
	};
	static int cli_len = sizeof(cli_commands) / sizeof(PurpldCommandOps);
	static PurpldCommandOps cli_commands2[] = {
		{ "delete",	respond_account_delete,		0 },
		{ "up",		respond_account_up,		0 },
		{ "down",	respond_account_down,		0 },
		{ "status",	respond_account_status,		0 },
		{ "enable",	respond_account_enable,		0 },
		{ "disable",	respond_account_disable,	0 },
		/* Set */
		{ "set",	respond_account_set,		0 },
		{ "seti",	respond_account_set,		0 },
		{ "setb",	respond_account_set,		0 },
		{ "uset",	respond_account_set,		0 },
		{ "useti",	respond_account_set,		0 },
		{ "usetb",	respond_account_set,		0 },
		/* End Set */
		{ "send",	respond_account_send,		3 },
		{ "join",	respond_account_join,		0 },
		{ "part",	respond_account_part,		0 },
		{ "forget",	respond_account_forget,		0 },
		{ "check",	respond_account_check,		0 },
		{ "collect",	respond_account_collect,	0 },
		{ "buddies",	respond_account_buddies,	0 }
	};
	static int cli_len2 = sizeof(cli_commands2) / sizeof(PurpldCommandOps);

	/* Empty command */
	if (!args[1] || args[1][0] == '\0') {
		return TRUE;
	}

	if (!purpld_parse_command(ptr, args[1], cli_commands, cli_len, 0)) {
		int id, n, off = 0;
		GList *iter = purple_accounts_get_all();
		PurpleAccount *account = NULL;
		gchar *msg;
		if (sscanf(args[1], "%d", &id) == 1) {
			off = (int)(id / 10)+1;
			account = g_list_nth_data(iter, id);
		} else if ((n = strpos(args[1], ' ')) != -1) {
			GList *find;
			char buf[PD_TINY_STRING];
			bzero(buf, PD_TINY_STRING);
			strncpy(buf, args[1], n);
			off = strlen(buf);
			find = g_list_find_custom( iter, buf, find_account );
			if (find) account = find->data;
		}
		if (!account) {
			msg = g_strdup_printf(
				"error: Bad command or account name \"%s\"\r\n",
				args[1]);
			purpld_client_send(ptr, msg);
			g_free(msg);
			return TRUE;
		}

		if (off) strleft(args[1], strlen(args[1]), off+1 );
		purpld_parse_command(ptr, args[1], cli_commands2, cli_len2,
				     account);
	}

	return TRUE;
}

void client_command(client* ptr, char *mesg) {
	static PurpldCommandOps cli_commands[] = {
		{ "NICK",		respond_irc_generic,		0 },
		{ "PING",		respond_irc_generic,		0 },
		{ "PRIVMSG &root",	respond_irc_generic,		3 },
		{ "user",		respond_to_login,		5 },
		{ "pass",		respond_to_login,		0 },
		{ "GET",		respond_http_generic,		0 },
		{ "POST",		respond_http_generic,		0 },
		{ "Content-Length:",	respond_http_content,		0 },
		{ "http_offset=",	respond_http_command,		2 },
		{ "account",		respond_process_account,	2 },
		{ "acc",		respond_process_account,	2 }, //acc - shorthand for account
		{ "ver",		respond_command_ver,		0 },
		{ "who",		respond_command_who,		0 }
	 };
	static int cli_len = sizeof(cli_commands) / sizeof(PurpldCommandOps);

	mesg = g_strchomp(mesg);
	if (mesg[0] == '\0')
		return;
	if (ptr->conntype == CONNECTION_HTTP) strcrep(mesg, '+', ' ');

	//printf("DOING COMMAND \"%s\" \n", mesg);

	purpld_parse_command(ptr, mesg, cli_commands, cli_len, 0);

	/* Hack -- if he is not going to auth, just assign some id */
	if (!ptr->instance && !ptr->auth) {
		strcpy(ptr->user, "????");
		client_set_instance(ptr);
	}
}


void purpld_client_send(client* ptr, const char *mesg) {
	if (ptr->conntype == CONNECTION_IRC) {
		gchar *buf;
		if (!ptr->auth)
			buf = g_strdup_printf("NOTICE AUTH :%s", mesg);
		else
			buf = g_strdup_printf(
					":daemon!daemon@%s PRIVMSG &root :%s",
					ptr->server, mesg);
		send(ptr->connfd, buf, strlen(buf), 0);
		g_free(buf);
	}
	else
		send(ptr->connfd, mesg, strlen(mesg), 0);
}

void purpld_proccess_client(client* ptr) {
	int i;
	int len, off/*, first*/;
	/*gboolean complete = FALSE;*/
	gboolean several = FALSE;

	char mesg[PD_LARGE_BUFFER]; //mini-buffer

	len = strlen(ptr->buffer);
	//if (ptr->content_length && len >= ptr->content_length) {}
	//if (len > PD_BUFFER_LENGTH) { printf ("FATAL ERROR"); exit; }

	/* No command ready, just buffer */
	if ((off = strrpos(ptr->buffer, '\n', len)) < 0) return;
	/* More than 1 command - we must check this now, because buffer will be cleared afterwards */
	if ( strpos(ptr->buffer, '\n') != off ) several = TRUE;

	/* Copy to minibuffer */
	strncpy(mesg, ptr->buffer, off);
	mesg[off] = '\0';

	/* Pad leftovers */
	if (off < len-1)
		for (i = off; i < len; i++)
			ptr->buffer[i-off-1] = ptr->buffer[i];

	/* Clear what was copied to minibuffer from real buffer */
	ptr->buffer[len-off-1] = '\0';

	/* Execute ONE / MANY commands */
	if (!several)
		client_command(ptr, mesg);
	else {
		gchar **chunks = g_strsplit(mesg, "\n", 0);
		for (i=0;chunks[i];i++)
			client_command(ptr, chunks[i]);
		g_strfreev(chunks);
	}
}

static gboolean purpld_handle_client(GIOChannel *src, GIOCondition condition,
				     gpointer null2)
{
	int connfd = g_io_channel_unix_get_fd(src);
	int n;
	char mesg[PD_SMALL_BUFFER];
	/*char tmp[PD_TINY_STRING];*/

	client *client_ptr =
		(g_list_find_custom(clients, &connfd, find_client))->data;
	if (!client_ptr) {
		printf("Fatal Error: Client not found while handling client \n");
		exit(EXIT_FAILURE);
	}

	n = recv(connfd, mesg, PD_SMALL_BUFFER, 0);
	if (n <= 0 || !client_ptr) {
		total_c--;
		printf("Connection [%d] closed\n", connfd);
		//perror("Receive");

		close(connfd);

		clients = g_list_remove(clients, client_ptr);

		return FALSE;
	}
	mesg[n] = '\0';

	strcat(client_ptr->buffer, mesg);

	purpld_proccess_client(client_ptr);

	if (client_ptr->kill == TRUE) {
		printf("Connection [%d] closed\n", connfd);

		close(connfd);

		clients = g_list_remove( clients, client_ptr );

		return FALSE;
	}
	return TRUE;
}

static gboolean purpld_accept_client(GIOChannel *src, GIOCondition condition,
				     gpointer null2)
//static void	purpld_accept_client (gpointer null1, gint null2, PurpleInputCondition gic)
	//int listenfd = null2;
{
	struct sockaddr_in cliaddr;
	static socklen_t clilen = sizeof(cliaddr);
	int listenfd = g_io_channel_unix_get_fd(src);
	int connfd;
	/*char mesg[100];*/

	connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);
	//if (connfd == -1)	continue;

	glib_input_add(connfd, PURPLE_GLIB_READ_COND, purpld_handle_client);

	printf("Connection [%d] from %s established (online: %d)\n", connfd,
	       inet_ntoa(cliaddr.sin_addr), total_c );

	client* new_client;
	new_client = g_malloc0 (sizeof (struct client));
	new_client->connfd = connfd;
	new_client->conntype = CONNECTION_UNKNOWN;
	new_client->addr = cliaddr;

	clients = g_list_append (clients, new_client);

	total_c++;
	return TRUE;
}

static gboolean
auto_join_chats(gpointer data)
{
	PurpleBlistNode *node;
	PurpleConnection *pc = data;
	PurpleAccount *account = purple_connection_get_account(pc);

	for (node = purple_blist_get_root(); node;
			node = purple_blist_node_next(node, FALSE)) {
		if (PURPLE_BLIST_NODE_IS_CHAT(node)) {
			PurpleChat *chat = (PurpleChat*)node;
			if (purple_chat_get_account(chat) == account/* &&
					purple_blist_node_get_bool(node, "gnt-autojoin")*/)
				serv_join_chat(
					purple_account_get_connection(account),
					purple_chat_get_components(chat));
		}
	}
	return FALSE;
}

static gboolean
auto_reconnect(gpointer data)
{
	PurpleConnection *pc = data;
	PurpleAccount *account = purple_connection_get_account(pc);

	if (purple_account_get_enabled(account, UI_ID))
		purple_account_set_status(account, "available", TRUE, 0, NULL);

	return FALSE;
}

static void
signed_on(PurpleConnection *gc, gpointer null)
{
	PurpleAccount *account = purple_connection_get_account(gc);
	printf("Account connected: %s %s\n", account->username,
	       account->protocol_id);
	g_idle_add(auto_join_chats, gc);
}

static void
signed_off(PurpleConnection *gc, gpointer null)
{
	PurpleAccount *account = purple_connection_get_account(gc);
	const PurpleConnectionErrorInfo *err =
		purple_account_get_current_error(account);
	int recon = purple_account_get_ui_int(account, UI_ID,
					      "reconnect_timeout", 0) * 60;
	printf("Account %s disconnected: %s %s\n",
	       (!err ? "happily" : "unhappily"), account->username,
	       account->protocol_id);
	if (err) printf("%d %s\n", err->type, err->description);
	if (err && recon) g_timeout_add(recon, auto_reconnect, gc);
}

static void
register_purple_signals(void)
{
	static int handle;
	purple_signal_connect(purple_connections_get_handle(), "signed-on",
			      &handle, PURPLE_CALLBACK(signed_on), NULL);
	purple_signal_connect(purple_connections_get_handle(), "signed-off",
			      &handle, PURPLE_CALLBACK(signed_off), NULL);
}

void daemonize(void) {
	pid_t   pid, sid;

	pid = fork();

	if (pid < 0) {
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	umask(0);

	sid = setsid();
	if (sid < 0) {
		exit(EXIT_FAILURE);
	}

	if ((chdir("/")) < 0) {
		exit(EXIT_FAILURE);
	}
}

int uninit_path(void) {
    g_free(purpld_dirs.home_dir);
    g_free(purpld_dirs.log_file);
    g_free(purpld_dirs.pid_file);
    g_free(purpld_dirs.file_dir);
    return 1;
}

int init_paths(char *work_dir) {
	/* Get directories and such */
	struct passwd *passwd;
	uid_t id = getuid();
	passwd = getpwuid ( id );

	gchar *path;
	if (work_dir) {
		path = g_build_filename(work_dir, NULL);
	} else if (id == 0) {
		path = g_build_filename("usr", "local", "etc", UI_ID, NULL);
	} else if (!strcmp(passwd->pw_gecos, UI_ID)) {
		path = g_build_filename(passwd->pw_dir, NULL);
	} else {
		path = g_build_filename(passwd->pw_dir, UI_ID, NULL);
	}

	purpld_dirs.home_dir = g_strdup(path);
	g_free(path);

	/* Log-file */
	if (id == 0) {
		path = g_build_filename("var", "log", "purpled.log", NULL);
	} else {
		path = g_build_filename(purpld_dirs.home_dir, "purpled.log",
					NULL);
	}

	purpld_dirs.log_file = g_strdup(path);
	g_free(path);

	/* Pid-file */
	if (id == 0) {
		path = g_build_filename("var", "pid", "purpled.pid", NULL);
	} else {
		path = g_build_filename(purpld_dirs.home_dir, "purpled.pid",
					NULL);
	}

	purpld_dirs.pid_file = g_strdup(path);
	g_free(path);

	/* File-dir */
	if (id == 0) {
		path = g_build_filename("tmp", UI_ID, "files", NULL);
	} else {
		path = g_build_filename(purpld_dirs.home_dir, "files", NULL);
	}

	purpld_dirs.file_dir = g_strdup(path);
	g_free(path);

/*
	printf("Home Dir: %s \n", purpld_dirs.home_dir);
	printf("Log=File: %s \n", purpld_dirs.log_file);
	printf("Pid=File: %s \n", purpld_dirs.pid_file);
	printf("File Dir: %s \n", purpld_dirs.file_dir);
*/
	return 1;
}

void init_server_inet(in_port_t listen_port, struct in_addr listen_addr) {
	struct sockaddr_in servaddr;
	int on = 1;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);

	/* Enable address reuse */
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr = listen_addr;
	servaddr.sin_port = listen_port;

	if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
	{
		perror("Bind Failed");
		exit(EXIT_FAILURE);
	}
	if (listen(listenfd, PD_SMALL_BUFFER) < 0) {
		perror("Listen Failed");
		exit(EXIT_FAILURE);
	}
	//purple_glib_input_add(listenfd, PURPLE_INPUT_READ,
	//purpld_accept_client, NULL);
	glib_input_add(listenfd, PURPLE_GLIB_READ_COND, purpld_accept_client);
}

void init_server_unix(void) {
	char *sock_name = "purpled.sock";
	struct sockaddr_un servaddr;
	char *socket_path;

	listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listenfd == -1) {
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sun_family = AF_UNIX;
	socket_path = g_build_filename(purpld_dirs.home_dir, sock_name, NULL);
	strncpy(servaddr.sun_path, socket_path, sizeof(servaddr.sun_path)-1);
	unlink(socket_path);

	if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
	{
		perror("Bind Failed");
		exit(EXIT_FAILURE);
	}
	if (listen(listenfd, PD_SMALL_BUFFER) < 0) {
		perror("Listen Failed");
		exit(EXIT_FAILURE);
	}
	glib_input_add(listenfd, PURPLE_GLIB_READ_COND, purpld_accept_client);
}

int init_libpurple(void) {
	PurpleSavedStatus *status;

	/* libpurple's built-in DNS resolution...	[trim].. will it conflict with daemon? seems not */
	signal(SIGCHLD, SIG_IGN);

	/* Set path to search for ui-specific plugins. (Not protocols!) */
	//purple_plugins_add_search_path(CUSTOM_PLUGIN_PATH);
	purple_util_set_user_dir(purpld_dirs.home_dir);

	/* We do not want any debugging for now to keep the noise to a minimum. */
	purple_debug_set_enabled(FALSE);

	/* Set the core-uiops, which is used to
	 * 	- initialize the ui specific preferences.
	 * 	- initialize the debug ui.
	 * 	- initialize the ui components for all the modules.
	 * 	- uninitialize the ui components for all the modules when the core terminates.
	 */
//	purple_core_set_ui_ops(&purpld_core_uiops);
	purple_conversations_set_ui_ops(&purpld_conv_uiops);
	purple_notify_set_ui_ops(&purpld_notify_uiops);
	purple_request_set_ui_ops(&purpld_request_uiops);
	purple_accounts_set_ui_ops(&purpld_accounts_uiops);

	/* Set the uiops for the eventloop. If your client is glib-based, you can safely
	 * copy this verbatim. */
	purple_eventloop_set_ui_ops(&glib_eventloops);

	/* Now that all the essential stuff has been set, let's try to init the core. It's
	 * necessary to provide a non-NULL name for the current ui to the core. This name
	 * is used by stuff that depends on this ui, for example the ui-specific plugins. */
	if (!purple_core_init(UI_ID)) {
		/* Initializing the core failed. Terminate. */
		fprintf(stderr,
				"libpurple initialization failed. Dumping core.\n"
				"Please report this!\n");
		abort();
	}

	/* Create and load the buddylist. */
	purple_set_blist(purple_blist_new());
	purple_blist_load();

	/* Load the preferences. */
	purple_prefs_load();

	/* Load the desired plugins. The client should save the list of loaded plugins in
	 * the preferences using purple_plugins_save_loaded(PLUGIN_SAVE_PREF) */
	//purple_plugins_load_saved(PLUGIN_SAVE_PREF);

	/* Load the pounces. */
	purple_pounces_load();

	//printf("libpurple initialized.\n");

	/* This part I actually don't understand (yes, I admit!)
	 *
	 * purple_savedstatus_activate(status); -- doesn't work on it's own
	 * when old accounts are preloaded, so I restore their state...
	 *
	 * and then I still have to set PURPLE_STATUS_AVAILABLE for accounts
	 * created afterwards! is there a cleaner way for this?
	 */
	purple_accounts_restore_current_statuses();
	status = purple_savedstatus_find_transient_by_type_and_message(
							PURPLE_STATUS_AVAILABLE,
							NULL);
	if (status == NULL) status = purple_savedstatus_new(
							NULL,
							PURPLE_STATUS_AVAILABLE);

	/* Set the status for each account */
	purple_savedstatus_activate(status);

	/* Register account-wide libpurple signals */
	register_purple_signals();

	return 0;
}

static void
handle_server_signals(int sig)
{
	switch (sig) {
		case SIGTERM:
		case SIGINT:
			printf("Received signal (%d), Quitting\n", sig);

			GList* iter;

			for (iter = g_list_first(clients); iter;
			     iter = iter->next) {
				client* cli = iter->data;
				close (cli->connfd);
				g_free(cli);
			}
			close (listenfd);
			g_list_free(clients);

			fclose(stdout);
			fclose(stderr);

			//g_main_loop_quit (0);
			uninit_path();
			exit(EXIT_SUCCESS);
	}
}

void print_usage(void)
{
	fprintf(stderr, "Usage: purpled [-d] [-pPORT] [-lLISTEN_IP]\n"
		"OPTIONS\n"
		"-d		run purpled a unix daemon\n"
		"-i		use AF_INET/TCP socket\n"
		"-pPORT		specify on which TCP port purpled listen. Default: 32000\n"
		"-lLISTEN_IP	specify on which IP address purpled listen. Default: any 0.0.0.0\n"
		"-u		use AF_UNIX socket\n"
		"-wDIR		specify working directory of purpled\n"
		"-h		display this help and exit\n\n"
		"EXAMPLES\n"
		"purpled, listen on port 4242 and stay in the terminal.\n"
		" $ purpled -i -p4242\n"
		"purpled, listen on IP address 127.0.0.1 and start as a deamon.\n"
		" $ purpled -i -l127.0.0.1 -d\n");
}

int main(int argc, char *argv[])
{
	gboolean run_as_daemon = TRUE;
	gboolean inet_socket = FALSE;
	gboolean unix_socket = FALSE;
	struct in_addr listen_addr;
	in_port_t listen_port;
	char *work_dir = NULL;
	char *param;
	int i;

	run_as_daemon = FALSE;
	listen_port = htons (32000);
	listen_addr.s_addr = htonl (INADDR_ANY);
	for (i = 1; i < argc; i++)
	{
		param = argv[i];
		if (param[0] == '-')
		{
			if (param[1] == 'd')
			{
				run_as_daemon = TRUE;
			}
			else if (param[1] == 'h')
			{
				print_usage();
				return (EXIT_SUCCESS);
			}
			else if (param[1] == 'u') {
				/* AF_UNIX socket */
				unix_socket = TRUE;
			}
			else if (param[1] == 'i') {
				/* AF_INET socket */
				inet_socket = TRUE;
			}
			else if (param[1] == 'l')
			{
				if (!inet_aton (&param[2], &listen_addr))
				{
					fprintf(stderr,
						"invalid listen address: %s\n",
						&param[2]);
					print_usage();
					return (EXIT_FAILURE);
				}
			}
			else if (param[1] == 'p')
			{
				int port;
				port = atoi (&param[2]);
				if ((port <= 1) || (port > 66536))
				{
					fprintf(stderr,
						"invalid listen port: %s\n",
						&param[2]);
					print_usage();
					return (EXIT_FAILURE);
				}
				else
				{
					listen_port = htons ((short) port);
				}
			}
			else if (param[1] == 'w')
			{
				work_dir = &param[2];
			}
			else
			{
				fprintf(stderr, "unknown parameter: %s\n",
					param);
				print_usage();
				return (EXIT_FAILURE);
			}
		}
		else
		{
			fprintf(stderr, "invalid parameter: %s\n", param);
			print_usage();
			return (EXIT_FAILURE);
		}
	}

	/* either AF_INET or AF_UNIX must be selected */
	if (!unix_socket && !inet_socket) {
		fprintf(stderr, "missing -i or -u\n");
		print_usage();
		return(EXIT_FAILURE);
	}

	/* Bye-bye terminal */
	if (run_as_daemon)
		daemonize();

	/* Look around */
	init_paths(work_dir);

	/* Handle signals */
	signal(SIGINT, handle_server_signals);
	signal(SIGTERM, handle_server_signals);

	/* Program name */
	g_set_prgname("purpleD");

	/* Init server part */
	if (inet_socket)
		init_server_inet(listen_port, listen_addr);
	if (unix_socket)
		init_server_unix();

	/* Init client(s) part */
	init_libpurple();

#if 0
	/* Reroute stdout and stderr into log_file */
	freopen(purpld_dirs.log_file, "w", stderr);
	FILE *wfd = freopen(purpld_dirs.log_file, "w", stdout);
	setlinebuf(wfd);
#endif

	/* Endless loop glib-style */
	GMainLoop *loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);

	//TODO: end here
	uninit_path();

	return (EXIT_SUCCESS);
}
