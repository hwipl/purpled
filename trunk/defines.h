#define UI_ID                  "purpled"
#define PURPLED_VERSION_MAJOR		0
#define PURPLED_VERSION_MINOR		0
#define PURPLED_VERSION_MICRO		8
#define PURPLED_VERSION_STATE		'p'
 
#define CONNECTION_UNKNOWN	0
#define CONNECTION_RAW		1
#define CONNECTION_TELNET	2
#define CONNECTION_IRC		3
#define CONNECTION_HTTP 	4

#define PD_LARGE_BUFFER 	4096
#define PD_SMALL_BUFFER 	1024
#define PD_STRING				256
#define PD_SMALL_STRING		128
#define PD_TINY_STRING		80

typedef struct client client;
struct client {
	int 		connfd;
	struct 	sockaddr_in addr;
	time_t 	lastcollect;
	int 		conntype;
	char 		buffer[PD_LARGE_BUFFER];
	int 		instance;
	int		content_length;
	char 		name[PD_TINY_STRING];
	char 		user[PD_TINY_STRING];
	char 		server[PD_SMALL_STRING];
	char 		host[PD_SMALL_STRING];
	char 		pass[PD_SMALL_STRING];
	gboolean auth;
	gboolean kill;
};

typedef gboolean (*command_cb) (client *ptr, char *mesg, char **args, gpointer user_data);

typedef struct PurpldCommandOps {
	gchar 		*name;
	command_cb	call_back;
	int 			max;
} PurpldCommandOps;

//typedef struct purpld_dirs purpld_dirs; 
struct purpld_dirs {
	gchar *home_dir;
	gchar *log_file;
	gchar *pid_file;
	gchar *file_dir;
};
