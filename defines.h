#define UI_ID                  "purpled"
 
#define CONNECTION_UNKNOWN	0
#define CONNECTION_RAW		1
#define CONNECTION_TELNET	2
#define CONNECTION_IRC		3

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
	char 		name[PD_TINY_STRING];
	char 		user[PD_TINY_STRING];
	char 		server[PD_SMALL_STRING];
	char 		host[PD_SMALL_STRING];
	char 		pass[PD_SMALL_STRING];
	gboolean auth;
};

typedef gboolean (*command_cb) (client *ptr, char *mesg, char **args, gpointer user_data);

typedef struct PurpldCommandOps {
	gchar 		*name;
	command_cb	call_back;
	int 			max;
} PurpldCommandOps;
