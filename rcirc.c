#define _GNU_SOURCE
#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <poll.h>
#include <json-c/json.h>
#include <arpa/inet.h>
#include <search.h>
#include "json.h"
#include "util.h"

#define MALLOC malloc
#define NEW(x) (x *)memset(MALLOC(sizeof(x)), 0, sizeof(x))
#define IFFREE(x) if((x)) {free (x); (x) = NULL;}
#define STRDUP(x) ((x)?(strdup((x))):NULL)

#define EROOMNOTFOUND -1

#define STATE_SHUTTING_DOWN 1

#define MAXFD 512

static char *MSG_edited = "[edited]";
static char *MSG_removed = "[removed]";

static char *server_name = NULL;

static int interrupted;

typedef struct t_buff {
	char *buff;
	char *start;
	int left;
	struct t_buff *next;
} t_buff;

typedef struct t_rc_room {
	char *rid;
	char *fname;
	char *name;
	char *topic;
	unsigned long long ls;
	char t;

	struct t_rc_room *next;
} t_rc_room;

typedef char t_rc_id[16];
struct t_sess;

typedef struct t_rc_command {
	t_rc_id id;
	void *data;
	int (*fce)(struct t_sess * s, void *data, struct json_object * json);

	struct t_rc_command *next;
} t_rc_command;

typedef struct t_rc_message {
	const char *id;
	char t;
	char *dstname;
	char *msg;
	char *sender;
	char *reactions;
	time_t tim;

	struct t_rc_message *next;
} t_rc_message;

typedef struct t_rc_sndmsg {
	struct t_rc_sndmsg *next;
	char id[];
} t_rc_sndmsg;

typedef struct t_sess {
	int irc_fd;
	int rch_fd;
	int state;
	struct {
		char *nick;
	} irc;
	char irc_buff[513];
	int irc_buff_head;
	struct lws_pollfd *poll;
	struct lws_pollfd *rc_poll;
	t_buff *irc_out_buff, **irc_out_buff_tail;

	struct {
		struct lws_context *context;
		struct lws_vhost *vhost;
		const struct lws_protocols *protocol;
		pthread_t pthread_spam[2];

		t_buff *out_buff, **out_buff_tail;
		uint32_t tail;

		struct lws_client_connect_info i;
		struct lws *client_wsi;

		int counter;
		int fd_idx;
		char finished;
		char established;

		time_t last_ping;

		char *self_id;
		char *token;

		t_rc_command *commands;
		t_rc_room *rooms;
		t_rc_message *messages;
		t_rc_message *in_messages;
		void *in_messages_tree;
		t_rc_sndmsg *sent;
	} rc;

	struct t_sess *next;
} t_sess;

struct lws_pollfd pollfds[MAXFD];
struct t_sess *sessions[MAXFD];
int maxfds = 0;
static int rc_timeout = 60*5;
const char *selfident = "myserver";
static struct t_sess *session_list = NULL;

#define SWAPC(a, b) {char *__c; __c = a; a = b; b = __c; }

void poll_removefd(int i)
{
	for (t_sess *s = session_list; s; s = s->next) {
		if (s->rc_poll >= &pollfds[i]) s->rc_poll--;
		if (s->poll >= &pollfds[i]) s->poll--;
	}

	memcpy(&pollfds[i], &pollfds[i + 1],
	       sizeof(struct lws_pollfd) * (maxfds - i));
	memcpy(&sessions[i], &sessions[i + 1], sizeof(t_sess *) * (maxfds - i));
	maxfds--;
}

int poll_addfd(int fd, t_sess * s, int events)
{
	pollfds[maxfds].fd = fd;
	pollfds[maxfds].events = events;
	sessions[maxfds] = s;
	s->rc.fd_idx = maxfds;

	return (maxfds++);
}

t_buff *buff__sprintf(const char *fmt, ...);
t_buff *buff__new();
void buff__free(t_buff *b);

void sess__add_irc_out(t_sess * s, t_buff * b);
int sess__irc_nick_set(t_sess * s, const char *newnick);
int sess__irc_send_message(t_sess * s, char t, const char *srcname,
			   const char *name, char *pfx, char *msg);

void sess__add_sent_message(t_sess * s, const char *id);
int sess__find_sent_message(t_sess * s, const char *id);

int sess__rc_send_message(t_sess * s, char t, const char *name,
			  const char *msg);
void gen_id(t_rc_id id);
int sess__rc_command_call(t_sess * s, void *data, json_object * json,
			  int (*fce)(t_sess * s, void *data, json_object * j));

t_rc_room *sess__rc_room_add(t_sess * s, char t, const char *name,
			     const char *rid, const char *fname,
			     const char *topic);
t_rc_room *sess__rc_room_by_rid(t_sess * s, const char *rid);
t_rc_room *sess__rc_room_by_name(t_sess * s, char t, const char *name);
int sess__rc_command_call_(t_sess * s, void *data, json_object * json,
			   int (*fce)(t_sess * s, void *data, json_object * j));
int sess__rc_json_send_(t_sess * s, json_object * json);
int sess__rc_start(t_sess * s, struct lws_context *ctx);
int sess__rc_join_room(t_sess * s, char t, const char *name);
int sess__rc_queue_message(t_sess * s, char t, const char *name,
			   const char *msgs);
void rc_message__free(t_rc_message * m);
t_rc_message *sess__rc_find_message(t_sess *s, const char *id);
t_rc_message *sess__rc_add_message(t_sess *s, const char *id, const char *msg, const char *sender, const char *reactions);
int sess__rc_queue_process(t_sess * s);
int sess__rc_set_away(t_sess * s, const char *msg);
int sess__rc_set_back(t_sess * s);


int sess__cb_rc_getusers(t_sess * s, void *data, json_object * j);
int sess__cb_rc_joinroom(t_sess * s, void *data, json_object * j);
int sess__cb_rc_getroom(t_sess * s, void *data, json_object * j);
int sess__cb_rc_sendmessage(t_sess * s, void *data, json_object * j);
int sess__cb_rc_getsubscriptions(t_sess * s, void *data, json_object * j);
int sess__cb_rc_login(t_sess * s, void *data, json_object * j);
int sess__cb_rc_createdirect(t_sess * s, void *data, json_object * j);
int sess__cb_rc_set_away(t_sess * s, void *data, json_object * j);
int sess__cb_rc_set_back(t_sess * s, void *data, json_object * j);

int sess__close(t_sess * s);
int irc__process(t_sess * s, struct lws_context *ctx);

int sess__add_rc_out(t_sess * s, int len, const char *c)
{
	if (len == -1)
		len = strlen(c);
	t_buff *buff = buff__new();
	buff->buff = malloc(LWS_PRE + len + 1);
	memcpy(buff->buff + LWS_PRE, c, len);
	buff->buff[LWS_PRE + len] = '\0';
	buff->left = len;

	*s->rc.out_buff_tail = buff;
	s->rc.out_buff_tail = &buff->next;

	if (s->rc.client_wsi) {
		lws_callback_on_writable(s->rc.client_wsi);
		s->rc_poll->events |= POLLOUT;
	}
	return 0;
}

int sess__add_rc_out_(t_sess * s, const char *c)
{
	int r = sess__add_rc_out(s, -1, c);
	free((char *)c);
	return (r);
}

t_rc_command *sess__rc_command_by_id(t_sess * s, const t_rc_id id)
{
	t_rc_command *cmd;

	for (cmd = s->rc.commands; cmd && strcmp(cmd->id, id);
	     cmd = cmd->next) ;

	return cmd;
}

int sess__rc_work(t_sess * s, const char *in)
{
	int r;
	char *msg = NULL, *collection = NULL, *selfuser = NULL, *userid = NULL,
	    *_id = NULL, *username = NULL, *roomName = NULL;
	json_object *args = NULL;
	struct json_object *jo, *jobj = json_tokener_parse(in);

	if (!jobj) {
		logg(ERR, "Can\'t json_tokener_parse()\n");
		return (-1);

	}

	if ((jo = json_object_object_get(jobj, "msg"))) {
		const char *msg = json_object_get_string(jo);
		if (!strcmp(msg, "ping")) {
			msg = NULL;
			s->rc.last_ping = time(NULL);
			sess__add_rc_out(s, -1, "{\"msg\":\"pong\"}");
			goto finished;
		}
		msg = NULL;
	}

	jo = json_object_object_get(jobj, "id");

	if (jo) {
		const char *id = json_object_get_string(jo);
		t_rc_command *cb = sess__rc_command_by_id(s, id);
		if (cb) {
			logg(DBG1, "I've GOT REPLY %s!\n", id);

			if (cb->fce)
				r = cb->fce(s, cb->data, jobj);

			/* TODO: delete command struct */

			goto finished;
		}
	}

	if (json_read
	    (NULL, jobj, "{msg=%s collection=%s id:%s fields:{username:%s}}",
	     "added", "users", &userid, &selfuser) == 2) {
		sess__irc_nick_set(s, selfuser);
		s->rc.self_id = userid;
		userid = NULL;

		char *allsubs[] =
		    { "notification", "rooms-changed", "subscriptions-changed",
	      "otr", NULL };

		for (char **subs = allsubs; *subs; subs++) {
			char su[64];

			snprintf(su, sizeof(su), "%s/%s", s->rc.self_id, *subs);

			sess__rc_command_call_(s, NULL,
					       json_create(NULL,
							   "{msg:%s name:%s params:[%s %b]}",
							   "sub",
							   "stream-notify-user",
							   su, 0), NULL);
		}

		goto finished;
	}
	if (json_read
	    (NULL, jobj,
	     "{collection=%s msg=%s fields:{args:[:{t=%s u:{username:%s}} :{roomName:%s}]}}",
	     "stream-room-messages", "changed", "uj", &username,
	     &roomName) == 2) {

		sess__add_irc_out(s,
				  buff__sprintf(":%s JOIN #%s\r\n", username,
						roomName));

		goto finished;
	}
	/*
	   if (json_read(NULL, jobj, "{collection=%s msg=%s fields:{args:[:{t=%s u:{username:%s}} :{roomName:%s}]}}",
	   "stream-room-messages", "changed", "ru", &username, &roomName) == 2) {

	   sess__add_irc_out (s, buff__sprintf (":%s PART #%s\r\n", username, roomName));

	   goto finished;
	   } */

	if (json_read(NULL, jobj, "{msg:%s collection:%s fields:{args:%o}}",
		      &msg, &collection, &args) == 3) {

		if (!strcmp(collection, "stream-notify-user")) {
			char *name = NULL, *fname = NULL, *rid = NULL, *t =
			    NULL;

			if (json_read
			    (NULL, args,
			     "[=%s :{name:%s fname:%s rid:%s t:%s}]",
			     "inserted", &name, &fname, &rid, &t) == 4) {
				sess__rc_room_add(s, t[0], name, rid, fname,
						      NULL);

				IFFREE(fname);
				IFFREE(name);
				IFFREE(rid);
				IFFREE(t);
				sess__rc_queue_process(s);
			}
		} else {
			int cnt_args = json_object_array_length(args);
			for (int i = 0; i < cnt_args; i++) {
				json_object *attachments = NULL, *reactions = NULL;
				json_object *p =
				    json_object_array_get_idx(args, i);

				char *msg = NULL, *rid = NULL, *username =
				    NULL, *roomName = NULL, *t = NULL, *tmid = NULL,
					*mt = NULL;
				int roomParticipant = 0;

				if ((r = json_read(NULL, p,
						   "{payload:{message:{msg:%s} rid:%s sender:{username:%s} type:%s _id:%s}}",
						   &msg, &rid, &username, &t,
						   &_id)) >= 5) {

					char *dst = s->irc.nick;
					if (!strcmp(dst, username)) {
						t_rc_room *r =
						    sess__rc_room_by_rid(s,
									 rid);
						if (r)
							dst = r->name;
					}
					if (sess__find_sent_message(s, _id))
						goto finished2;
					sess__irc_send_message(s, 'd', username,
							       dst, NULL, msg);

				} else
				    if ((r =
					 json_read(NULL, p,
						   "{msg:%s rid:%s _id:%s u:{username:%s} attachments?%o reactions?%o tmid?%s t?%s}",
						   &msg, &rid, &_id,
						   &username, &attachments, &reactions, &tmid, &mt)) >= 4 
						   && msg && rid && _id && username) {

					t_rc_room *room =
					    sess__rc_room_by_rid(s, rid);

					if ((i + 1) < cnt_args) {
						i += 1;
						json_object *p =
						    json_object_array_get_idx
						    (args, i);

						r = json_read(NULL, p,
							      "{roomType:%s roomName?%s roomParticipant?%b}",
							      &t, &roomName,
							      &roomParticipant);

					}

					/*
					 * was this message sent by us? */
					if (sess__find_sent_message(s, _id))
						goto finished2;

					char *s_reactions = reactions2string(reactions);

					char *_pfx = NULL;
					char *_msg = msg;

					/*
					 * have we already seen this message? */
					t_rc_message *m = sess__rc_find_message(s, _id);

					if (m) {
						logg(DBG4, "Repeated message %s\n", _id);

						if(s_reactions && (!m->reactions || strcmp(m->reactions, s_reactions))) {
							SWAPC(m->reactions, s_reactions);
							_pfx = m->reactions;
						}

						if(strcmp(m->msg, msg)) {
							SWAPC(m->msg, msg);
							_pfx = MSG_edited;

							if (mt && !strcmp(mt, "rm")) {
								_pfx = MSG_removed;
								_msg = msg;
							}
						}

						if (!_pfx)
							goto finished2;
					} else {
						sess__rc_add_message(s, _id, msg, username, s_reactions);
					}

					char *_dest = roomName;
					char _t = 'd';

					if (t && (*t == 'c' || *t == 'p')
					    && roomName) {
						_t = 'c';
					} else if (room
						 && !strcmp(username,
							    s->irc.nick)) {
					       _dest = room->name;
					} else {
						_dest = s->irc.nick;
					}

					sess__irc_send_message(s, _t,
							       username,
							       _dest,
							       _pfx,
							       _msg);

				}
finished2:

				IFFREE(msg);
				IFFREE(rid);
				IFFREE(username);
				IFFREE(roomName);
				IFFREE(t);
				IFFREE(mt);
				IFFREE(tmid);
			}
		}

	}

 finished:
	json_object_put(jobj);
	IFFREE(msg);
	IFFREE(_id);
	IFFREE(collection);
	IFFREE(selfuser);
	IFFREE(userid);
	IFFREE(username);
	IFFREE(roomName);

	return (0);
}

static int
callback_minimal_broker_2(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	int m;

	t_sess *s = lws_get_opaque_user_data(wsi);

	if (!s)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	if (s->rc.finished)
		return (-1);

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		logg(ERR, "CLIENT_CONNECTION_ERROR: %s\n",
		     in ? (char *)in : "(null)");
		s->rc.client_wsi = NULL;
		s->rc.finished = 1;
		sess__add_irc_out(s,
				  buff__sprintf("RocketChat connection error\r\n"));

		s->state |= STATE_SHUTTING_DOWN;
		if (s->rc.vhost && s->rc.protocol)
			lws_timed_callback_vh_protocol(s->rc.vhost,
						       s->rc.protocol,
						       LWS_CALLBACK_USER, 1);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		logg(DBG1, "%s: established\n", __func__);
		s->rc.established = 1;
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		logg(DBG4, "LWS_CALLBACK_CLIENT_WRITEABLE\n");
		t_buff *b = s->rc.out_buff;
		if (!b) {
			s->rc_poll->events = POLLIN;
			goto skip;
		}

		logg(DBG4, "RC-TX[%d]: %.*s\n", s->rc_poll->fd, b->left,
		     (const char *)b->buff + LWS_PRE);
		m = lws_write(wsi, ((unsigned char *)b->buff) + LWS_PRE,
			      b->left, LWS_WRITE_TEXT);
		if (m < (int)b->left) {
			logg(ERR, "ERROR %d writing to ws socket\n", m);
			return -1;
		}

		if (s->rc.out_buff_tail == &b->next) {
			s->rc.out_buff_tail = &s->rc.out_buff;
			s->rc_poll->events = POLLIN;
		} else {
			lws_callback_on_writable(wsi);
		}
		s->rc.out_buff = b->next;
		buff__free(b);
 skip:
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		logg(DBG1, "%s: LWS_CALLBACK_CLIENT_CLOSED\n", __func__);
		s->rc.client_wsi = NULL;
		s->rc.established = 0;
		s->rc.finished = 1;

		sess__add_irc_out(s,
				  buff__sprintf("RocketChat closing socket\r\n"));

		s->state |= STATE_SHUTTING_DOWN;
		lws_timed_callback_vh_protocol(s->rc.vhost, s->rc.protocol,
					       LWS_CALLBACK_USER, 1);
		break;

	case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
		if (s->rc.client_wsi && s->rc.established)
			lws_callback_on_writable(s->rc.client_wsi);
		break;

	case LWS_CALLBACK_USER:
		logg(DBG4, "%s: LWS_CALLBACK_USER\n", __func__);
		lws_timed_callback_vh_protocol(s->rc.vhost,
					       s->rc.protocol,
					       LWS_CALLBACK_USER, 1);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		logg(DBG4, "RC-RX[%d]: %s\n", s->rc_poll->fd, (const char *)in);

		sess__rc_work(s, in);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
	 "lws-minimal-broker",
	 callback_minimal_broker_2,
	 0,
	 65535,
	 0,
	 NULL,
	 },
	{NULL, NULL, 0, 0}
};

static void sigint_handler(int sig)
{
	interrupted = 1;
}

struct lws_pollfd irc_mainport_pollfd;
int irc_mainport = 6666;
int rc_port = 443;

int irc_mainport_bind()
{
	int sockopt;
	struct addrinfo *n, *no, hostinf;
	char sport[128];
	int r, sock;

	snprintf(sport, sizeof(sport), "%d", irc_mainport);

	memset(&hostinf, 0, sizeof(hostinf));

	hostinf.ai_family = AF_UNSPEC;
	hostinf.ai_socktype = SOCK_STREAM;
	hostinf.ai_flags = AI_PASSIVE;

	r = getaddrinfo(NULL, sport, &hostinf, &n);

	if (r || !n) {
		logg(ERR, "Cannot getaddrinfo socket %d\n", r);
		return (-2);
	}

	no = n;

	for (; n; n = n->ai_next) {
		sock = socket(n->ai_family, n->ai_socktype, n->ai_protocol);

		if (sock == -1) {
			logg(ERR, "Cannot create socket.. %d (%s)", errno,
			     strerror(errno));
			freeaddrinfo(no);
			return (-2);
		}

		sockopt = 1;

		if (setsockopt
		    (sock, SOL_SOCKET, SO_REUSEADDR, (void *)&sockopt,
		     sizeof(sockopt)) != 0) {
			logg(ERR, "error setting socket options (%s).",
			     strerror(errno));
			return (-1);
		}

		if (bind(sock, n->ai_addr, n->ai_addrlen) == 0)
			break;

		close(sock);

		sock = -1;
	}

	if (sock == -1) {
		logg(ERR, "Cannot create socket.\n");
		return (-3);
	}

	listen(sock, 5);

	return (sock);
}

t_buff *buff__new()
{
	t_buff *b;

	b = malloc(sizeof(*b));
	memset(b, 0, sizeof(*b));

	return (b);
}

void buff__free(t_buff * b)
{
	free(b->buff);
	free(b);
}

t_buff *buff__sprintf(const char *fmt, ...)
{
	va_list args;
	t_buff *b;

	b = buff__new();
	va_start(args, fmt);

	b->left = vasprintf(&b->buff, fmt, args);
	b->start = b->buff;

	return (b);
}

t_sess *sess_new()
{
	t_sess *s;

	s = malloc(sizeof(*s));
	memset(s, 0, sizeof(*s));
	s->irc_buff_head = 0;
	s->irc_out_buff_tail = &s->irc_out_buff;
	s->rc.out_buff_tail = &s->rc.out_buff;

	s->next = session_list;
	session_list = s;

	return (s);
}

void sess__add_irc_out(t_sess * s, t_buff * b)
{
	*s->irc_out_buff_tail = b;
	s->irc_out_buff_tail = &b->next;

	s->poll->events |= POLLOUT;
}

void gen_id(t_rc_id id)
{
	int r = rand();
	snprintf(id, sizeof(t_rc_id), "%014x", r);
}

int sess__rc_command_call(t_sess * s, void *data, json_object * json,
			  int (*fce)(t_sess * s, void *data, json_object * j))
{
	t_rc_id id;
	t_rc_command *cmd;

	gen_id(id);

	json_object_object_add(json, "id", json_object_new_string(id));

	cmd = NEW(t_rc_command);

	sess__add_rc_out(s, -1, json_object_to_json_string(json));

	cmd->data = data;
	cmd->fce = fce;
	memcpy(cmd->id, id, sizeof(id));

	cmd->next = s->rc.commands;
	s->rc.commands = cmd;

	return 0;
}

t_rc_room *sess__rc_room_add(t_sess * s, char t, const char *name,
			     const char *rid, const char *fname,
			     const char *topic)
{

	t_rc_room *room = sess__rc_room_by_rid(s, rid);
	if (room) {
		IFFREE(room->name);
		IFFREE(room->fname);
		IFFREE(room->topic);
		IFFREE(room->rid);
	} else {
		room = NEW(t_rc_room);
		room->next = s->rc.rooms;
		s->rc.rooms = room;
	}
	if (fname)
		room->fname = strdup(fname);
	if (name)
		room->name = strdup(name);
	if (topic)
		room->topic = strdup(topic);
	room->t = t;
	room->rid = strdup(rid);

	return (room);
}

t_rc_room *sess__rc_room_by_rid(t_sess * s, const char *rid)
{
	t_rc_room *r;

	for (r = s->rc.rooms; r && (strcmp(r->rid, rid)); r = r->next) ;

	return (r);
}

t_rc_room *sess__rc_room_by_name(t_sess * s, char t, const char *name)
{
	t_rc_room *r;

	for (r = s->rc.rooms; r && (r->t != t || strcmp(r->name, name));
	     r = r->next) ;

	return (r);
}

int sess__cb_rc_createdirect(t_sess * s, void *data, json_object * j)
{
	char *t = NULL, *rid = NULL, *msg = NULL;
	json_object *usernames;

	if (json_read
	    (NULL, j, "{result:{t:%s rid:%s usernames:%o}}", &t, &rid,
	     &usernames) == 3) {
		const char *name = NULL;

		for (int i = 0; i < json_object_array_length(usernames); i++) {
			json_object *un = json_object_array_get_idx(usernames, i);
			name = json_object_get_string(un);
			if (name && strcmp(name, s->irc.nick)) {
				break;
			}
		}
		if (!name)
			goto end;

		t_rc_room *room =
		    sess__rc_room_add(s, t[0], name, rid, NULL, NULL);

		room->next = s->rc.rooms;
		s->rc.rooms = room;
	} else {

		if (json_read(NULL, j, "{error:{message:%s}}", &msg) == 1) {
			sess__add_irc_out(s,
					  buff__sprintf("ERROR: %s\r\n", msg));
		}

	}

 end:
	IFFREE(t);
	IFFREE(rid);
	IFFREE(msg);

	sess__rc_queue_process(s);
	return 0;
}

void sess__add_sent_message(t_sess * s, const char *id)
{
	int l = strlen(id);
	t_rc_sndmsg *m = malloc(sizeof(t_rc_sndmsg) + l + 1);

	m->next = s->rc.sent;
	s->rc.sent = m;

	strcpy(m->id, id);
}

int sess__find_sent_message(t_sess * s, const char *id)
{
	for (t_rc_sndmsg * m = s->rc.sent; m; m = m->next)
		if (!strcmp(m->id, id))
			return 1;

	return (0);
}

int sess__cb_rc_sendmessage(t_sess * s, void *data, json_object * j)
{
	char *_id = NULL;
	if ((json_read(NULL, j, "{result:{_id:%s}}", &_id)) != 1) {
		return 0;
	}

	sess__add_sent_message(s, _id);

	IFFREE(_id);
	return 0;
}

int sess__cb_rc_getsubscriptions(t_sess * s, void *data, json_object * j)
{
	logg(ERR, "CALLBACK - SUBS \n");
	json_object *res;

	if (json_read(NULL, j, "{result:%o}", &res) != 1) {
		logg(ERR, "Malformed reply\n");
		goto error;
	}

	int sublen = json_object_array_length(res);

	for (int i = 0; i < sublen; i++) {
		json_object *o = json_object_array_get_idx(res, i);

		char *fname = NULL, *rid = NULL, *name =
		    NULL, *t = NULL;

		if (json_read(NULL, o, "{fname:%s rid:%s name:%s t:%s}",
			      &fname, &rid, &name, &t) != 4) {

			logg(ERR, "Invalid sub record\n");
			continue;
		}

		sess__rc_room_add(s, t[0], name, rid, fname, NULL);

		IFFREE(fname);
		IFFREE(t);
		IFFREE(rid);
		IFFREE(name);

	}

	for (t_rc_room * r = s->rc.rooms; r; r = r->next) {
		if (r->t == 'c' || r->t == 'p')
			sess__rc_join_room(s, r->t, r->name);
	}

	return 0;
 error:
	return -1;
}

int sess__cb_rc_login(t_sess * s, void *data, json_object * j)
{
	logg(ERR, "CALLBACK - LOGIN\n");

	char *reason = NULL;
	int error;

	if (json_read(NULL, j, "{error:{error:%d reason:%s}}", &error, &reason)
	    == 2 && error) {
		sess__add_irc_out(s,
				  buff__sprintf("RocketChat Error %d: %s\r\n", error,
						reason));

		s->state |= STATE_SHUTTING_DOWN;
		IFFREE(reason);
	}
	return 0;
}

int sess__rc_command_call_(t_sess * s, void *data, json_object * json,
			   int (*fce)(t_sess * s, void *data, json_object * j))
{
	int r = sess__rc_command_call(s, data, json, fce);
	json_object_put(json);
	return (r);
}

int sess__rc_json_send_(t_sess * s, json_object * json)
{
	const char *c = json_object_to_json_string(json);
	int r = sess__add_rc_out(s, -1, c);
	json_object_put(json);
	return (r);
}

int sess__rc_start(t_sess * s, struct lws_context *ctx)
{
	if (s->rc_poll) {
		logg(ERR, "RC session already started");
		return 2;
	}
	s->rc.context = ctx;
	s->rc.i.context = ctx;
	s->rc.i.port = rc_port;
	s->rc.i.address = server_name;
	s->rc.i.path = "/websocket";
	s->rc.i.host = s->rc.i.address;
	s->rc.i.origin = s->rc.i.address;
	s->rc.i.opaque_user_data = s;
	s->rc.i.ssl_connection = LCCSCF_USE_SSL;

	s->rc.i.protocol = "lws-minimal-broker";
	s->rc.i.pwsi = &s->rc.client_wsi;

	struct lws *ws = lws_client_connect_via_info(&s->rc.i);

	if (!ws) {
		logg(ERR, "Error in lws_client_connect_via_info\n");
		return 1;
	}

	int fd = lws_get_socket_fd(ws);

	logg(ERR, "FD=%d\n", fd);

	s->rc_poll = &pollfds[poll_addfd(fd, s, POLLIN | POLLOUT)];

	sess__rc_json_send_(s,
			    json_create(NULL,
					"{msg:%s version:%s support:[%s]}",
					"connect", "1", "1"));

	sess__rc_command_call_(s, NULL,
			       json_create(NULL,
					   "{msg:%s method:%s params:[{resume:%s}]}",
					   "method", "login", s->rc.token),
			       sess__cb_rc_login);

	sess__rc_command_call_(s, NULL,
			       json_create(NULL, "{msg:%s method:%s params:[]}",
					   "method", "subscriptions/get"),
			       sess__cb_rc_getsubscriptions);

	sess__rc_command_call_(s, NULL,
			       json_create(NULL,
					   "{msg:%s name:%s params:[%s %b]}",
					   "sub", "stream-room-messages",
					   "__my_messages__", 0), NULL);

	s->rc.context = lws_get_context(ws);
	s->rc.protocol = lws_get_protocol(ws);
	s->rc.vhost = lws_get_vhost(ws);

	return 0;
}

int sess__irc_nick_set(t_sess * s, const char *newnick)
{
	sess__add_irc_out(s,
			  buff__sprintf(":%s NICK %s\r\n", s->irc.nick,
					newnick));
	IFFREE(s->irc.nick);
	s->irc.nick = strdup(newnick);

	return 0;
}

int sess__irc_send_message(t_sess * s, char t, const char *srcname,
			   const char *name, char *pfx, char *msg)
{
	int r = 0;
	char pmsg[2];
	char *next, *start;

	if (t == 'c') {
		pmsg [0] = '#';
		pmsg [1] = '\0';
	} else
		pmsg [0] = '\0';


	start = msg;
	while (1) {
		next = strchr(start, '\n');
		if (next) *next = '\0';

		if (! pfx)
			sess__add_irc_out(s,
					  buff__sprintf(":%s PRIVMSG %s%s :%s\r\n",
						srcname, pmsg, name, start));
		else
			sess__add_irc_out(s,
					  buff__sprintf(":%s PRIVMSG %s%s :\x02%s\x0f %s\r\n",
						srcname, pmsg, name, pfx, start));

		if (! next || !(*(next+1))) break;
		else start = next + 1;
	}

	return r;
}

int sess__cb_rc_getusers(t_sess * s, void *data, json_object * j)
{
	t_rc_room *r = (t_rc_room *) data;
	char buff[512], *b = buff;

	buff[0] = 0;

	json_object *records;

	if ((json_read(NULL, j, "{result:{records:%o}}", &records)) != 1)
		return 0;

	int cnt_args = json_object_array_length(records);
	for (int i = 0; i < cnt_args; i++) {
		json_object *n, *p = json_object_array_get_idx(records, i);

		n = json_object_object_get(p, "username");
		if (n) {
			const char *st = json_object_get_string(n);
			b = stpncpy(b, st, buff + sizeof(buff) - b);
			b = stpncpy(b, " ", buff + sizeof(buff) - b);
		}
	}
	*b = 0;
	sess__add_irc_out(s, buff__sprintf(":%s 353 %s = #%s :%s\r\n",
					   selfident, s->irc.nick, r->name,
					   buff));
	sess__add_irc_out(s,
			  buff__sprintf(":%s 366 %s #%s :End of NAMES list\r\n",
					selfident, s->irc.nick, r->name));

	return 0;
}

int sess__cb_rc_joinroom(t_sess * s, void *data, json_object * j)
{
	t_rc_room *r = (t_rc_room *) data;

	sess__add_irc_out(s, buff__sprintf(":%s JOIN #%s\r\n",
					   s->irc.nick, r->name));
	sess__add_irc_out(s, buff__sprintf(":%s 332 %s #%s :%s\r\n",
					   selfident, s->irc.nick, r->name,
					   r->topic ? r->topic : ""));

	sess__rc_command_call_(s, r,
			       json_create(NULL,
					   "{msg:%s method:%s params:[%s %b {limit:%d skip:%d} %s]}",
					   "method", "getUsersOfRoom", r->rid,
					   0, 100, 0, ""),
			       sess__cb_rc_getusers);

	return 0;
}

int sess__cb_rc_getroom(t_sess * s, void *data, json_object * j)
{
	int r;

	char *_id = NULL, *t = NULL, *name = NULL, *fname = NULL, *topic = NULL;

	if ((r =
	     json_read(NULL, j,
		       "{result:{_id:%s name:%s fname:%s t:%s topic?%s}}", &_id,
		       &name, &fname, &t, &topic)) < 4)
		goto err;

	t_rc_room *room = sess__rc_room_add(s, *t, name, _id, fname, topic);

	sess__rc_command_call_(s, room,
			       json_create(NULL,
					   "{msg:%s method:%s params:[%s %o]}",
					   "method", "joinRoom", _id, NULL),
			       sess__cb_rc_joinroom);
 err:
	IFFREE(_id);
	IFFREE(t);
	IFFREE(name);
	IFFREE(fname);
	IFFREE(topic);
	return 0;
}

int sess__rc_join_room(t_sess * s, char t, const char *name)
{
	char tt[2];
	tt[0] = t;
	tt[1] = '\0';

	if (t == 'd')
		sess__rc_command_call_(s, NULL,
				       json_create(NULL,
						   "{msg:%s method:%s params:[%s]}",
						   "method",
						   "createDirectMessage", name),
				       sess__cb_rc_createdirect);
	else
		sess__rc_command_call_(s, NULL,
				       json_create(NULL,
						   "{msg:%s method:%s params:[%s %s]}",
						   "method",
						   "getRoomByTypeAndName", tt,
						   (*name ==
						    '#') ? (name + 1) : name),
				       sess__cb_rc_getroom);
	return 0;
}

int sess__rc_queue_message(t_sess * s, char t, const char *name,
			   const char *msgs)
{
	t_rc_message *msg, **m;

	for (m = &s->rc.messages; *m; m = &(*m)->next) ;

	msg = NEW(t_rc_message);
	msg->t = t;
	msg->dstname = strdup(name);
	msg->msg = strdup(msgs);

	*m = msg;

	return 0;
}

static int rc_message_cmpid(const t_rc_message *a, const t_rc_message *b)
{
	return strcmp(a->id, b->id);
}

t_rc_message *sess__rc_add_message(t_sess *s, const char *id, const char *msg,
				   const char *sender, const char *reactions)
{
	t_rc_message *m;

	m = NEW(t_rc_message);

	m->id = strdup(id);
	m->msg = STRDUP(msg);
	m->sender = STRDUP(sender);
	m->reactions = STRDUP(reactions);

	m->next = s->rc.in_messages;
	s->rc.in_messages = m;
	tsearch((void*)m, (void**)&s->rc.in_messages_tree,
		(int(*)(const void *, const void*))rc_message_cmpid);

	return m;
}

t_rc_message *sess__rc_find_message(t_sess *s, const char *id)
{

	t_rc_message **m = NULL;
	t_rc_message fm;
	fm.id = id;

	m = (t_rc_message**)tfind((void*)&fm, (void**)&s->rc.in_messages_tree,
		 (int(*)(const void *, const void*))rc_message_cmpid);

	if (m) return (*m);
	else return (NULL);

}

void rc_message__free(t_rc_message * m)
{
	IFFREE(m->dstname);
	IFFREE(m->reactions);
	IFFREE(m->msg);
	IFFREE(m);
}

int sess__rc_queue_process(t_sess * s)
{
	t_rc_message *msg, **m;

	for (m = &s->rc.messages; (msg = *m); m = &(*m)->next) {
		if (!sess__rc_send_message(s, msg->t, msg->dstname, msg->msg)) {
			*m = (*m)->next;

			rc_message__free(msg);
		}
	}
	return 0;
}

int sess__rc_send_message(t_sess * s, char t, const char *name, const char *msg)
{
	t_rc_room *room;

	room = sess__rc_room_by_name(s, t, name);
	if (!room && t == 'c')
		room = sess__rc_room_by_name(s, 'p', name);
	if (!room) {
		logg(ERR, "Room %c:%s NOT FOUND, not supported atm\n", t, name);
		return (EROOMNOTFOUND);
	}

	sess__rc_command_call_(s, NULL,
			       json_create(NULL,
					   "{msg:%s method:%s params:[{rid:%s msg:%s}]}",
					   "method", "sendMessage", room->rid,
					   msg), sess__cb_rc_sendmessage);

	return 0;
}

int sess__rc_set_away(t_sess * s, const char *msg)
{

	if (!msg) {
		logg(DBG3, "Setting back\n");
		sess__rc_set_back(s);
	}
	else {
		logg(DBG3, "Setting away\n");
		sess__rc_command_call_(s, NULL,
				json_create(NULL,
					"{msg:%s method:%s params:[%s]}",
					"method",
					"setUserStatus", "away"),
				sess__cb_rc_set_away);
	}
	return 0;
}

int sess__rc_set_back(t_sess * s)
{
	sess__rc_command_call_(s, NULL,
			json_create(NULL,
				"{msg:%s method:%s params:[%s]}",
				"method",
				"setUserStatus", "online"),
			sess__cb_rc_set_back);
	return 0;
}

int sess__cb_rc_set_away(t_sess * s, void *data, json_object * j)
{
	char buff[512];

	sess__add_irc_out(s, buff__sprintf(":%s 306 :You have been marked as being away\r\n",
				selfident, buff));
	return 0;
}

int sess__cb_rc_set_back(t_sess * s, void *data, json_object * j)
{
	char buff[512];

	sess__add_irc_out(s, buff__sprintf(":%s 305 :You are no longer marked as being away\r\n",
				selfident, buff));
	return 0;
}

int sess__free(t_sess * s)
{
	t_sess **d;
	for (d = &session_list; *d && *d != s; d = &(*d)->next);

	*d = s->next;

	tdestroy((void*)s->rc.in_messages_tree, (void(*)(void*))rc_message__free);

	/* TODO: add pretty much all freeing !!! */
	free(s);

	return 0;
}

int sess__close(t_sess * s)
{
	logg(DBG1, "Closing session FDs %d,%d\n", s->poll->fd,
	     s->rc_poll?s->rc_poll->fd:-1);

	shutdown(s->poll->fd, SHUT_RDWR);
	close(s->poll->fd);
	s->rc.finished = 1;
	if (s->rc_poll) {
		shutdown(s->rc_poll->fd, SHUT_RDWR);
		close(s->rc_poll->fd);
		lws_service_fd(s->rc.context, s->rc_poll);
	}
	for (int i = 0; i <= maxfds; i++) {
		if (&pollfds[i] == s->poll) {
			poll_removefd(i);
			break;
		}
	}
	for (int i = 0; i <= maxfds; i++) {
		if (&pollfds[i] == s->rc_poll) {
			poll_removefd(i);
			break;
		}
	}

	return 0;
}

int irc__process(t_sess * s, struct lws_context *ctx)
{
	int st = 0;
	char *c, *end, *b;
	char *command;

	for (c = s->irc_buff; c < s->irc_buff + s->irc_buff_head && st != 2;
	     c++) {
		switch (*c) {
		case '\r':
			st = 1;
			break;
		case '\n':
	//		if (st == 1)
				st = 2;
			break;
		default:
			st = 0;
		}
		if (st == 2)
			break;
	}

	if (st != 2)
		return 1;

	if (c > s->irc_buff && (*(c-1) == '\r')) *(c - 1) = '\0';
			else
	*(c ) = '\0';
	end = c;

	logg(DBG2, "IRC received: %s\n", s->irc_buff);

	b = s->irc_buff;
	c = strchr(b, ' ');
	if (!c) {
		logg(DBG3, "IRC command without parameter\n");
		goto skip_parsing;
	}
	*c = '\0';

	if (*b == ':') {

		c = strchr(c + 1, ' ');
		if (!c) {
			logg(ERR, "Can\'t find #2 space\n");
			goto error_parsing;
		}
		b = c + 1;
		*c = '\0';
	} else {
	}
	c += 1;
skip_parsing:
	command = b;

	logg(ERR, "command \'%s\'\n", command);
	if (c && !strcmp(command, "NICK")) {
		if (!s->irc.nick || !strcmp(s->irc.nick, c)) {
			sess__add_irc_out(s,
					  buff__sprintf
					  (":%s 001 %s :Welcome to the Internet Relay Network %s\r\n",
					   selfident, c, c));
			sess__add_irc_out(s,
					  buff__sprintf
					  
 (":myserver 002 alnovak Your host is localhost, running version 1\r\n"
                        ":myserver 003 alnovak This server was created Tue Oct 22, 16:00:54 UTC\r\n"
                        ":myserver 004 alnovak localhost 1 oirw abeIiklmnopqstv\r\n"
					   ":%s 375 %s :%s message of the day\r\n"
					   ":%s 372 %s :RocketChat->IRC gateway!\r\n"
					   ":%s 376 %s :End of message of the day.\r\n",
					   selfident, c, selfident,
					   selfident, c,
					   selfident, c));

			IFFREE(s->irc.nick);
			s->irc.nick = strdup(c);
		}

	} else if (!strcmp(command, "USER")) {
		/* TODO */
	} else if (c && !strcmp(command, "PING")) {
		sess__add_irc_out(s, buff__sprintf(":%s PONG %s :%s\r\n", selfident, selfident, c));
	} else if (c && (!strcmp(command, "PASS") || !strcmp(command, "IDENTIFY"))) {
		IFFREE(s->rc.token);
		if (*c == ':') c++;
		s->rc.token = strdup(c);
		sess__rc_start(s, ctx);
	} else if (c && !strcmp(command, "PRIVMSG")) {
		char *msg = strchr(c, ' ');
		char t;
		logg(DBG3, "PRIVMSG->msg = %p,c = %s\n", msg, c);
		if (!msg)
			goto error_parsing;
		*(msg++) = '\0';
		if (*msg == ':')
			msg++;

		t = (*c == '#') ? 'c' : 'd';
		if (t == 'c')
			c++;

		if (sess__rc_send_message(s, t, c, msg) == EROOMNOTFOUND) {
			sess__rc_join_room(s, t, c);
			sess__rc_queue_message(s, t, c, msg);
		}
	} else if (!strcmp(command, "WHO")) {
		/* TODO */
	} else if (c && !strcmp(command, "JOIN")) {
		sess__rc_join_room(s, 'c', c);
	} else if (!strcmp(command, "AWAY")) {
		sess__rc_set_away(s, c);
	} else if (!strcmp(command, "QUERY")) {
		sess__rc_join_room(s, 'd', c);
	} else if (!strcmp(command, "QUIT")) {
		shutdown(s->poll->fd, SHUT_RDWR);
		shutdown(s->rc_poll->fd, SHUT_RDWR);
	} else {
		logg(ERR, "Unrecognized command %s\n", command);
	}

 error_parsing:
	memcpy(s->irc_buff, end + 1,
	       s->irc_buff + s->irc_buff_head - (end + 1));
	s->irc_buff_head -= (end - s->irc_buff + 1);

	return 0;
}
static const char *doc_usage = 
	"Usage: %s [options] <RC server hostname>\n"
	"Options:\n"
	"\t-h\tshows this help\n"
	"\t-d\tincreases logging verbosity, can be used repeatedly\n"
	"\t-l\tIRC listen port (%d)\n"
	"\t-p\tRC server port (%d)\n\n";

int main(int argc, char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	int showhelp = 0;
	int logmask = 1, c;

	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;

	while ((c = getopt(argc, argv, "hdl:p:")) != -1) {
		switch (c) {
			case 'h':
				showhelp = 1;
				break;
			case 'd':
				logmask++;
				break;
			case 'l':
				irc_mainport = atoi(optarg);
				break;
			case 'p':
				rc_port = atoi(optarg);
				break;
			case '?':
				logg(ERR, "Unknown argument '%c'\n",
						optopt);
				showhelp = 2;
				break;
			default:
				logg(ERR, "getopt error (%d,%s)\n",
						optopt,
						optarg?optarg:"<null>");
		}
	}

	if (argc < 2 || argc != optind + 1 || showhelp) {
		fprintf(stderr, doc_usage, argv[0], irc_mainport, rc_port);
		return 1;
	} else
		server_name = (char*)argv[optind];

	logg_setmask((1<<logmask)-1);

	signal(SIGINT, sigint_handler);

	lws_set_log_level(logs, NULL);

	memset(&info, 0, sizeof info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.protocols = protocols;

	info.fd_limit_per_thread = 128;
	memset(pollfds, 0, sizeof(pollfds));
	memset(sessions, 0, sizeof(t_sess *) * MAXFD);
	if ((pollfds[0].fd = irc_mainport_bind()) < 0) {

		return 1;
	}

	pollfds[0].events = POLLIN;
	maxfds = 1;

	context = lws_create_context(&info);
	if (!context) {
		logg(ERR, "lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted) {
		int ret;

		ret = poll(pollfds, maxfds, 10000);

		if (ret > 0 && pollfds[0].revents == POLLIN) {
			/* new connection on the IRC port */
			struct sockaddr_in cl_addr;
			socklen_t cl_len;

			int newfd =
			    accept(pollfds[0].fd,
				   (struct sockaddr *)&cl_addr,
				   (socklen_t *) & cl_len);

			logg(DBG1, "spawning new fd %d\n", newfd);

			pollfds[maxfds].fd = newfd;
			pollfds[maxfds].events = POLLIN | POLLNVAL;
			pollfds[maxfds].revents = 0;

			t_sess *sess = sess_new();
			sess->poll = &pollfds[maxfds];
			sess->irc_fd = newfd;

			sessions[maxfds] = sess;

			maxfds++;

			ret--;
		}


		for (int i = 0; i < maxfds && ret > 0; i++) {
			t_sess *s = sessions[i];

			if (pollfds[i].revents == 0)
				continue;
			ret--;

			if (s && pollfds[i].revents & (POLLNVAL | POLLERR)) {
				sess__close(s);
				sess__free(s);
				continue;
			}

			if (s && s->irc_fd == pollfds[i].fd) {
				logg(DBG4, "gotcha [%d] %d -> %d\n", pollfds[i].fd, pollfds[i].events, pollfds[i].revents);
				if (pollfds[i].revents & POLLIN) {
					/* IRC RX */
					int r =
					    recv(pollfds[i].fd,
						 s->irc_buff + s->irc_buff_head,
						 sizeof(s->irc_buff) -
						 (unsigned long long)s->
						 irc_buff_head, 0);

					logg(DBG4, "IRC-RX[%d]: %.*s\n", pollfds[i].fd, r,
					     s->irc_buff + s->irc_buff_head);

					if (r == 0 || pollfds[i].revents & POLLHUP) {
						logg(DBG1,"Going to close %d+%d\n", pollfds[i].fd, pollfds[s->rc.fd_idx].fd);
						shutdown(pollfds[i].fd,
							 SHUT_RDWR);
						close(pollfds[i].fd);
						s->rc.finished = 1;
						if (s->rc_poll)
							lws_service_fd(context,
								       s->
								       rc_poll);
						sess__close(s);
						sess__free(s);
						continue;

					} else if (r == -1) {
						perror("what's the issue?");
						exit(1);
					}

					s->irc_buff_head += r;

					while (!irc__process(s, context)) ;

				} else if (pollfds[i].revents & POLLOUT) {
					if (!s->irc_out_buff) {
						pollfds[i].events &= ~POLLOUT;

						if (s->state & STATE_SHUTTING_DOWN) {
							if (s->poll) shutdown(s->poll->fd, SHUT_RDWR);
							if (s->rc_poll) shutdown(s->rc_poll->fd, SHUT_RDWR);
						}
					} else {
						int r =
						    send(pollfds[i].fd,
							 s->irc_out_buff->start,
							 s->irc_out_buff->left,
							 0);

						if (r == -1) {
							perror("Can't send\n");
							exit(1);

						}
						logg(DBG4, "IRC-TX[%d]: %.*s\n",
								pollfds[i].fd,
								r,
								s->irc_out_buff->start);

						s->irc_out_buff->start += r;
						s->irc_out_buff->left -= r;

						if (!s->irc_out_buff->left) {
							t_buff *b =
							    s->irc_out_buff->
							    next;
							buff__free(s->
								   irc_out_buff);
							s->irc_out_buff = b;
							if (b == NULL) {
								s->irc_out_buff_tail = &s->irc_out_buff;
							}
						}

					}

				} else {
					logg(DBG1,"TODO[%d]: -> %x\n", pollfds[i].fd, pollfds[i].revents);
				}
			} else {
				logg(DBG4, "gotcha-2 [%d] %d -> %d\n", pollfds[i].fd, pollfds[i].events, pollfds[i].revents);
				int ret = lws_service_fd(context, &pollfds[i]);
				if (ret) {
					logg(ERR,"lws_service_fd(%d)... %d:\n",  pollfds[i].fd, ret);
					sessions[i]->rc.finished = 1;
					sessions[i]->state |= STATE_SHUTTING_DOWN;
					sess__add_irc_out(sessions[i],
							  buff__sprintf("RocketChat connection error (%d)\r\n", ret));

				}
			}
			pollfds[i].revents = 0;

		}

		time_t now = time(NULL);

		for (t_sess *s = session_list; s; s = s->next) {
			if (s->rc.last_ping && (now - s->rc.last_ping) > rc_timeout && !(s->state & STATE_SHUTTING_DOWN)) {
				sess__add_irc_out(s,
						buff__sprintf("RocketChat server didn't ping us in %d secs, closing\r\n",
							now - s->rc.last_ping));
				s->state |= STATE_SHUTTING_DOWN;
			}
		}
	}

	lws_context_destroy(context);
	logg(DBG1, "Completed\n");

	return 0;
}
