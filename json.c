#define _GNU_SOURCE
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <strings.h>
#include <json-c/json.h>
#include "util.h"

int json_read(void *data, struct json_object *object, const char *fmt, ...)
{
	va_list args;
	struct jc_stack {
		struct json_object *o;
		int isarray;
		struct jc_stack *firstchild, *parent;
	};

	const char *c;
	char z;
	int cnt = 0;
	int mode = 0;
	char objname[32];
	int on_i = 0;

	struct jc_stack *root = alloca(sizeof(struct jc_stack)), *top =
	    root, *n;
	top->parent = NULL;
	top->o = object;
	struct json_object *curr = NULL;

	va_start(args, fmt);

	for (c = fmt; (z = *c); c++) {
		if (mode == 5) {
			mode = 0;
			va_arg(args, void*);
			continue;
		} else if (mode == 3) {

			switch (z) {
			case 'o':
				{
					json_object *v = curr;
					*(json_object **) va_arg(args,
								 json_object **)
					    = v;
					cnt++;
				}
				break;
			case 'b':
				{
					int v = json_object_get_boolean(curr);
					*(int *)va_arg(args, int *) = v;
					cnt++;
				}
				break;
			case 'd':
				{
					int v = json_object_get_int(curr);
					*(int *)va_arg(args, int *) = v;
					cnt++;
				}
				break;
			case 's':
				{
					const char *v =
					    json_object_get_string(curr);
					*(const char **)va_arg(args,
							       const char **) =
					    strdup(v);
					cnt++;
				}
				break;
			default:
				logg(ERR, "Wrong usage\n");
				goto error;
			}
			while (top->o == curr && top->parent)
				top = top->parent;
			curr = top->o;
			mode = 0;
			continue;
		} else if (mode == 7) {
			int r = 0;

			switch (z) {
			case 'b':
				{
					int v = json_object_get_boolean(curr);
					if ((int)va_arg(args, int) != v)
						 r = -1;
				}
				break;
			case 'd':
				{
					int v = json_object_get_int(curr);
					if ((int)va_arg(args, int) != v)
						 r = -1;
				}
				break;
			case 's':
				{
					const char *v =
					    json_object_get_string(curr);
					if (strcmp
					    ((const char *)
					     va_arg(args, const char *), v))
						 r = -1;
				}
				break;
			default:
				fprintf(stderr, "Wrong usage\n");
				goto error;
			}
			if (r == -1)
				goto error;
			while (top->o == curr && top->parent)
				top = top->parent;
			curr = top->o;
			mode = 0;
			continue;
		}

		switch (z) {
		case '[':
			n = alloca(sizeof(struct jc_stack));
			n->parent = top;
			if (!curr)
				curr = object;
			n->o = curr;
			n->isarray = 1;
			top->firstchild = n;
			top = n;
			break;
		case ']':
			top = top->parent;
			curr = top->o;
			break;
		case '{':
			n = alloca(sizeof(struct jc_stack));
			n->parent = top;
			if (!curr)
				curr = object;
			n->o = curr;
			n->isarray = 0;
			top->firstchild = n;
			top = n;
			break;
		case '}':
			while (top->o == curr && top->parent)
				top = top->parent;
			curr = top->o;
			break;
		case ' ':
			break;

		case '?':
		case '=':
		case ':':
			objname[on_i] = '\0';

			mode = (z == '=') ? 6 : 1;

			on_i = 0;

			n = alloca(sizeof(struct jc_stack));
			n->parent = top;

			if (top->isarray) {
				n->o =
				    json_object_array_get_idx(curr,
							      (top->isarray -
							       1));
				top->isarray++;
			} else {
				n->o = json_object_object_get(curr, objname);
			}
			if (!n->o) {
				logg(DBG3, "No member named [%p] \'%s\'\n",
				     curr, objname);
				if (z == '?') {
					mode = 4;
					break;
				} else
					goto error;
			}

			if (!top->firstchild)
				top->firstchild = n;
			n->isarray = 0;
			top = n;
			curr = n->o;

			break;
		case '%':
			if (mode == 4)
				mode = 5;
			else if (mode == 6)
				mode = 7;
			else
				mode = 3;
			break;
		default:
			if (on_i >= sizeof(objname)) {
				logg(DBG1, "Too long objname");
				goto error;
			}
			objname[on_i++] = z;
		}
	}
	va_end(args);

	return (cnt);
 error:
	va_end(args);
	return -1;

}

struct json_object *json_create(void *data, const char *fmt, ...)
{
	va_list args;
	struct jc_stack {
		json_object *o;
		int isarray;
		char *name;
		struct jc_stack *firstchild, *parent;
	};

	const char *c;
	char z;
	int mode = 0;
	char objname[32];
	int on_i = 0;

	struct jc_stack *root = alloca(sizeof(struct jc_stack)), *top =
	    root, *n;
	top->parent = NULL;
	top->o = NULL;

	va_start(args, fmt);

	for (c = fmt; (z = *c); c++) {
		if (mode == 3) {
			struct json_object *s;

			switch (z) {
			case 'b':
				s = json_object_new_boolean(va_arg(args, int));
				break;
			case 'd':
				s = json_object_new_int(va_arg(args, int));
				break;
			case 's':
				s = json_object_new_string(va_arg
							   (args, char *));
				break;
			case 'o':
				s = va_arg(args, json_object *);
				break;
			default:
				logg(DBG1, "Wrong usage\n");
				goto error;
			}
			if (top->isarray)
				json_object_array_add(top->o, s);
			else
				json_object_object_add(top->o, top->name, s);
			mode = 0;
			continue;
		}
		switch (z) {
		case '[':
			n = alloca(sizeof(struct jc_stack));
			n->parent = top;
			n->name = NULL;
			n->o = json_object_new_array();
			n->isarray = 1;
			top->firstchild = n;
			top = n;
			break;
		case ']':
			if (top->parent->o) {
				if (top->parent->isarray)
					json_object_array_add(top->parent->o,
							      top->o);
				else
					json_object_object_add(top->parent->o,
							       top->parent->
							       name, top->o);
			}
			top = top->parent;
			break;
		case '{':
			n = alloca(sizeof(struct jc_stack));
			n->parent = top;
			n->name = NULL;
			n->o = json_object_new_object();
			n->isarray = 0;
			top->firstchild = n;
			top = n;
			break;
		case '}':
			if (top->parent->o) {
				if (top->parent->isarray)
					json_object_array_add(top->parent->o,
							      top->o);
				else
					json_object_object_add(top->parent->o,
							       top->parent->
							       name, top->o);
			}
			top = top->parent;
			break;
		case ' ':
			break;

		case ':':
			objname[on_i] = '\0';
			top->name = strdupa(objname);
			mode = 1;
			on_i = 0;
			break;
		case '%':
			mode = 3;
			break;
		default:
			if (on_i >= sizeof(objname)) {
				logg(DBG3, "Too long objname");
				goto error;
			}
			objname[on_i++] = z;
		}
	}
	va_end(args);

	while (top->parent && top->parent->o) {
		top = top->parent;
	}
	return (root->firstchild->o);
 error:
	va_end(args);
	return NULL;
}

#ifdef _JSON_TEST
int main(int argc, char **argv)
{

	struct json_object *o;

	printf("==== TEST 1 ====\n");
	o = json_create(NULL,
			"{ahoj:%s id:%d arr:[%b [] %b] o:{p1:%d p2:%s p3:%o}}",
			"cau", 4, 6, 0, 456, "sst", NULL);

	printf("S=%s\n", json_object_to_json_string(o));

	char *s = NULL, *p2 = NULL;

	printf("==== TEST 2 ====\n");
	int r = json_read(NULL, o, "{ahoj:%s o:{p2:%s}}", &s, &p2);

	printf("r=%d,s=%s,p2=%s\n", r, s, p2);

	json_object *jo =
	    json_tokener_parse
	    ("{\"msg\":\"changed\",\"collection\":\"stream-notify-user\",\"id\":\"id\",\"fields\":{\"eventName\":\"RCdeuvCAQb7sFwbPA/notification\",\"args\":[{\"title\":\"Lesslie Nengu\",\"text\":\"Basically they want to close the case  (to which bug is connected).\",\"payload\":{\"_id\":\"EXBbjGxve9ha5Bpwv\",\"rid\":\"RCdeuvCAQb7sFwbPAWEjesNXpKc9HzxKYZ\",\"sender\":{\"_id\":\"WEjesNXpKc9HzxKYZ\",\"username\":\"amuddy2\"},\"type\":\"d\",\"message\":{\"msg\":\"Basically the...\"}}}]}}");

	char *msg = NULL, *collection = NULL, *fields = NULL, *rid = NULL;

	printf("==== TEST 3 ====\n");

	if ((r =
	     json_read(NULL, jo, "{msg:%s collection:%s fields:{args:%o}}",
		       &msg, &collection, &fields, &rid)) == 3) {
		printf("ok\n");
		printf("len=%d\n", json_object_array_length(fields));
	} else {
		printf("err %d\n", r);
	}

	jo = json_tokener_parse("{"
				"    \"collection\": \"stream-notify-user\","
				"    \"fields\": {"
				"        \"args\": ["
				"            \"removed\","
				"            {"
				"                \"_id\": \"hiZESKwWkeJFsCMxH\","
				"                \"rid\": \"HaHmdy4mmfmStKvQR\","
				"                \"u\": {"
				"                    \"_id\": \"RCdeuvCAQb7sFwbPA\","
				"                    \"name\": \"Bilbo Baggins\","
				"                    \"username\": \"merkele\""
				"                }"
				"            }"
				"        ],"
				"        \"eventName\": \"RCdeuvCAQb7sFwbPA/subscriptions-changed\""
				"    },"
				"    \"id\": \"id\","
				"    \"msg\": \"changed\"" "}");

	rid = NULL;
	printf("==== TEST 4 ====\n");

	r = json_read(NULL, jo, "{msg=%s fields:{args:[=%s :{rid:%s}]} }",
		      "changed", "removed", &rid);
	printf("R=%d,rid=%s\n", r, rid);

	jo = json_tokener_parse("{\n"
				"    \"collection\": \"stream-room-messages\",\n"
				"    \"fields\": {\n"
				"        \"args\": [\n"
				"            {\n"
				"                \"_id\": \"BtMxjQzX7TGQhRNxN\",\n"
				"                \"_updatedAt\": {\n"
				"                    \"$date\": 1602361705261\n"
				"                },\n"
				"                \"groupable\": false,\n"
				"                \"msg\": \"zelele\",\n"
				"                \"rid\": \"HaHmdk4mmzmStKvQR\",\n"
				"                \"t\": \"uj\",\n"
				"                \"ts\": {\n"
				"                    \"$date\": 1602361705241\n"
				"                },\n"
				"                \"u\": {\n"
				"                    \"_id\": \"farmZrGcK269cKCP2\",\n"
				"                    \"name\": \"Miklos Vajna\",\n"
				"                    \"username\": \"zelele\"\n"
				"                }\n"
				"            },\n"
				"            {\n"
				"                \"roomName\": \"rc-learn-aanovak-4\",\n"
				"                \"roomParticipant\": true,\n"
				"                \"roomType\": \"c\"\n"
				"            }\n"
				"        ],\n"
				"        \"eventName\": \"__my_messages__\"\n"
				"    },\n"
				"    \"id\": \"id\",\n"
				"    \"msg\": \"changed\"\n" "}\n");

	printf("==== TEST 5 ====\n");
	char *username, *roomName;
	r = json_read(NULL, jo,
		      "{collection=%s msg=%s fields:{args:[:{t=%s u:{username:%s}} :{roomName:%s}]}}",
		      "stream-room-messages", "changed", "uj", &username,
		      &roomName);
	printf("R=%d,username=%s,roomName=%s\n", r, username, roomName);

	printf("==== TEST 6 ====\n");
	jo = json_tokener_parse("{\n"
			"                \"_id\": \"Rs9iRsadaasdhGHx\",\n"
			"                \"_updatedAt\": {\n"
			"                    \"$date\": 1602491275690\n"
			"                },\n"
			"                \"channels\": [],\n"
			"                \"mentions\": [],\n"
			"                \"msg\": \"down\",\n"
			"                \"reactions\": {\n"
			"                    \":flushed:\": {\n"
			"                        \"usernames\": [\n"
			"                            \"amusta\"\n"
			"                        ]\n"
			"                    }\n"
			"                },\n"
			"                \"rid\": \"GisRHFYEMmWoM5\",\n"
			"                \"tmid\": \"somX89q4vHjavp\",\n"
			"                \"ts\": {\n"
			"                    \"$date\": 1602491242261\n"
			"                },\n"
			"                \"u\": {\n"
			"                    \"_id\": \"n2bzjQNCcEuq2FDWi\",\n"
			"                    \"name\": \"Harty\",\n"
			"                    \"username\": \"gonzo\"\n"
			"                }\n"
			"            }\n"
			);
	{
		char *msg = NULL, *rid = NULL, *_id = NULL, *username = NULL, *tmid = NULL;
		json_object *attachments = NULL, *reactions = NULL;
		r = json_read(NULL, jo,
			   "{msg:%s rid:%s _id:%s u:{username:%s} attachments?%o reactions?%o tmid?%s}",
			   &msg, &rid, &_id, &username, &attachments, &reactions, &tmid);
		printf("r=%d\n", r);
	}
	return 0;
}
#endif
