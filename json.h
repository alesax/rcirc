#ifndef __json_h__
#define __json_h__

#include<json-c/json.h>

int json_read(void *data, struct json_object *object, const char *fmt, ...);
struct json_object *json_create(void *data, const char *fmt, ...);

#endif
