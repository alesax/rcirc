#ifndef __util_h__
#define __util_h__

#define ERR  (1<<0)
#define DBG1 (1<<1)
#define DBG2 (1<<2)
#define DBG3 (1<<3)
#define DBG4 (1<<4)

void logg(short lvl, const char *fmt, ...);
#endif
