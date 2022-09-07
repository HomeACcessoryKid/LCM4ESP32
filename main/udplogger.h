// (c) 2018-2021 HomeAccessoryKid
#ifndef __UDPLOGGER_H__
#define __UDPLOGGER_H__

//use nc -kulnw0 45678 to collect this output
//and use     udplogger_init(int prio);

#define UDPLOG(format, ...)      udplogstring_len+=sprintf(udplogstring+udplogstring_len,format,##__VA_ARGS__)
#define UDPLGP(format, ...)  do {printf(format,##__VA_ARGS__); \
                                 udplogstring_len+=sprintf(udplogstring+udplogstring_len,format,##__VA_ARGS__); \
                                } while(0)
void udplog_send(void *pvParameters);
extern char udplogstring[];
extern int udplogstring_len;

void udplogger_init(int prio);

#endif //__UDPLOGGER_H__
