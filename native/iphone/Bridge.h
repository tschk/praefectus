#ifndef PRAEFECTUS_IPHONE_BRIDGE_H
#define PRAEFECTUS_IPHONE_BRIDGE_H
char *praefectus_iphone_call(const char *input);
void praefectus_iphone_begin(void);
void praefectus_iphone_cancel(void);
void praefectus_iphone_free(char *output);
#endif
