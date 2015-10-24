/* gets rid of warnings about opnessl using dlopen when statically linked */

#include <stdlib.h>

static char *dlerrstr = "dynamic loader not available (using dldummy)";

//void * dlopen(const char *filename, int flat) { return NULL; }
void * dlopen(void) { return NULL; }
char * dlerror(void) { return dlerrstr; }
void * dlsym(void) { return NULL; }
int dlclose(void) { return -1; }
/* this is supposed to set some null pointers on error, but fuck it */
int dladdr(void) { return -1; }
