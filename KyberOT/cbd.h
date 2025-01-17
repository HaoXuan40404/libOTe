#ifndef CBD_H
#define CBD_H

#include "params.h"
#include "poly.h"
#include <stdint.h>

#if (KYBER_ETA == 4)
#define cbd cbdeta4
#else
#define cbd cbdref
#endif

void cbd(poly* r, const unsigned char* buf);


#endif
