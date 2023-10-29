/*  Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#ifndef __BRAINFLAYER_PSTRING_H_
#define __BRAINFLAYER_PSTRING_H_

#include <stdint.h>

int pfread8(void *, FILE *);
int pfread16(void *, FILE *);

int pfwrite8(const void *, uint8_t, FILE *);
int pfwrite16(const void *, uint16_t, FILE *);

/* vim: set ts=2 sw=2 et ai si: */
#endif /* __BRAINFLAYER_PSTRING_H_ */
