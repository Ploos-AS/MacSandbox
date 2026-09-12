/*
 * MacSandbox - Basilisk II Malware Analysis Edition
 *
 * Passive defensive-analysis instrumentation. Distributed under the same
 * GPL-2.0-or-later terms as Basilisk II.
 */
#ifndef MACSANDBOX_ANALYSIS_H
#define MACSANDBOX_ANALYSIS_H

#include <stdint.h>

void MacSandbox_RecordCpuSnapshot(const char *phase);
void MacSandbox_RecordTrap(uint16_t trap);
void MacSandbox_RecordInterrupt(unsigned int level);
void MacSandbox_RecordMemoryWrite(uint32_t address, unsigned int size, uint32_t value);

#endif /* MACSANDBOX_ANALYSIS_H */
