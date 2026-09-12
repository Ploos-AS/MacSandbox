/*
 * MacSandbox - Basilisk II Malware Analysis Edition
 *
 * Passive defensive-analysis instrumentation. Distributed under the same
 * GPL-2.0-or-later terms as Basilisk II.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sysdeps.h"
#include "macsandbox_analysis.h"
#include "uae_cpu/newcpu.h"

static FILE *analysis_events;
static bool analysis_initialized = false;
static unsigned long analysis_event_count = 0;
static unsigned long analysis_event_limit = 4096;
static uint32 analysis_watch_start = 0;
static uint32 analysis_watch_end = 0xffffffffu;

static unsigned long parse_ulong_env(const char *name, unsigned long fallback)
{
	const char *value = getenv(name);
	char *end = NULL;
	unsigned long parsed;
	if (!value || !*value)
		return fallback;
	parsed = strtoul(value, &end, 0);
	return (end && *end == '\0') ? parsed : fallback;
}

static FILE *analysis_open(void)
{
	const char *dir;
	char path[4096];
	if (analysis_initialized)
		return analysis_events;
	analysis_initialized = true;

	dir = getenv("MACSANDBOX_ANALYSIS_DIR");
	if (!dir || !*dir)
		return NULL;
	analysis_event_limit = parse_ulong_env("MACSANDBOX_EVENT_LIMIT", 4096);
	analysis_watch_start = (uint32)parse_ulong_env("MACSANDBOX_WATCH_START", 0);
	analysis_watch_end = (uint32)parse_ulong_env("MACSANDBOX_WATCH_END", 0xffffffffu);
	if (analysis_watch_end < analysis_watch_start)
		return NULL;
	if (snprintf(path, sizeof(path), "%s/core-events.jsonl", dir) >= (int)sizeof(path))
		return NULL;
	analysis_events = fopen(path, "a");
	if (analysis_events)
		setvbuf(analysis_events, NULL, _IOLBF, 0);
	return analysis_events;
}

static FILE *event_file(void)
{
	FILE *fp = analysis_open();
	if (!fp || analysis_event_count >= analysis_event_limit)
		return NULL;
	analysis_event_count++;
	return fp;
}

static void write_registers(FILE *fp)
{
	int i;
	MakeSR();
	fprintf(fp, "\"pc\":%u,\"sr\":%u,\"d\":[", (unsigned)m68k_getpc(), (unsigned)regs.sr);
	for (i = 0; i < 8; i++)
		fprintf(fp, "%s%u", i ? "," : "", (unsigned)m68k_dreg(regs, i));
	fputs("],\"a\":[", fp);
	for (i = 0; i < 8; i++)
		fprintf(fp, "%s%u", i ? "," : "", (unsigned)m68k_areg(regs, i));
	fputs("]", fp);
}

void MacSandbox_RecordCpuSnapshot(const char *phase)
{
	FILE *fp = event_file();
	if (!fp)
		return;
	fprintf(fp, "{\"schema\":\"macsandbox.event/1\",\"type\":\"cpu.snapshot\",\"source\":\"macsandbox.uae_cpu\",\"phase\":\"%s\",", phase ? phase : "runtime");
	write_registers(fp);
	fputs("}\n", fp);
}

void MacSandbox_RecordTrap(uint16_t trap)
{
	FILE *fp = event_file();
	if (!fp)
		return;
	fprintf(fp, "{\"schema\":\"macsandbox.event/1\",\"type\":\"mac.toolbox_trap\",\"source\":\"macsandbox.uae_cpu\",\"trap\":%u,", (unsigned)trap);
	write_registers(fp);
	fputs("}\n", fp);
}

void MacSandbox_RecordInterrupt(unsigned int level)
{
	FILE *fp = event_file();
	if (!fp)
		return;
	fprintf(fp, "{\"schema\":\"macsandbox.event/1\",\"type\":\"cpu.interrupt.request\",\"source\":\"macsandbox.uae_cpu\",\"level\":%u,", level);
	write_registers(fp);
	fputs("}\n", fp);
}

void MacSandbox_RecordMemoryWrite(uint32_t address, unsigned int size, uint32_t value)
{
	FILE *fp;
	if (address < analysis_watch_start || address > analysis_watch_end)
		return;
	fp = event_file();
	if (!fp)
		return;
	fprintf(fp, "{\"schema\":\"macsandbox.event/1\",\"type\":\"memory.write\",\"source\":\"macsandbox.uae_memory\",\"address\":%u,\"size\":%u,\"value\":%u,", (unsigned)address, size, (unsigned)value);
	write_registers(fp);
	fputs("}\n", fp);
}
