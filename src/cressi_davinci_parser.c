/*
 * libdivecomputer
 *
 * Copyright (C) 2026 Jeff Kreitner
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include "cressi_davinci.h"
#include "context-private.h"
#include "parser-private.h"
#include "array.h"

#define ISINSTANCE(parser) dc_parser_isinstance((parser), &cressi_davinci_parser_vtable)

/*
 * The dive buffer produced by cressi_davinci.c is a 15-byte header (dive
 * index[4,BE], sample count[4,BE], year[2,BE], month[1], day[1], hour[1],
 * minute[1], second[1]) followed by the raw sample stream downloaded from
 * register 0x0612: a sequence of 32-byte records, all multi-byte fields
 * little-endian. See the big comment in cressi_davinci.c for how this
 * layout was reverse engineered and what is still unconfirmed (notably
 * the temperature scale, and the exact meaning of the 0x0601 timestamp).
 */
#define SZ_HEADER 15
#define SZ_RECORD 32

#define HEADER_YEAR   8
#define HEADER_MONTH  10
#define HEADER_DAY    11
#define HEADER_HOUR   12
#define HEADER_MINUTE 13
#define HEADER_SECOND 14

#define RECORD_TIME   4
#define RECORD_DEPTH  8
#define RECORD_TEMP   10

typedef struct cressi_davinci_parser_t {
	dc_parser_t base;
} cressi_davinci_parser_t;

static dc_status_t cressi_davinci_parser_get_datetime (dc_parser_t *abstract, dc_datetime_t *datetime);
static dc_status_t cressi_davinci_parser_get_field (dc_parser_t *abstract, dc_field_type_t type, unsigned int flags, void *value);
static dc_status_t cressi_davinci_parser_samples_foreach (dc_parser_t *abstract, dc_sample_callback_t callback, void *userdata);

static const dc_parser_vtable_t cressi_davinci_parser_vtable = {
	sizeof(cressi_davinci_parser_t),
	DC_FAMILY_CRESSI_DAVINCI,
	NULL, /* set_clock */
	NULL, /* set_atmospheric */
	NULL, /* set_density */
	cressi_davinci_parser_get_datetime, /* datetime */
	cressi_davinci_parser_get_field, /* fields */
	cressi_davinci_parser_samples_foreach, /* samples_foreach */
	NULL, /* destroy */
};

dc_status_t
cressi_davinci_parser_create (dc_parser_t **out, dc_context_t *context, const unsigned char data[], size_t size)
{
	cressi_davinci_parser_t *parser = NULL;

	if (out == NULL)
		return DC_STATUS_INVALIDARGS;

	if (size < SZ_HEADER || (size - SZ_HEADER) % SZ_RECORD != 0) {
		ERROR (context, "Invalid dive length (" DC_PRINTF_SIZE ").", size);
		return DC_STATUS_DATAFORMAT;
	}

	// Allocate memory.
	parser = (cressi_davinci_parser_t *) dc_parser_allocate (context, &cressi_davinci_parser_vtable, data, size);
	if (parser == NULL) {
		ERROR (context, "Failed to allocate memory.");
		return DC_STATUS_NOMEMORY;
	}

	*out = (dc_parser_t *) parser;

	return DC_STATUS_SUCCESS;
}

static dc_status_t
cressi_davinci_parser_get_datetime (dc_parser_t *abstract, dc_datetime_t *datetime)
{
	const unsigned char *header = abstract->data;

	if (datetime) {
		datetime->year   = array_uint16_be (header + HEADER_YEAR);
		datetime->month  = header[HEADER_MONTH];
		datetime->day    = header[HEADER_DAY];
		datetime->hour   = header[HEADER_HOUR];
		datetime->minute = header[HEADER_MINUTE];
		datetime->second = header[HEADER_SECOND];
		datetime->timezone = DC_TIMEZONE_NONE;
	}

	return DC_STATUS_SUCCESS;
}

static dc_status_t
cressi_davinci_parser_get_field (dc_parser_t *abstract, dc_field_type_t type, unsigned int flags, void *value)
{
	const unsigned char *data = abstract->data + SZ_HEADER;
	unsigned int nrecords = (unsigned int) ((abstract->size - SZ_HEADER) / SZ_RECORD);

	if (nrecords == 0)
		return DC_STATUS_UNSUPPORTED;

	if (value) {
		switch (type) {
		case DC_FIELD_DIVETIME:
			*((unsigned int *) value) = array_uint16_le (data + (nrecords - 1) * SZ_RECORD + RECORD_TIME);
			break;
		case DC_FIELD_MAXDEPTH:
		{
			unsigned int maxdepth = 0;
			for (unsigned int i = 0; i < nrecords; ++i) {
				unsigned int depth = data[i * SZ_RECORD + RECORD_DEPTH];
				if (depth > maxdepth)
					maxdepth = depth;
			}
			*((double *) value) = maxdepth / 10.0;
			break;
		}
		case DC_FIELD_AVGDEPTH:
		{
			unsigned int sum = 0;
			for (unsigned int i = 0; i < nrecords; ++i) {
				sum += data[i * SZ_RECORD + RECORD_DEPTH];
			}
			*((double *) value) = (sum / (double) nrecords) / 10.0;
			break;
		}
		case DC_FIELD_GASMIX_COUNT:
			*((unsigned int *) value) = 0;
			break;
		case DC_FIELD_DIVEMODE:
			*((dc_divemode_t *) value) = DC_DIVEMODE_OC;
			break;
		default:
			return DC_STATUS_UNSUPPORTED;
		}
	}

	return DC_STATUS_SUCCESS;
}

static dc_status_t
cressi_davinci_parser_samples_foreach (dc_parser_t *abstract, dc_sample_callback_t callback, void *userdata)
{
	const unsigned char *data = abstract->data + SZ_HEADER;
	unsigned int nrecords = (unsigned int) ((abstract->size - SZ_HEADER) / SZ_RECORD);

	for (unsigned int i = 0; i < nrecords; ++i) {
		const unsigned char *record = data + i * SZ_RECORD;
		dc_sample_value_t sample = {0};

		// Time (milliseconds). The raw record stores elapsed seconds.
		sample.time = array_uint16_le (record + RECORD_TIME) * 1000;
		if (callback) callback (DC_SAMPLE_TIME, &sample, userdata);

		// Depth (1/10 m).
		sample.depth = record[RECORD_DEPTH] / 10.0;
		if (callback) callback (DC_SAMPLE_DEPTH, &sample, userdata);

		// Temperature: this tracks inversely with depth exactly like a
		// thermocline would, but the raw-to-Celsius formula below
		// (raw - 200) is an unverified guess based on the observed
		// 224-236 raw range for a shallow warm-water test dive. Confirm
		// against the temperature DiveSync displays for this dive
		// before trusting this field.
		sample.temperature = record[RECORD_TEMP] - 200;
		if (callback) callback (DC_SAMPLE_TEMPERATURE, &sample, userdata);
	}

	return DC_STATUS_SUCCESS;
}
