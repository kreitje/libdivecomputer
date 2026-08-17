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

#include <string.h> // memcpy, memset

#include <libdivecomputer/ble.h>

#include "cressi_davinci.h"
#include "context-private.h"
#include "device-private.h"
#include "checksum.h"
#include "array.h"
#include "platform.h"

#define ISINSTANCE(device) dc_device_isinstance((device), &cressi_davinci_device_vtable)

/*
 * The GATT profile and application protocol below were reverse engineered
 * from two BLE sniffer captures of a Cressi Davinci (advertised name
 * "DAV02741", one dive stored) syncing with the Cressi DiveSync app.
 *
 * Custom service: 03d97288-001f-11ee-be56-0242ac120002
 *   03d97c10-001f-11ee-be56-0242ac120002  Write Without Response ("command")
 *   03d97d1e-001f-11ee-be56-0242ac120002  Read                   ("response")
 *   03d974d6-001f-11ee-be56-0242ac120002  Notify                 (unused by the app; not implemented here)
 *   0000fe11-8e22-4541-9d4c-21edae82ed19  Write Without Response (unused by the app; purpose unknown)
 *
 * The application protocol is a simple 16-bit register read/write scheme.
 * A GET is a bare envelope written to the command characteristic, and the
 * result is fetched by reading the response characteristic immediately
 * afterwards. A SET is the same envelope with a payload appended.
 *
 *   Command:  ADDR(2, BE) | LENGTH(2, BE, self-inclusive) | [PAYLOAD] | CRC16(2, BE)
 *   Response: ADDR(2, BE) | LENGTH(2, BE, self-inclusive) | STATUS(1) | [PAYLOAD] | CRC16(2, BE)
 *
 * CRC16 is CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, xorout 0x0000),
 * computed over every byte of the envelope preceding the checksum itself.
 * It was verified against every request/response pair in both captures.
 *
 * Registers observed:
 *   0x0012  GET  ASCII serial number suffix (e.g. "02741")
 *   0x0014  GET  ASCII firmware version (e.g. "1.2.2")
 *   0x0016  GET  ASCII device name (e.g. "DAV02741")
 *   0x0600  GET  4-byte BE dive count
 *   0x0610  SET  4-byte BE dive index -> GET returns the 4-byte BE sample count for that dive
 *   0x0612  SET  4-byte BE dive index + 4-byte BE sample cursor
 *                -> GET returns up to 5 consecutive 32-byte sample records
 *                   starting at that cursor (fewer for the final, partial page)
 *
 * Sample record (32 bytes, all multi-byte fields little-endian, unlike the
 * envelope which is big-endian):
 *   offset  0   constant 0x0001
 *   offset  2   int16, noisy/unidentified (possibly a raw sensor delta)
 *   offset  4   uint16, elapsed dive time in seconds (~10s interval)
 *   offset  8   uint8,  depth in decimetres (confirmed: forms a clean
 *               descent/bottom/ascent curve peaking at ~9.2 m)
 *   offset 10   uint8,  probably temperature; tracks inversely with depth
 *               exactly as a thermocline would, but the raw-to-Celsius
 *               formula is NOT confirmed yet (raw range 224-236 observed)
 *   offset 11-31  mostly constant/flag bytes across every sample in this
 *               capture; not decoded
 *
 * Register 0x0601 (SET with a 4-byte BE index, same convention as 0x0610/
 * 0x0612, then GET) contains a timestamp at payload offset 12:
 *   second(1) | unknown(1) | hour(1) | minute(1) | day(1) | month(1) | year(2, LE)
 * For index=1 this decoded to 2026-08-09 10:05:09, which matches the
 * real-world date of the only dive on the test unit. It's only been
 * confirmed against a single dive (index=1), so whether this register is
 * genuinely per-dive-indexed (like 0x0610/0x0612) or just a device-wide
 * "last sync" timestamp that happened to coincide with the dive is not
 * yet certain -- treat the datetime as a good-confidence dive timestamp,
 * not a fully verified one. The "unknown" byte (hundredths of a second?)
 * is dropped. The fingerprint is still a content hash of the profile
 * rather than being derived from this timestamp, since a dive that is
 * re-logged at the same date/time (e.g. two short dives within the same
 * minute) would otherwise collide.
 */
static const dc_ble_uuid_t cressi_davinci_uuid_write =
	{0x03, 0xd9, 0x7c, 0x10, 0x00, 0x1f, 0x11, 0xee, 0xbe, 0x56, 0x02, 0x42, 0xac, 0x12, 0x00, 0x02};
static const dc_ble_uuid_t cressi_davinci_uuid_read =
	{0x03, 0xd9, 0x7d, 0x1e, 0x00, 0x1f, 0x11, 0xee, 0xbe, 0x56, 0x02, 0x42, 0xac, 0x12, 0x00, 0x02};

#define ADDR_SERIAL   0x0012
#define ADDR_FIRMWARE 0x0014
#define ADDR_NAME     0x0016
#define ADDR_COUNT    0x0600
#define ADDR_SELECT   0x0610
#define ADDR_SAMPLES  0x0612
#define ADDR_DATETIME 0x0601

#define SZ_RECORD   32
#define SZ_PAGE     (5 * SZ_RECORD)
#define SZ_PACKET   256
#define SZ_HEADER   15 /* index(4) + nsamples(4) + year(2) + month(1) + day(1) + hour(1) + minute(1) + second(1) */

#define FP_SIZE 8

typedef struct cressi_davinci_device_t {
	dc_device_t base;
	dc_iostream_t *iostream;
	unsigned char fingerprint[FP_SIZE];
} cressi_davinci_device_t;

static dc_status_t cressi_davinci_device_set_fingerprint (dc_device_t *abstract, const unsigned char data[], unsigned int size);
static dc_status_t cressi_davinci_device_foreach (dc_device_t *abstract, dc_dive_callback_t callback, void *userdata);

static const dc_device_vtable_t cressi_davinci_device_vtable = {
	sizeof(cressi_davinci_device_t),
	DC_FAMILY_CRESSI_DAVINCI,
	cressi_davinci_device_set_fingerprint, /* set_fingerprint */
	NULL, /* read */
	NULL, /* write */
	NULL, /* dump */
	cressi_davinci_device_foreach, /* foreach */
	NULL, /* timesync */
	NULL, /* close */
};

dc_status_t
cressi_davinci_device_open (dc_device_t **out, dc_context_t *context, dc_iostream_t *iostream)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	cressi_davinci_device_t *device = NULL;

	if (out == NULL)
		return DC_STATUS_INVALIDARGS;

	// Allocate memory.
	device = (cressi_davinci_device_t *) dc_device_allocate (context, &cressi_davinci_device_vtable);
	if (device == NULL) {
		ERROR (context, "Failed to allocate memory.");
		return DC_STATUS_NOMEMORY;
	}

	// Set the default values.
	device->iostream = iostream;
	memset (device->fingerprint, 0, sizeof (device->fingerprint));

	// Set the timeout for receiving data.
	status = dc_iostream_set_timeout (device->iostream, 5000);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to set the timeout.");
		goto error_free;
	}

	dc_iostream_purge (device->iostream, DC_DIRECTION_ALL);

	*out = (dc_device_t *) device;

	return DC_STATUS_SUCCESS;

error_free:
	dc_device_deallocate ((dc_device_t *) device);
	return status;
}

static dc_status_t
cressi_davinci_device_set_fingerprint (dc_device_t *abstract, const unsigned char data[], unsigned int size)
{
	cressi_davinci_device_t *device = (cressi_davinci_device_t *) abstract;

	if (size && size != sizeof (device->fingerprint))
		return DC_STATUS_INVALIDARGS;

	if (size)
		memcpy (device->fingerprint, data, sizeof (device->fingerprint));
	else
		memset (device->fingerprint, 0, sizeof (device->fingerprint));

	return DC_STATUS_SUCCESS;
}

/*
 * Perform one GET or SET register transfer.
 *
 * NOTE: The exact truncation/padding behaviour of DC_IOCTL_BLE_CHARACTERISTIC_READ
 * for a variable-length characteristic value has not been verified against
 * real hardware (the only precedent in this codebase, cressi_goa.c, only
 * ever reads characteristics of a known, fixed length). This function
 * requests a generously oversized buffer and then trusts the embedded
 * LENGTH field to know how much of it is real; if the platform backend
 * turns out not to zero-fill or exactly size the output, this will need
 * adjusting.
 */
static dc_status_t
cressi_davinci_transfer (cressi_davinci_device_t *device, unsigned int addr,
	const unsigned char input[], unsigned int isize,
	unsigned char output[], unsigned int osize, unsigned int *actual)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	dc_device_t *abstract = (dc_device_t *) device;

	if (isize > SZ_PACKET - 6) {
		ERROR (abstract->context, "Unexpected payload size (%u).", isize);
		return DC_STATUS_INVALIDARGS;
	}

	// Build the command envelope.
	unsigned char command[SZ_PACKET];
	unsigned int length = 6 + isize;
	array_uint16_be_set (command + 0, addr);
	array_uint16_be_set (command + 2, length);
	if (isize) {
		memcpy (command + 4, input, isize);
	}
	unsigned short crc = checksum_crc16_ccitt (command, length - 2, 0xFFFF, 0x0000);
	array_uint16_be_set (command + length - 2, crc);

	// Send the command to the write characteristic.
	unsigned char request[sizeof(dc_ble_uuid_t) + SZ_PACKET];
	memcpy (request, cressi_davinci_uuid_write, sizeof(dc_ble_uuid_t));
	memcpy (request + sizeof(dc_ble_uuid_t), command, length);
	status = dc_iostream_ioctl (device->iostream, DC_IOCTL_BLE_CHARACTERISTIC_WRITE, request, sizeof(dc_ble_uuid_t) + length);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to write register %#06x.", addr);
		return status;
	}

	// Read the response from the read characteristic.
	unsigned char response[sizeof(dc_ble_uuid_t) + SZ_PACKET] = {0};
	memcpy (response, cressi_davinci_uuid_read, sizeof(dc_ble_uuid_t));
	status = dc_iostream_ioctl (device->iostream, DC_IOCTL_BLE_CHARACTERISTIC_READ, response, sizeof(response));
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to read register %#06x.", addr);
		return status;
	}

	const unsigned char *packet = response + sizeof(dc_ble_uuid_t);

	unsigned int rspaddr = array_uint16_be (packet + 0);
	unsigned int rsplength = array_uint16_be (packet + 2);
	if (rspaddr != addr) {
		ERROR (abstract->context, "Unexpected register in response (%#06x, expected %#06x).", rspaddr, addr);
		return DC_STATUS_PROTOCOL;
	}
	if (rsplength < 7 || rsplength > SZ_PACKET) {
		ERROR (abstract->context, "Unexpected response length (%u).", rsplength);
		return DC_STATUS_PROTOCOL;
	}

	unsigned short rspcrc = array_uint16_be (packet + rsplength - 2);
	unsigned short rspccrc = checksum_crc16_ccitt (packet, rsplength - 2, 0xFFFF, 0x0000);
	if (rspcrc != rspccrc) {
		ERROR (abstract->context, "Unexpected response checksum.");
		return DC_STATUS_PROTOCOL;
	}

	unsigned char status_byte = packet[4];
	if (status_byte != 0x06) {
		ERROR (abstract->context, "Unexpected response status (%#04x).", status_byte);
		return DC_STATUS_PROTOCOL;
	}

	unsigned int payload_size = rsplength - 7;
	if (payload_size > osize) {
		ERROR (abstract->context, "Output buffer too small (%u > %u).", payload_size, osize);
		return DC_STATUS_PROTOCOL;
	}

	if (payload_size && output) {
		memcpy (output, packet + 5, payload_size);
	}
	if (actual) {
		*actual = payload_size;
	}

	return status;
}

static dc_status_t
cressi_davinci_device_foreach (dc_device_t *abstract, dc_dive_callback_t callback, void *userdata)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	cressi_davinci_device_t *device = (cressi_davinci_device_t *) abstract;
	dc_buffer_t *buffer = NULL;

	// Enable progress notifications.
	dc_event_progress_t progress = EVENT_PROGRESS_INITIALIZER;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	// Read the device identification registers.
	unsigned char serial[32] = {0}, firmware[32] = {0}, name[32] = {0};
	unsigned int n = 0;
	status = cressi_davinci_transfer (device, ADDR_SERIAL, NULL, 0, serial, sizeof(serial), &n);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to read the serial number.");
		return status;
	}
	status = cressi_davinci_transfer (device, ADDR_FIRMWARE, NULL, 0, firmware, sizeof(firmware), &n);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to read the firmware version.");
		return status;
	}
	status = cressi_davinci_transfer (device, ADDR_NAME, NULL, 0, name, sizeof(name), &n);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to read the device name.");
		return status;
	}

	// Emit a vendor event with the raw identification data.
	unsigned char id[sizeof(serial) + sizeof(firmware) + sizeof(name)];
	memcpy (id + 0, serial, sizeof(serial));
	memcpy (id + sizeof(serial), firmware, sizeof(firmware));
	memcpy (id + sizeof(serial) + sizeof(firmware), name, sizeof(name));
	dc_event_vendor_t vendor;
	vendor.data = id;
	vendor.size = sizeof(id);
	device_event_emit (abstract, DC_EVENT_VENDOR, &vendor);

	// Read the number of dives stored on the device.
	unsigned char countbuf[4] = {0};
	status = cressi_davinci_transfer (device, ADDR_COUNT, NULL, 0, countbuf, sizeof(countbuf), &n);
	if (status != DC_STATUS_SUCCESS || n != sizeof(countbuf)) {
		ERROR (abstract->context, "Failed to read the dive count.");
		return status != DC_STATUS_SUCCESS ? status : DC_STATUS_PROTOCOL;
	}
	unsigned int ndives = array_uint32_be (countbuf);

	progress.maximum = (ndives + 1) * 1000;
	progress.current = 1000;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	buffer = dc_buffer_new (4096);
	if (buffer == NULL) {
		ERROR (abstract->context, "Failed to allocate memory for the dive.");
		return DC_STATUS_NOMEMORY;
	}

	// NOTE: The dive index numbering/order (oldest-to-newest vs
	// newest-to-oldest) has only been verified for a device with a single
	// stored dive; both captures used index 1.
	for (unsigned int index = 1; index <= ndives; ++index) {
		dc_buffer_clear (buffer);

		// Select the dive and read its sample count.
		unsigned char selectbuf[4] = {0};
		array_uint32_be_set (selectbuf, index);
		unsigned char countbuf2[4] = {0};
		status = cressi_davinci_transfer (device, ADDR_SELECT, selectbuf, sizeof(selectbuf), countbuf2, sizeof(countbuf2), &n);
		if (status != DC_STATUS_SUCCESS || n != sizeof(countbuf2)) {
			ERROR (abstract->context, "Failed to read the sample count for dive %u.", index);
			status = status != DC_STATUS_SUCCESS ? status : DC_STATUS_PROTOCOL;
			goto error_free_buffer;
		}
		unsigned int nsamples = array_uint32_be (countbuf2);

		// Read the dive timestamp (see the big comment at the top of
		// this file for how this register/offset was identified).
		unsigned char dtbuf[SZ_PACKET] = {0};
		unsigned int dtsize = 0;
		status = cressi_davinci_transfer (device, ADDR_DATETIME, selectbuf, sizeof(selectbuf), dtbuf, sizeof(dtbuf), &dtsize);
		if (status != DC_STATUS_SUCCESS || dtsize < 20) {
			ERROR (abstract->context, "Failed to read the timestamp for dive %u.", index);
			status = status != DC_STATUS_SUCCESS ? status : DC_STATUS_PROTOCOL;
			goto error_free_buffer;
		}
		unsigned int second = dtbuf[12];
		unsigned int hour   = dtbuf[14];
		unsigned int minute = dtbuf[15];
		unsigned int day    = dtbuf[16];
		unsigned int month  = dtbuf[17];
		unsigned int year   = array_uint16_le (dtbuf + 18);

		// Prepend a header (dive index, sample count, timestamp) so the
		// parser has access to metadata that isn't part of the raw
		// sample stream itself.
		unsigned char header[SZ_HEADER];
		array_uint32_be_set (header + 0, index);
		array_uint32_be_set (header + 4, nsamples);
		array_uint16_be_set (header + 8, year);
		header[10] = month;
		header[11] = day;
		header[12] = hour;
		header[13] = minute;
		header[14] = second;
		if (!dc_buffer_append (buffer, header, sizeof(header))) {
			ERROR (abstract->context, "Insufficient buffer space available.");
			status = DC_STATUS_NOMEMORY;
			goto error_free_buffer;
		}

		// Download the sample data, one page (up to 5 records) at a time.
		unsigned int cursor = 0;
		while (cursor < nsamples) {
			unsigned char cursorbuf[8];
			array_uint32_be_set (cursorbuf + 0, index);
			array_uint32_be_set (cursorbuf + 4, cursor);

			unsigned char page[SZ_PAGE];
			unsigned int pagesize = 0;
			status = cressi_davinci_transfer (device, ADDR_SAMPLES, cursorbuf, sizeof(cursorbuf), page, sizeof(page), &pagesize);
			if (status != DC_STATUS_SUCCESS) {
				ERROR (abstract->context, "Failed to read samples for dive %u at offset %u.", index, cursor);
				goto error_free_buffer;
			}
			if (pagesize == 0 || pagesize % SZ_RECORD != 0) {
				ERROR (abstract->context, "Unexpected sample page size (%u).", pagesize);
				status = DC_STATUS_PROTOCOL;
				goto error_free_buffer;
			}

			if (!dc_buffer_append (buffer, page, pagesize)) {
				ERROR (abstract->context, "Insufficient buffer space available.");
				status = DC_STATUS_NOMEMORY;
				goto error_free_buffer;
			}

			cursor += pagesize / SZ_RECORD;

			progress.current = 1000 + index * 1000 - 1000 + 1000 * cursor / (nsamples ? nsamples : 1);
			device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);
		}

		const unsigned char *data = dc_buffer_get_data (buffer);
		size_t size = dc_buffer_get_size (buffer);

		// A real per-dive fingerprint (e.g. the dive's start date/time)
		// has not been located yet -- see the TODO at the top of this
		// file. As a placeholder, hash the profile content itself so
		// repeated downloads of the same dive at least dedupe correctly.
		unsigned char fingerprint[FP_SIZE] = {0};
		if (size >= sizeof(header)) {
			size_t tail = size >= (size_t) FP_SIZE ? (size_t) FP_SIZE : size - sizeof(header);
			memcpy (fingerprint, data + size - tail, tail);
		}

		if (callback && !callback (data, size, fingerprint, sizeof (fingerprint), userdata))
			break;
	}

error_free_buffer:
	dc_buffer_free (buffer);
	return status;
}
