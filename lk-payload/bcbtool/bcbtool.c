// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-or-later
/*
 * bcbtool - tool for manipulating amazon/mediatek bcb data
 * Copyright (c) 2026 Ben Grisdale <bengris32@protonmail.ch>
 *
 * This work is dual-licensed under the terms of the 3-Clause BSD License
 * or the GNU General Public License (GPL) version 2.0 or later.
 * You may choose, at your discretion, which of the licenses to follow.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bcblib.h"

#define BCB_PATHS	3

static const char *bcb_paths[BCB_PATHS] = {
	"/dev/block/platform/mtk-msdc.0/by-name/misc",
	"/dev/block/bootdevice/by-name/misc",
	"/dev/disk/by-partlabel/misc",
};

static void print_usage(const char *prog)
{
	fprintf(stderr, "usage: %s [-f path] <command> [args]\n\n", prog);
	fprintf(stderr, "Options:\n  -f <path>                               Specify path to misc partition/file\n\n");
	fprintf(stderr, "Commands:\n");
	fprintf(stderr, "  dump                                    Show current BCB state\n");
	fprintf(stderr, "  get [a|b] [prio|tries|success|all]      Get slot metadata\n");
	fprintf(stderr, "  set [a|b] [(prio,tries,success)] [vals] Set fields (e.g. prio,tries)\n");
	fprintf(stderr, "  get_active                              Get the active/successful slot\n");
	fprintf(stderr, "  set_active [a|b]                        Set a slot as active/successful\n");
	fprintf(stderr, "  init [a|b]                              Initialize new BCB metadata\n");
}

static void print_bcb(struct bcb *data)
{
	int active_slot = bcblib_bcb_get_active_slot(data, false, false);
	printf("BCB [Magic: %.3s | Ver: %d]\n", data->magic, data->version);
	printf("Slot A: prio=%-2d tries=%-1d success=%d\n", 
		   data->slot[0].priority, data->slot[0].tries, data->slot[0].success);
	printf("Slot B: prio=%-2d tries=%-1d success=%d\n", 
		   data->slot[1].priority, data->slot[1].tries, data->slot[1].success);
	if (active_slot >= 0)
		printf("Active slot: %c\n", 'a' + active_slot);
	else
		printf("Active slot: NONE; WILL FAIL TO BOOT!\n");
}

static bool read_bcb(FILE *fp, struct bcb *data)
{
	if (fseek(fp, BCB_OFFSET, SEEK_SET) != 0) return false;
	return fread(data, sizeof(struct bcb), 1, fp) == 1;
}

static bool write_bcb(FILE *fp, const struct bcb *data)
{
	if (fseek(fp, BCB_OFFSET, SEEK_SET) != 0) return false;
	if (fwrite(data, sizeof(struct bcb), 1, fp) != 1) return false;
	return fflush(fp) == 0;
}

static FILE *open_bcb(const char* path)
{
	FILE *fp = NULL;
	int i = 0;

	if (path) {
		fp = fopen(path, "r+b");
		return fp;
	} else {
		for (i = 0; i < BCB_PATHS; i++) {
			FILE *fp = fopen(bcb_paths[i], "r+b");
			if (fp) return fp;
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	char *target_path = NULL, *prog = argv[0];
	int opt;
	int ret = EXIT_SUCCESS;

	while ((opt = getopt(argc, argv, "f:")) != -1) {
		switch (opt) {
			case 'f':
				target_path = optarg;
				break;
			default:
				print_usage(prog);
				return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		print_usage(prog);
		return EXIT_FAILURE;
	}

	FILE *bcb_fp = open_bcb(target_path);
	if (!bcb_fp) {
		perror("Error: Could not open BCB partition");
		return EXIT_FAILURE;
	}

	struct bcb data = {0};
	if (strcmp(argv[0], "init") == 0) {
		bcblib_bcb_init(&data);

		if (argc >= 2) {
			if (argv[1][0] == 'a') {
				data.slot[0] = BCB_SLOT_METADATA_ACTIVE;
				data.slot[1] = BCB_SLOT_METADATA_EMPTY;
			} else if (argv[1][0] == 'b') {
				data.slot[1] = BCB_SLOT_METADATA_ACTIVE;
				data.slot[0] = BCB_SLOT_METADATA_EMPTY;
			} else {
				print_usage(prog);
				goto cleanup;
			}
		} else {
			printf("Warning: Initializing with no slots marked as bootable. This may eventually BRICK your device.\n");
		}

		if (write_bcb(bcb_fp, &data)) {
			printf("BCB initialized successfully.\n");
			print_bcb(&data);
		} else {
			fprintf(stderr, "Error: Failed to write BCB.\n");
			ret = EXIT_FAILURE;
		}
		goto cleanup;
	}

	if (!read_bcb(bcb_fp, &data)) {
		fprintf(stderr, "Error: Failed to read BCB data.\n");
		fclose(bcb_fp);
		return EXIT_FAILURE;
	}

	if (!bcblib_bcb_magic_valid(&data)) {
		fprintf(stderr, "Error: BCB header is corrupted. Please run bcbtool init.");
		fclose(bcb_fp);
		return EXIT_FAILURE;
	}

	if (strcmp(argv[0], "dump") == 0) {
		print_bcb(&data);
	}
	else if (strcmp(argv[0], "get") == 0) {
		if (argc < 3) { print_usage(prog); goto cleanup; }
		bcb_slot_metadata_t *s = bcblib_bcb_get_slot(&data, argv[1][0]);
		if (s == NULL) { print_usage(prog); goto cleanup; }
		
		if (strcmp(argv[2], "prio") == 0) printf("%d\n", s->priority);
		else if (strcmp(argv[2], "tries") == 0) printf("%d\n", s->tries);
		else if (strcmp(argv[2], "success") == 0) printf("%d\n", s->success);
		else if (strcmp(argv[2], "all") == 0) printf("prio: %d tries: %d success: %d\n",
			s->priority, s->tries, s->success);
	}
	else if (strcmp(argv[0], "get_active") == 0) {
		int active_slot = bcblib_bcb_get_active_slot(&data, false, false);
		if (active_slot >= 0) {
			printf("%c\n", 'a' + active_slot);
		} else {
			ret = EXIT_FAILURE;
		}
	}
	else if (strcmp(argv[0], "set_active") == 0) {
		if (argc < 2) { print_usage(prog); goto cleanup; }

		if (argv[1][0] == 'a') {
			data.slot[0] = BCB_SLOT_METADATA_ACTIVE;
			data.slot[1] = BCB_SLOT_METADATA_EMPTY;
		} else if (argv[1][0] == 'b') {
			data.slot[1] = BCB_SLOT_METADATA_ACTIVE;
			data.slot[0] = BCB_SLOT_METADATA_EMPTY;
		} else {
			print_usage(prog);
			goto cleanup;
		}

		if (write_bcb(bcb_fp, &data)) {
			printf("Active slot set to %c.\n", argv[1][0]);
		}
	}
	else if (strcmp(argv[0], "set") == 0) {
		if (argc < 4) { print_usage(prog); goto cleanup; }
		bcb_slot_metadata_t *s = bcblib_bcb_get_slot(&data, argv[1][0]);
		if (s == NULL) { print_usage(prog); goto cleanup; }

		char *f_save, *v_save;
		char *f_ptr = strtok_r(argv[2], ",", &f_save);
		char *v_ptr = strtok_r(argv[3], ",", &v_save);

		while (f_ptr && v_ptr) {
			int val = (int)strtol(v_ptr, NULL, 10);
			if (strcmp(f_ptr, "prio") == 0) bcblib_metadata_set_priority(s, val);
			else if (strcmp(f_ptr, "tries") == 0) bcblib_metadata_set_tries(s, val);
			else if (strcmp(f_ptr, "success") == 0) bcblib_metadata_set_success(s, !!val);
			
			f_ptr = strtok_r(NULL, ",", &f_save);
			v_ptr = strtok_r(NULL, ",", &v_save);
		}

		if (write_bcb(bcb_fp, &data)) {
			printf("Update applied to slot %c.\n", argv[1][0]);
			print_bcb(&data);
		}
	}

cleanup:
	fclose(bcb_fp);
	return ret;
}
