// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-or-later
/*
 * idmetool - tool for manipulating amazon idme data
 * Copyright (c) 2026 Roger Ortiz <me@r0rt1z2.com>
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

#include "idmelib.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

static const char *idme_default_path = "/dev/block/mmcblk0boot1";

/* items that contain raw binary data rather than printable strings.
 */
static const char *binary_items[] = {
	"KB", "DKB", NULL /* sentinel */
};

static bool is_binary_item(const char *name)
{
	const char **p;

	for (p = binary_items; *p; p++) {
		if (strncmp(name, *p, IDME_MAX_NAME_LEN) == 0)
			return true;
	}

	return false;
}

static void print_usage(const char *prog)
{
	fprintf(stderr, "usage: %s [-f path] <command> [args]\n\n", prog);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -f <path>                               "
			"Specify path to IDME partition/file\n\n");
	fprintf(stderr, "Commands:\n");
	fprintf(stderr, "  dump                                    "
			"Show all IDME entries and their values\n");
	fprintf(stderr, "  get <key>                               "
			"Get the value of an IDME entry\n");
	fprintf(stderr, "  set <key> <value>                       "
			"Set the value of an IDME entry\n");
	fprintf(stderr, "  hexdump <key>                           "
			"Hexdump the raw data of an entry\n");
	fprintf(stderr, "  extract <key> <file>                    "
			"Save raw entry data to a file\n");
	fprintf(stderr, "  flags [fos|dev|usr]                     "
			"Show flags (default: fos)\n");
	fprintf(stderr, "  flags [fos|dev|usr] set <value>         "
			"Set flags to hex value or symbolic name\n");
	fprintf(stderr, "  flags [fos|dev|usr] add <value>         "
			"Add flag bits (OR)\n");
	fprintf(stderr, "  flags [fos|dev|usr] remove <value>      "
			"Remove flag bits (AND NOT)\n");
	fprintf(stderr, "  board                                   "
			"Show decoded board_id info\n");
	fprintf(stderr, "  bootmode                                "
			"Show current boot mode\n");
	fprintf(stderr, "  bootcount                               "
			"Show current boot count\n");
	fprintf(stderr, "  bootcount reset                         "
			"Reset boot count to 0\n");
	fprintf(stderr, "  version [value]                         "
			"Show or set the IDME version\n");
}

static void print_idme(struct idme *hdr)
{
	struct idme_item *item;
	char perm_str[10];
	char value[256];
	char flags_str[256];
	uint32_t i;

	printf("IDME [Magic: %.8s | Ver: %.3s | Items: %u]\n",
	       hdr->magic, hdr->version, hdr->items_num);

	item = idmelib_first_item(hdr);
	for (i = 0; i < hdr->items_num; i++) {
		idmelib_permission_to_str(item->desc.permission, perm_str);

		printf("  %-16s [size=%-4u exp=%u perm=%s] ",
		       item->desc.name, item->desc.size,
		       item->desc.exportable, perm_str);

		if (is_binary_item(item->desc.name)) {
			printf("(%s)",
			       idmelib_item_has_data(item) ? "valid" : "empty");
			printf("\n");
			item = idmelib_item_next(item);
			continue;
		}

		size_t copy_len = MIN(item->desc.size, sizeof(value) - 1);
		memset(value, 0, sizeof(value));
		memcpy(value, item->data, copy_len);
		printf("%s", value);

		if (strcmp(item->desc.name, "fos_flags") == 0 ||
		    strcmp(item->desc.name, "dev_flags") == 0 ||
		    strcmp(item->desc.name, "usr_flags") == 0) {
			unsigned long long flags = strtoull(value, NULL, 16);
			if (idmelib_flags_to_str(flags, flags_str,
						 sizeof(flags_str)) == 0)
				printf(" (%s)", flags_str);
		}

		if (strcmp(item->desc.name, "bootmode") == 0) {
			int mode = (int)strtol(value, NULL, 10);
			printf(" (%s)", idmelib_bootmode_to_str(mode));
		}

		if (strcmp(item->desc.name, "board_id") == 0) {
			struct idme_board_info info;
			if (idmelib_get_board_info(hdr, &info) == 0)
				printf(" (type=0x%04x rev=0x%02x wan=%s)",
				       info.board_type, info.board_rev,
				       info.has_wan ? "yes" : "no");
		}

		printf("\n");
		item = idmelib_item_next(item);
	}
}

static FILE *open_idme(const char *path)
{
	if (!path)
		path = idme_default_path;
	return fopen(path, "r+b");
}

static bool read_idme(FILE *fp, void *buf, size_t size)
{
	if (fseek(fp, 0, SEEK_SET) != 0)
		return false;
	return fread(buf, 1, size, fp) == size;
}

static bool write_idme(FILE *fp, const void *buf, size_t size)
{
	if (fseek(fp, 0, SEEK_SET) != 0)
		return false;
	if (fwrite(buf, 1, size, fp) != size)
		return false;
	return fflush(fp) == 0;
}

/* parse a flags type name to its enum value. */
static enum idme_flag_type parse_flag_type(const char *str)
{
	if (!str)
		return IDME_FLAGS_FOS;
	if (strcmp(str, "fos") == 0)
		return IDME_FLAGS_FOS;
	if (strcmp(str, "dev") == 0)
		return IDME_FLAGS_DEV;
	if (strcmp(str, "usr") == 0)
		return IDME_FLAGS_USR;
	return IDME_FLAGS_MAX;
}

/* parse a flags value: either a hex number (0x...) or a symbolic name. */
static int parse_flag_value(const char *str, unsigned long long *out)
{
	char *end;

	if (!str || !out)
		return -1;

	*out = strtoull(str, &end, 0);
	if (end != str && *end == '\0')
		return 0;

	return idmelib_flags_parse_name(str, out);
}

static int cmd_flags(struct idme *hdr, int argc, char *argv[],
		     FILE *fp, uint8_t *buf)
{
	enum idme_flag_type type;
	unsigned long long cur;
	char sym[256];
	int arg_off = 0;

	type = IDME_FLAGS_FOS;
	if (argc > 0) {
		enum idme_flag_type t = parse_flag_type(argv[0]);
		if (t < IDME_FLAGS_MAX) {
			type = t;
			arg_off = 1;
		}
	}

	if (argc <= arg_off) {
		if (idmelib_flags_get(hdr, type, &cur) != 0) {
			fprintf(stderr, "Error: Could not read %s.\n",
				idmelib_flags_var_name(type));
			return EXIT_FAILURE;
		}

		idmelib_flags_to_str(cur, sym, sizeof(sym));
		printf("%s = 0x%llx (%s)\n",
		       idmelib_flags_var_name(type), cur, sym);
		return EXIT_SUCCESS;
	}

	const char *subcmd = argv[arg_off];
	const char *val_str = (argc > arg_off + 1) ? argv[arg_off + 1] : NULL;

	if (!val_str) {
		fprintf(stderr, "Error: Missing value for '%s'.\n", subcmd);
		return EXIT_FAILURE;
	}

	unsigned long long value;
	if (parse_flag_value(val_str, &value) != 0) {
		fprintf(stderr, "Error: Invalid flag value '%s'.\n", val_str);
		return EXIT_FAILURE;
	}

	if (idmelib_flags_get(hdr, type, &cur) != 0)
		cur = 0;

	unsigned long long new_flags;

	if (strcmp(subcmd, "set") == 0) {
		new_flags = value;
	} else if (strcmp(subcmd, "add") == 0) {
		new_flags = cur | value;
	} else if (strcmp(subcmd, "remove") == 0) {
		new_flags = cur & ~value;
	} else {
		fprintf(stderr, "Error: Unknown flags subcommand '%s'.\n",
			subcmd);
		return EXIT_FAILURE;
	}

	if (idmelib_flags_set(hdr, type, new_flags) != 0) {
		fprintf(stderr, "Error: Could not update %s.\n",
			idmelib_flags_var_name(type));
		return EXIT_FAILURE;
	}

	if (!write_idme(fp, buf, IDME_SIZE)) {
		fprintf(stderr, "Error: Failed to write IDME data.\n");
		return EXIT_FAILURE;
	}

	idmelib_flags_to_str(new_flags, sym, sizeof(sym));
	printf("%s set to 0x%llx (%s)\n",
	       idmelib_flags_var_name(type), new_flags, sym);

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	char *target_path = NULL, *prog = argv[0];
	uint8_t buf[IDME_SIZE];
	struct idme *hdr;
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

	FILE *fp = open_idme(target_path);
	if (!fp) {
		perror("Error: Could not open IDME partition");
		return EXIT_FAILURE;
	}

	if (!read_idme(fp, buf, sizeof(buf))) {
		fprintf(stderr, "Error: Failed to read IDME data.\n");
		fclose(fp);
		return EXIT_FAILURE;
	}

	hdr = (struct idme *)buf;

	if (!idmelib_magic_valid(hdr)) {
		fprintf(stderr, "Error: IDME header is corrupted "
				"(bad magic: %.8s).\n", hdr->magic);
		fclose(fp);
		return EXIT_FAILURE;
	}

	if (strcmp(argv[0], "dump") == 0) {
		print_idme(hdr);
	} else if (strcmp(argv[0], "get") == 0) {
		if (argc < 2) {
			print_usage(prog);
			goto cleanup;
		}

		struct idme_item *item = idmelib_get_item(hdr, argv[1]);
		if (!item) {
			fprintf(stderr, "Error: Item '%s' not found.\n",
				argv[1]);
			ret = EXIT_FAILURE;
		} else if (is_binary_item(argv[1])) {
			printf("%s (%u bytes):\n", argv[1], item->desc.size);
			idmelib_hexdump(item, stdout);
		} else {
			char value[256] = {0};
			size_t copy_len = MIN(item->desc.size,
					      sizeof(value) - 1);
			memcpy(value, item->data, copy_len);
			printf("%s\n", value);
		}
	} else if (strcmp(argv[0], "set") == 0) {
		if (argc < 3) {
			print_usage(prog);
			goto cleanup;
		}

		if (idmelib_set_var(hdr, argv[1], argv[2]) != 0) {
			fprintf(stderr, "Error: Item '%s' not found.\n",
				argv[1]);
			ret = EXIT_FAILURE;
			goto cleanup;
		}

		if (!write_idme(fp, buf, sizeof(buf))) {
			fprintf(stderr, "Error: Failed to write IDME data.\n");
			ret = EXIT_FAILURE;
		} else {
			printf("Set '%s' to '%s'.\n", argv[1], argv[2]);
		}
	} else if (strcmp(argv[0], "hexdump") == 0) {
		if (argc < 2) {
			print_usage(prog);
			goto cleanup;
		}

		struct idme_item *item = idmelib_get_item(hdr, argv[1]);
		if (!item) {
			fprintf(stderr, "Error: Item '%s' not found.\n",
				argv[1]);
			ret = EXIT_FAILURE;
		} else {
			printf("%s (%u bytes):\n", argv[1], item->desc.size);
			idmelib_hexdump(item, stdout);
		}
	} else if (strcmp(argv[0], "extract") == 0) {
		if (argc < 3) {
			print_usage(prog);
			goto cleanup;
		}

		struct idme_item *item = idmelib_get_item(hdr, argv[1]);
		if (!item) {
			fprintf(stderr, "Error: Item '%s' not found.\n",
				argv[1]);
			ret = EXIT_FAILURE;
			goto cleanup;
		}

		FILE *out = fopen(argv[2], "wb");
		if (!out) {
			perror("Error: Could not open output file");
			ret = EXIT_FAILURE;
			goto cleanup;
		}

		if (fwrite(item->data, 1, item->desc.size, out) !=
		    item->desc.size) {
			fprintf(stderr, "Error: Failed to write output file.\n");
			ret = EXIT_FAILURE;
		} else {
			printf("Saved '%s' (%u bytes) to '%s'.\n",
			       argv[1], item->desc.size, argv[2]);
		}

		fclose(out);
	} else if (strcmp(argv[0], "version") == 0) {
		if (argc < 2) {
			char ver[IDME_VERSION_LEN + 1];
			if (idmelib_get_version(hdr, ver, sizeof(ver)) != 0) {
				fprintf(stderr, "Error: Could not read version.\n");
				ret = EXIT_FAILURE;
			} else {
				printf("%s\n", ver);
			}
		} else {
			if (idmelib_set_version(hdr, argv[1]) != 0) {
				fprintf(stderr,
					"Error: Invalid version '%s' (max %d chars).\n",
					argv[1], IDME_VERSION_LEN);
				ret = EXIT_FAILURE;
				goto cleanup;
			}

			if (!write_idme(fp, buf, sizeof(buf))) {
				fprintf(stderr, "Error: Failed to write IDME data.\n");
				ret = EXIT_FAILURE;
			} else {
				printf("Set version to '%s'.\n", argv[1]);
			}
		}
	} else if (strcmp(argv[0], "flags") == 0) {
		ret = cmd_flags(hdr, argc - 1, argv + 1, fp, buf);
	} else if (strcmp(argv[0], "board") == 0) {
		struct idme_board_info info;
		if (idmelib_get_board_info(hdr, &info) != 0) {
			fprintf(stderr, "Error: Could not read board_id.\n");
			ret = EXIT_FAILURE;
		} else {
			printf("board_id:   %s\n", info.raw);
			printf("board_type: 0x%04x\n", info.board_type);
			printf("board_rev:  0x%02x\n", info.board_rev);
			printf("wan:        %s\n", info.has_wan ? "yes" : "no");
		}
	} else if (strcmp(argv[0], "bootmode") == 0) {
		int mode = idmelib_get_bootmode(hdr);
		if (mode < 0) {
			fprintf(stderr, "Error: Could not read bootmode.\n");
			ret = EXIT_FAILURE;
		} else {
			printf("%d (%s)\n", mode,
			       idmelib_bootmode_to_str(mode));
		}
	} else if (strcmp(argv[0], "bootcount") == 0) {
		if (argc >= 2 && strcmp(argv[1], "reset") == 0) {
			if (idmelib_set_var(hdr, "bootcount", "0") != 0) {
				fprintf(stderr,
					"Error: Could not reset bootcount.\n");
				ret = EXIT_FAILURE;
				goto cleanup;
			}

			if (!write_idme(fp, buf, sizeof(buf))) {
				fprintf(stderr,
					"Error: Failed to write IDME data.\n");
				ret = EXIT_FAILURE;
			} else {
				printf("Bootcount reset to 0.\n");
			}
		} else if (argc >= 2) {
			fprintf(stderr,
				"Error: Unknown bootcount subcommand '%s'.\n",
				argv[1]);
			print_usage(prog);
			ret = EXIT_FAILURE;
		} else {
			unsigned int count;
			if (idmelib_get_bootcount(hdr, &count) != 0) {
				fprintf(stderr,
					"Error: Could not read bootcount.\n");
				ret = EXIT_FAILURE;
			} else {
				printf("%u\n", count);
			}
		}
	} else {
		fprintf(stderr, "Error: Unknown command '%s'.\n", argv[0]);
		print_usage(prog);
		ret = EXIT_FAILURE;
	}

cleanup:
	fclose(fp);
	return ret;
}