// SPDX-License-Identifier: GPL-2.0-only
/*
 * Functions to provide persistence to eBPF maps
 *
 * Copyright (c) 2024 Tanuj Ravi Rao
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/string.h>

#include "persist.h"

struct file *file;
struct bpf_persist_map_hdr *map_hdr;
char filepath[100];
unsigned long base_addr, file_size;

int bpf_persist_map_open(u32 id, char *name, char *filepath, u32 size)
{
	/* Create the persistent map header */
	map_hdr = kmalloc(sizeof(struct bpf_persist_map_hdr), GFP_ATOMIC);

	map_hdr->id = id;
	strscpy(map_hdr->name, name, 16);
	map_hdr->cons_pos = 0;
	map_hdr->prod_pos = 0;

	// Open or create the file with write permissions
	// Note: Using O_WRONLY | O_CREAT to write and create the file if it does not exist
	file = filp_open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(file)) {
		printk(KERN_ERR "BPF_PERSIST: Error opening file %s\n", filepath);
		kfree(map_hdr);
		return PTR_ERR(file);
	}
	file_size = size;
	printk(KERN_INFO "BPF_PERSIST: Map file created %s\n", filepath);
	printk(KERN_INFO "BPF_PERSIST: sizeof map header %ld\n", sizeof(*map_hdr));
	printk(KERN_INFO "BPF_PERSIST: sizeof record header %ld\n", sizeof(struct bpf_ringbuf_record));

	return 0;
}

int bpf_persist_map_write(struct bpf_ringbuf_record *hdr,
			  unsigned long rec_pos)
{
	loff_t offset = rec_pos;
	printk(KERN_INFO "BPF_PERSIST: new record! len=%d, pg_off=%d \n", hdr->len, hdr->pg_off);
	kernel_write(file, hdr, hdr->len + 8, &offset);
	// vfs_fsync(file, 0);
	vfs_setpos(file, sizeof(*map_hdr), INT_MAX);
	return 0;
}

void bpf_persist_map_update_cons_pos(unsigned long pos)
{
	map_hdr->cons_pos = pos;
	vfs_setpos(file, 0, 1);
	printk(KERN_INFO "BPF_PERSIST: write new header for cons_pos update %lu \n", pos);
	kernel_write(file, map_hdr, sizeof(struct bpf_persist_map_hdr), 0);
	// vfs_fsync(file, 0);
}

void bpf_persist_map_update_prod_pos(unsigned long pos)
{
	map_hdr->prod_pos = pos;
	vfs_setpos(file, 0, 1);
	printk(KERN_INFO "BPF_PERSIST: write new header for prod_pos update %lu \n", pos);
	kernel_write(file, map_hdr, sizeof(struct bpf_persist_map_hdr), 0);
	// vfs_fsync(file, 0);
}

void bpf_persist_map_close()
{
	/* Close the file if it's open */
	if (file) {
		filp_close(file, NULL);
	}

	/* Free the allocated map header */
	if (map_hdr) {
		kfree(map_hdr);
	}

	printk(KERN_INFO
	       "BPF_PERSIST: Map and file resources have been released\n");
}
