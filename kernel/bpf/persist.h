// SPDX-License-Identifier: GPL-2.0-only
/*
 * Persistence Framework for eBPF Maps
 *
 * Copyright (c) 2024 Tanuj Ravi Rao
 */

#ifndef __BPF_PERSIST_H_
#define __BPF_PERSIST_H_

#include <linux/types.h>
#include <linux/fs.h>


/* struct for ccmapd jobs */
struct ccmapd_job {
	struct file *file;
	char *write_buffer; // start address of buffer that needs to be written
	u64 length;
	loff_t offset;
	bool done;
	struct ccmapd_job *next;
};

/* struct for ccmapd kthread init */
struct ccmapd_data {
	struct ccmapd_job *jobs_head;
	struct ccmapd_job *jobs_tail;
};

/* ccmapd thread */
int ccmapd(void *);

/* function to init kthread for ccmapd */
int bpf_persist_kthread_init(void);

/* open a file for persistence */
int bpf_persist_map_open(u32 id, char *name, void *rb_ptr, u32 size);

/* close the file */
void bpf_persist_map_close(char *name);
#endif
