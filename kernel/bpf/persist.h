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

#define CCMAPS_MOUNT_PATH "/mnt/ccmaps"
#define CCMAPS_INDEX_FILENAME "index"
#define MAX_MAPS 200

/* struct for ccmapd jobs */
struct ccmap_job {
	struct file *file;
	char *data;
	size_t len;
	loff_t *pos;
	bool done;
	struct list_head list;
};

/* ccmap job queue struct and APIs */
struct ccmap_job_queue {
	struct list_head head;
	spinlock_t lock;
};

struct ccmap_job_queue_node {
	struct ccmap_job *job;
	struct list_head list;
};

void ccmap_queue_init(struct ccmap_job_queue *queue);
void ccmap_job_enqueue(struct ccmap_job_queue *queue, struct ccmap_job *job);
int ccmap_job_dequeue(struct ccmap_job_queue *queue, struct ccmap_job **job);
void ccmap_queue_cleanup(struct ccmap_job_queue *queue);


/* struct for ccmapd kthread init */
struct ccmapd_data {
	struct ccmap_job_queue *job_queue;
	spinlock_t lock;
};

/* ebpf map to file table */
struct ccmap {
	struct file *file;
	char name[16U];
	u32 id;
	spinlock_t lock;
	u32 map_type;
};

/* On disk header for ccmap log file */
struct ccmap_hdr {
	char name[16U];
	u32 id;
	u32 map_type;
};

/* ccmapd thread */
int ccmapd(void *);

/* function to init kthread for ccmapd */
int bpf_persist_kthread_init(void);

/* open a file for persistence */
int bpf_persist_map_open(u32 id, char *name, u32 map_type);

/* write contents to a map */
int bpf_persist_map_write(void);

/* close the file */
void bpf_persist_map_close(char *name);
#endif
