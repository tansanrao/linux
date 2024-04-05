// SPDX-License-Identifier: GPL-2.0-only
/*
 * Functions to provide persistence to eBPF maps
 *
 * Copyright (c) 2024 Tanuj Ravi Rao
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/kthread.h>
#include <linux/sched.h>

#include "persist.h"

#define SCAN_INTERVAL_MS 10

struct bpf_persistd_data *persistd_data;
struct file **file;
struct bpf_persist_map_hdr **map_hdr;
int refcnt = 0;
char filepath[100];
static struct task_struct *kth_ptr;
void *prep_buf_ptr, *req_buf_ptr;

/* helper to get rb address from rec_hdr */
void *bpf_ringbuf_restore_from_record(struct bpf_ringbuf_record *hdr)
{
	unsigned long addr = (unsigned long)(void *)hdr;
	unsigned long off = (unsigned long)hdr->pg_off << PAGE_SHIFT;

	return (void*)((addr & PAGE_MASK) - off);
}


/* kthread for bpf_persistd */
int bpf_persistd(void *data)
{
	struct bpf_persistd_data *d = (struct bpf_persistd_data *)data;

	while (!kthread_should_stop()) {
		if (READ_ONCE(d->do_fsync)) {
			vfs_fsync(d->file, 1);
			WRITE_ONCE(d->do_fsync, false);
		}

		// sleep after doing this job until woken up again
		schedule_timeout_interruptible(MAX_SCHEDULE_TIMEOUT);
	}

	printk(KERN_INFO "[bpf_persistd]: thread stopped \n");
	return 0;
}

int initialize_kthread()
{
	char th_name[20];
	sprintf(th_name, "bpf_persistd");
	kth_ptr = kthread_create(bpf_persistd, persistd_data,
				 (const char *)th_name);
	if (kth_ptr != NULL) {
		wake_up_process(kth_ptr);
		printk(KERN_INFO "%s is running\n", th_name);
	} else {
		printk(KERN_INFO "kthread %s could not be created\n", th_name);
		return -1;
	}
	return 0;
}

int bpf_persist_map_open(u32 id, char *name, void *rb_ptr, u32 size)
{
	unsigned int rec_id;
	if (strcmp(name, "map_prepare_buf") == 0) {
		rec_id = 0;
		strcpy(filepath, "/tmp/map_prepare_buf.bin");
		prep_buf_ptr = rb_ptr;
	} else {
		rec_id = 1;
		strcpy(filepath, "/tmp/map_request_buf.bin");
		req_buf_ptr = rb_ptr;
	}

	if(refcnt == 0) {
		map_hdr = kzalloc(sizeof(**map_hdr) * 2, GFP_ATOMIC);
		file = kzalloc(sizeof(**file) * 2, GFP_ATOMIC);
	}

	/* Create the persistent map header */
	map_hdr[rec_id] = kzalloc(sizeof(struct bpf_persist_map_hdr), GFP_ATOMIC);

	map_hdr[rec_id]->id = id;
	strscpy(map_hdr[rec_id]->name, name, 16);
	map_hdr[rec_id]->cons_pos = 0;
	map_hdr[rec_id]->prod_pos = 0;

	// Open or create the file with write permissions
	// Note: Using O_WRONLY | O_CREAT to write and create the file if it does not exist
	file[rec_id] = filp_open(filepath, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (IS_ERR(file[rec_id])) {
		printk(KERN_ERR "BPF_PERSIST: Error opening file %s\n",
		       filepath);
		kfree(map_hdr[rec_id]);
		return PTR_ERR(file[rec_id]);
	}

	refcnt++;

	/* setup bpf_persistd and start the kthread */
	persistd_data = kzalloc(sizeof(struct bpf_persistd_data), GFP_ATOMIC);
	persistd_data->file = file[rec_id];
	persistd_data->do_fsync = false;
	initialize_kthread();

	/* write the persistent map header */
	kernel_write(file[rec_id], map_hdr[rec_id], sizeof(**map_hdr), 0);

	/* call fsync on it */
	/* if do_fsync is true here, the locks are broken */
	BUG_ON(READ_ONCE(persistd_data->do_fsync));

	/* set do_fsync to true */
	WRITE_ONCE(persistd_data->do_fsync, true);

	/* wake the kthread */
	wake_up_process(kth_ptr);

	/* wait for do_fsync to be false before returning */
	while (READ_ONCE(persistd_data->do_fsync))
		;

	return 0;
}

int __bpf_persist_map_write_hdr(void *rb_ptr)
{
	unsigned int rec_id;
	if (prep_buf_ptr == rb_ptr) {
		rec_id = 0;
	} else {
		rec_id = 1;
	}
	/* write the persistent map header */
	kernel_write(file[rec_id], map_hdr[rec_id], sizeof(**map_hdr), 0);

	return 0;
}

int bpf_persist_map_write(struct bpf_ringbuf_record *hdr, unsigned long rec_pos)
{
	unsigned int rec_id;
	void* rb_ptr = bpf_ringbuf_restore_from_record(hdr);

	if (prep_buf_ptr == rb_ptr) {
		rec_id = 0;
	} else {
		rec_id = 1;
	}
	__bpf_persist_map_write_hdr(rb_ptr);

	loff_t offset = rec_pos + sizeof(**map_hdr);
	kernel_write(file[rec_id], hdr, hdr->len + 8, &offset);

	/* call fsync on it */
	/* if do_fsync is true here, the locks are broken */
	BUG_ON(READ_ONCE(persistd_data->do_fsync));

	/* set do_fsync to true */
	WRITE_ONCE(persistd_data->file, file[rec_id]);
	WRITE_ONCE(persistd_data->do_fsync, true);

	/* wake the kthread */
	wake_up_process(kth_ptr);

	/* wait for do_fsync to be false before returning */
	while (READ_ONCE(persistd_data->do_fsync))
		;

	return 0;
}

void bpf_persist_map_close(char *name)
{
	unsigned int rec_id;
	if (strcmp(name, "map_prepare_buf") == 0) {
		rec_id = 0;
	} else {
		rec_id = 1;
	}

	/* Close the file if it's open */
	if (file[rec_id]) {
		filp_close(file[rec_id], NULL);
	}

	/* Free the allocated map header */
	if (map_hdr[rec_id]) {
		kfree(map_hdr[rec_id]);
		refcnt--;
	}

	if (refcnt == 0) {
		kfree(map_hdr);
		kfree(file);
	}

	printk(KERN_INFO
	       "BPF_PERSIST: Map and file resources have been released\n");
}
