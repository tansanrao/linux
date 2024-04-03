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
struct file *file;
struct bpf_persist_map_hdr *map_hdr;
char filepath[100];
static struct task_struct *kth_ptr;

/* kthread for bpf_persistd */
int bpf_persistd(void *data)
{
	struct bpf_persistd_data *d = (struct bpf_persistd_data *)data;

	printk(KERN_INFO "[bpf_persistd]: thread started \n");

	while (!kthread_should_stop()) {
		if (READ_ONCE(d->do_fsync)) {
			printk(KERN_INFO "[bpf_persistd]: doing fsync\n");
			vfs_fsync(d->file, 1);
			WRITE_ONCE(d->do_fsync, false);
			printk(KERN_INFO "[bpf_persistd]: done fsync\n");
		}

		// sleep after doing this job until woken up again
		printk(KERN_INFO "[bpf_persistd]: going to sleep\n");
		schedule_timeout_interruptible(MAX_SCHEDULE_TIMEOUT);
		printk(KERN_INFO "[bpf_persistd]: woke up\n");
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

int bpf_persist_map_open(u32 id, char *name, char *filepath, u32 size)
{
	/* Create the persistent map header */
	map_hdr = kzalloc(sizeof(struct bpf_persist_map_hdr), GFP_ATOMIC);

	map_hdr->id = id;
	strscpy(map_hdr->name, name, 16);
	map_hdr->cons_pos = 0;
	map_hdr->prod_pos = 0;

	// Open or create the file with write permissions
	// Note: Using O_WRONLY | O_CREAT to write and create the file if it does not exist
	file = filp_open(filepath, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (IS_ERR(file)) {
		printk(KERN_ERR "BPF_PERSIST: Error opening file %s\n",
		       filepath);
		kfree(map_hdr);
		return PTR_ERR(file);
	}
	printk(KERN_INFO "BPF_PERSIST: Map file created %s\n", filepath);
	printk(KERN_INFO "BPF_PERSIST: sizeof map header %ld\n",
	       sizeof(*map_hdr));
	printk(KERN_INFO "BPF_PERSIST: sizeof record header %ld\n",
	       sizeof(struct bpf_ringbuf_record));

	/* setup bpf_persistd and start the kthread */
	persistd_data = kzalloc(sizeof(struct bpf_persistd_data), GFP_ATOMIC);
	persistd_data->file = file;
	persistd_data->do_fsync = false;
	initialize_kthread();

	/* write the persistent map header */
	kernel_write(file, map_hdr, sizeof(*map_hdr), 0);

	/* call fsync on it */
	/* check and wait for do_fsync to be false */
	while (READ_ONCE(persistd_data->do_fsync)) {
		printk(KERN_WARNING
		       "BPF_PERSIST: do_fsync was true and we entered another write\n");
	}

	printk(KERN_INFO "BPF_PERSIST: setting do_fsync");

	WRITE_ONCE(persistd_data->do_fsync, true);

	/* wake the kthread */
	wake_up_process(kth_ptr);

	/* wait for do_fsync to be false before returning */
	while (READ_ONCE(persistd_data->do_fsync))
		;

	return 0;
}

int __bpf_persist_map_write_hdr()
{
	/* write the persistent map header */
	kernel_write(file, map_hdr, sizeof(*map_hdr), 0);

	return 0;
}

int bpf_persist_map_write(struct bpf_ringbuf_record *hdr, unsigned long rec_pos)
{
	__bpf_persist_map_write_hdr();

	loff_t offset = rec_pos + sizeof(*map_hdr);
	printk(KERN_INFO "BPF_PERSIST: new record! len=%d, pg_off=%d \n",
	       hdr->len, hdr->pg_off);
	kernel_write(file, hdr, hdr->len + 8, &offset);

	/* check and wait for do_fsync to be false */
	while (READ_ONCE(persistd_data->do_fsync)) {
		printk(KERN_WARNING
		       "BPF_PERSIST: do_fsync was true and we entered another write\n");
	}

	printk(KERN_INFO "BPF_PERSIST: setting do_fsync");

	WRITE_ONCE(persistd_data->do_fsync, true);

	/* wake the kthread */
	wake_up_process(kth_ptr);

	/* wait for do_fsync to be false before returning */
	while (READ_ONCE(persistd_data->do_fsync))
		;

	return 0;
}

void bpf_persist_map_update_cons_pos(unsigned long pos)
{
	map_hdr->cons_pos = pos;
}

void bpf_persist_map_update_prod_pos(unsigned long pos)
{
	map_hdr->prod_pos = pos;
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
