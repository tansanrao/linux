// SPDX-License-Identifier: GPL-2.0-only
/*
 * Persistence Framework for eBPF Maps
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

struct file **file;

/* ccmapd related */
unsigned int refcnt = 0;
static struct task_struct *kth_ptr;
struct ccmapd_data *ccmapd_data;
unsigned long flags;


/* kthread for ccmapd */
int ccmapd(void *data)
{
	while (!kthread_should_stop()) {
		// if queue empty, sleep until woken up
		schedule_timeout_interruptible(MAX_SCHEDULE_TIMEOUT);
	}

	printk(KERN_INFO "[ccmapd]: thread stopped\n");
	return 0;
}

int bpf_persist_kthread_init(void)
{
	char th_name[20];
	sprintf(th_name, "ccmapd");
	kth_ptr = kthread_create(ccmapd, ccmapd_data,
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
	/* Initialize ccmapd if it isn't already running */
	if(refcnt == 0) {
		file = kzalloc(sizeof(**file) * 2, GFP_ATOMIC);
		/* setup ccmapd */
		ccmapd_data =
			kzalloc(sizeof(struct ccmapd_data), GFP_ATOMIC);
		/* init kthread */
		bpf_persist_kthread_init();
	}
	refcnt++;

	return 0;
}

void bpf_persist_map_close(char *name)
{
	refcnt--;
	printk(KERN_INFO
	       "[ccmapd]: Map and file resources have been released\n");
	/* Cleanup and unload kthread if this is the last instance */
	if (refcnt == 0) {
		kthread_stop(kth_ptr);
		kfree(ccmapd_data);
		printk(KERN_INFO "[ccmapd]: Kthread stopped\n");
	}
}
