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

/* ccmap requirements */
struct ccmap **map_table = NULL;
struct ccmapd_job *job_queue = NULL;

/* ccmapd kthread requirements */
unsigned int refcnt = 0;
static struct task_struct *kth_ptr;
struct ccmapd_data *ccmapd_data;

/* queue management APIs */
void ccmap_queue_init(struct ccmap_job_queue *queue)
{
	INIT_LIST_HEAD(&queue->head); // Initialize the list head
	spin_lock_init(&queue->lock); // Initialize the spinlock
}

void ccmap_job_enqueue(struct ccmap_job_queue *queue, struct ccmap_job *job)
{
	struct ccmap_job_queue_node *new_node =
		kmalloc(sizeof(struct ccmap_job_queue_node), GFP_ATOMIC);
	if (!new_node) {
		printk(KERN_ERR
		       "[ccmapd]: Failed to allocate memory for new node\n");
		return;
	}

	new_node->job = job;
	INIT_LIST_HEAD(&new_node->list);

	// Grab lock before inserting node
	unsigned long flags;
	spin_lock_irqsave(&queue->lock, flags);
	list_add_tail(&new_node->list, &queue->head);
	spin_unlock_irqrestore(&queue->lock, flags);
}

int ccmap_job_dequeue(struct ccmap_job_queue *queue, struct ccmap_job **job)
{
	struct ccmap_job_queue_node *node;
	int ret = 0;

	// Grab lock before removing node
	unsigned long flags;
	spin_lock_irqsave(&queue->lock, flags);
	if (list_empty(&queue->head)) {
		ret = -1; // Return -1 if queue is empty
	} else {
		node = list_first_entry(&queue->head,
					struct ccmap_job_queue_node, list);
		*job = node->job;
		list_del(&node->list);
		kfree(node);
	}
	spin_unlock_irqrestore(&queue->lock, flags);

	return ret;
}

void ccmap_queue_cleanup(struct ccmap_job_queue *queue)
{
	struct ccmap_job_queue_node *node, *tmp;

	// Lock the list while cleaning up
	unsigned long flags;
	spin_lock_irqsave(&queue->lock, flags);
	list_for_each_entry_safe(node, tmp, &queue->head, list) {
		list_del(&node->list);
		kfree(node);
	}
	spin_unlock_irqrestore(&queue->lock, flags);
}

/* kthread for ccmapd */
int ccmapd(void *data)
{
	struct ccmap_job *job;
	while (!kthread_should_stop()) {
		// Check if job in queue
		while (ccmap_job_dequeue(ccmapd_data->job_queue, &job) != -1) {
			// printk(KERN_INFO "[ccmapd]: job dequeued\n");
			if (job) {
				BUG_ON(READ_ONCE(job->done));
				kernel_write(job->file, job->data, job->len,
					     job->pos);
				// printk(KERN_INFO "[ccmapd]: Written to disk\n");
				WRITE_ONCE(job->done, true);
			} else {
				printk(KERN_ERR
				       "[ccmapd]: Job NULL for some reason\n");
			}
		}

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
	kth_ptr = kthread_create(ccmapd, ccmapd_data, (const char *)th_name);
	if (kth_ptr != NULL) {
		wake_up_process(kth_ptr);
		printk(KERN_INFO "[ccmapd]: %s is running\n", th_name);
	} else {
		printk(KERN_INFO "[ccmapd]: kthread %s could not be created\n",
		       th_name);
		return -1;
	}
	return 0;
}

static int __write(struct file *file, void *data, size_t len, loff_t *pos)
{
	/* create job for ccmapd */
	struct ccmap_job *job = kmalloc(sizeof(struct ccmap_job), GFP_ATOMIC);
	if (!job) {
		printk(KERN_ERR "[ccmapd]: Error allocating job for ccmapd\n");
		return -1;
	}

	job->file = file;
	job->data = data;
	job->len = len;
	job->pos = pos;
	job->done = false;

	/* push job onto queue */
	ccmap_job_enqueue(ccmapd_data->job_queue, job);

	/* wake kthread if required */
	wake_up_process(kth_ptr);

	/*  spin until job is done */
	while (!READ_ONCE(job->done)) {
		cpu_relax();
	}

	/* free up memory */
	kfree(job);

	return 0;
}

int bpf_persist_map_open(u32 id, char *name, u32 map_type)
{
	printk(KERN_INFO "[ccmapd]: map_open id: %u, name: %s, map_type: %u",
	       id, name, map_type);

	/* Initialize ccmapd if it isn't already running */
	if (refcnt == 0) {
		/* setup ccmap table */
		map_table =
			kmalloc(sizeof(struct ccmap *) * MAX_MAPS, GFP_KERNEL);
		for (int i = 0; i < MAX_MAPS; i++)
			map_table[i] = NULL;

		/* setup data for ccmapd startup */
		ccmapd_data = kmalloc(sizeof(struct ccmapd_data), GFP_KERNEL);
		ccmapd_data->job_queue =
			kmalloc(sizeof(struct ccmap_job_queue), GFP_KERNEL);
		ccmap_queue_init(ccmapd_data->job_queue);

		/* init kthread */
		bpf_persist_kthread_init();
	}
	refcnt++;

	/* Initialize map */
	struct ccmap *map = kmalloc(sizeof(struct ccmap), GFP_KERNEL);
	if (!map) {
		printk(KERN_ERR "[ccmapd]: kmalloc fail on map init\n");
		// TODO: Cleanup memory
		return -1;
	}
	strscpy(map->name, name, 16U);
	map->id = id;
	map->map_type = map_type;
	spin_lock_init(&map->lock);
	map_table[id] = map;

	/* create file for persistence log */
	char filepath[255];
	snprintf(filepath, sizeof(filepath), "%s/%s", CCMAPS_MOUNT_PATH,
		 map->name);
	map->file = filp_open(filepath,
			      O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (IS_ERR(map->file)) {
		printk(KERN_ERR "[ccmapd]: Error opening file\n");
		// TODO: Cleanup memory
	}
	/* write map metadata header */
	__write(map->file, map, sizeof(struct ccmap), 0);
	/* update on disk index */

	return 0;
}

int ccmap_map_write(u32 id, void *data, size_t len, loff_t *pos)
{
	__write(map_table[id]->file, data, len, pos);
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
