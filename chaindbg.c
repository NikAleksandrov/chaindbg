/*
 * chaindbg.c
 * Linux kernel networking subsystem chains debug module
 *
 * This module will register chain handlers and print information about events 
 * which have occurred with useful additional information related to them.
 *
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) Nikolay Aleksandrov (nik@BlackWall.org) 2012 
 */

#include <linux/module.h>	
#include <linux/kernel.h>
#include <linux/init.h>	
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/inetdevice.h>
#include <linux/if_vlan.h>

#define ND_END NETDEV_JOIN

#ifdef CONFIG_INET

const char *ND_EVENTS[] = {
	"",
	"UP",
	"DOWN",
	"REBOOT",
	"CHANGE",
	"REGISTER",
	"UNREGISTER",
	"CHANGEMTU",
	"CHANGEADDR",
	"GOING_DOWN",
	"CHANGENAME",
	"FEAT_CHANGE",
	"BONDING_FAILOVER",
	"PRE_UP",
	"PRE_TYPE_CHANGE",
	"POST_TYPE_CHANGE",
	"POST_INIT",
	"UNREGISTER_FINAL",
	"RELEASE",
	"NOTIFY_PEERS",
	"JOIN",
	NULL
};

static int cdbg_netdev_event(struct notifier_block *this,
				unsigned long event, void *ptr)
{
	struct net_device *dev = (struct net_device *)ptr;
	char nd_buf[128];

	if (event > ND_END) {
		snprintf(nd_buf, sizeof(nd_buf), "C: NETDEV DEV: %s EVENT: 0x%lx\n", dev->name, event);
		goto done;
	}
	snprintf(nd_buf, sizeof(nd_buf), "C: NETDEV DEV: %s EVENT: NETDEV_%s (0x%lx)", dev->name, ND_EVENTS[event], event);

	switch (event) {
		case NETDEV_CHANGEADDR:
			snprintf(nd_buf, sizeof(nd_buf), "%s MAC: %pM\n", nd_buf, dev->dev_addr);
		break;

		case NETDEV_CHANGEMTU:
			snprintf(nd_buf, sizeof(nd_buf), "%s MTU: %d\n", nd_buf, dev->mtu);
		break;
		
		case NETDEV_PRE_TYPE_CHANGE:
		case NETDEV_POST_TYPE_CHANGE:
			snprintf(nd_buf, sizeof(nd_buf), "%s TYPE: 0x%x\n", nd_buf, dev->type);
		break;

		case NETDEV_CHANGE:
			snprintf(nd_buf, sizeof(nd_buf), "%s FLAGS: %u\n", nd_buf, dev->flags);
		break;

		case NETDEV_FEAT_CHANGE:
			snprintf(nd_buf, sizeof(nd_buf), "%s FEATURES: %llu\n", nd_buf, (unsigned long long)(dev->features));
		break;

		default:
			snprintf(nd_buf, sizeof(nd_buf), "%s\n", nd_buf);
		break;
	}
done:
	printk(KERN_INFO "%s", nd_buf);
	return NOTIFY_DONE;
}

static int cdbg_inetaddr_event(struct notifier_block *this,
				unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *dev;

        dev = ifa->ifa_dev ? ifa->ifa_dev->dev : NULL;
	if (dev == NULL)
		goto done;

	if (event > ND_END) {
		printk(KERN_INFO "C: INETADDR DEV: %s EVENT: 0x%lx ADDR: %pI4\n", dev->name, event, &ifa->ifa_address);
		goto done;
	}
	printk(KERN_INFO "C: INETADDR DEV: %s EVENT: NETDEV_%s (0x%lx) ADDR: %pI4\n", dev->name, ND_EVENTS[event], event, &ifa->ifa_address);

done:
	return NOTIFY_DONE;
}

static struct notifier_block	cdbg_netdev_cb = {
	.notifier_call = cdbg_netdev_event,
};

static struct notifier_block	cdbg_inetaddr_cb = {
	.notifier_call = cdbg_inetaddr_event,
};
#endif /* CONFIG_INET */

static int __init cdbg_init(void)
{
	printk(KERN_INFO "CHAINDBG loading\n");
#ifdef CONFIG_INET
	register_netdevice_notifier(&cdbg_netdev_cb);
	register_inetaddr_notifier(&cdbg_inetaddr_cb);
#endif
	return 0;
}

static void __exit cdbg_exit(void)
{
	printk(KERN_INFO "CHAINDBG unloading\n");
#ifdef CONFIG_INET
	unregister_netdevice_notifier(&cdbg_netdev_cb);
	unregister_inetaddr_notifier(&cdbg_inetaddr_cb);
#endif
}

module_init(cdbg_init);
module_exit(cdbg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nikolay Aleksandrov <nik@BlackWall.org>");
