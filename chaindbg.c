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
#if defined(CONFIG_IPV6) || (defined(CONFIG_IPV6_MODULE) && defined(MODULE))
#include <net/if_inet6.h>
#include <net/addrconf.h>
#endif

#define ND_END NETDEV_JOIN

static const char *ND_EVENTS[] = {
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

static const char *netdev_features_strings[] = {
	"tx-scatter-gather",
	"tx-checksum-ipv4",
	"UNUSED_NETIF_F_1",
	"tx-checksum-ip-generic",
	"tx-checksum-ipv6",
	"highdma",
	"tx-scatter-gather-fraglist",
	"tx-vlan-hw-insert",
	"rx-vlan-hw-parse",
	"rx-vlan-filter",
	"vlan-challenged",
	"tx-generic-segmentation",
	"tx-lockless",
	"netns-local",
	"rx-gro",
	"rx-lro",
	"tx-tcp-segmentation",
	"tx-udp-fragmentation",
	"tx-gso-robust",
	"tx-tcp-ecn-segmentation",
	"tx-tcp6-segmentation",
	"tx-fcoe-segmentation",
	"GSO_RESERVED1",
	"GSO_RESERVED2",
	"tx-checksum-fcoe-crc",
	"tx-checksum-sctp",
	"fcoe-mtu",
	"rx-ntuple-filter",
	"rx-hashing",
	"rx-checksum",
	"tx-nocache-copy",
	"loopback",
	"rx-fcs",
	"rx-all",
	NULL
};

static const char *netdev_flags[] =
{
	"IFF_UP",
	"IFF_BROADCAST",
	"IFF_DEBUG",
	"IFF_LOOPBACK",
	"IFF_POINTOPOINT",
	"IFF_NOTRAILERS",
	"IFF_RUNNING",
	"IFF_NOARP",
	"IFF_PROMISC",
	"IFF_ALLMULTI",
	"IFF_MASTER",
	"IFF_SLAVE",
	"IFF_MULTICAST",
	"IFF_PORTSEL",
	"IFF_AUTOMEDIA",
	"IFF_DYNAMIC",
	"IFF_LOWER_UP",
	"IFF_DORMANT",
	"IFF_ECHO",
	NULL
};

/* Not yet
static const char *netdev_priv_flags[] =
{
	"IFF_802_1Q_VLAN",
	"IFF_EBRIDGE",
	"IFF_SLAVE_INACTIVE",
	"IFF_MASTER_8023AD",
	"IFF_MASTER_ALB",
	"IFF_BONDING",
	"IFF_SLAVE_NEEDARP",
	"IFF_ISATAP",
	"IFF_MASTER_ARPMON",
	"IFF_WAN_HDLC",
	"IFF_XMIT_DST_RELEASE",
	"IFF_DONT_BRIDGE",
	"IFF_DISABLE_NETPOLL",
	"IFF_MACVLAN_PORT",
	"IFF_BRIDGE_PORT",
	"IFF_OVS_DATAPATH",
	"IFF_TX_SKB_SHARING",
	"IFF_UNICAST_FLT",
	"IFF_TEAM_PORT",
	"IFF_SUPP_NOFCS",
	"IFF_LIVE_ADDR_CHANGE",
	NULL
};
*/

void cdbg_get_strings(unsigned long long bits, int bitlen, const char *strings[], char *buf, int buflen)
{
	int i;
	for(i=0;i<bitlen%((sizeof(unsigned long long)*8)+1);i++) {
		if ((bits>>i) & 0x1) {
			if (strings[i] == NULL)
				return;
			else
				snprintf(buf, buflen, "%s %s", buf, strings[i]);
		}
	}
}

#ifdef CONFIG_INET
static int cdbg_netdev_event(struct notifier_block *this,
				unsigned long event, void *ptr)
{
	struct net_device *dev = (struct net_device *)ptr;
	int buflen = 128 * sizeof(netdev_features_strings);
	char *nd_buf;

	nd_buf = kzalloc(buflen, GFP_KERNEL);
	if (nd_buf == NULL) 
		return NOTIFY_DONE;

	if (event > ND_END) {
		snprintf(nd_buf, buflen, "C: NETDEV DEV: %s EVENT: 0x%lx", dev->name, event);
		goto done;
	}
	snprintf(nd_buf, buflen, "C: NETDEV DEV: %s EVENT: NETDEV_%s (0x%lx)", dev->name, ND_EVENTS[event], event);

	switch (event) {
		case NETDEV_CHANGEADDR:
			snprintf(nd_buf, buflen, "%s MAC: %pM", nd_buf, dev->dev_addr);
		break;

		case NETDEV_CHANGEMTU:
			snprintf(nd_buf, buflen, "%s MTU: %d", nd_buf, dev->mtu);
		break;
		
		case NETDEV_PRE_TYPE_CHANGE:
		case NETDEV_POST_TYPE_CHANGE:
			snprintf(nd_buf, buflen, "%s TYPE: 0x%x", nd_buf, dev->type);
		break;

		case NETDEV_CHANGE:
			snprintf(nd_buf, buflen, "%s FLAGS: (0x%x)", nd_buf, dev->flags);
			cdbg_get_strings(dev->flags, sizeof(dev->flags)*8, (const char **)&netdev_flags, nd_buf, buflen);
		break;

		case NETDEV_FEAT_CHANGE:
			snprintf(nd_buf, buflen, "%s FEATURES: (0x%llx)", nd_buf, (unsigned long long)(dev->features));
			cdbg_get_strings((unsigned long long)(dev->features), NETDEV_FEATURE_COUNT, (const char **)&netdev_features_strings, nd_buf, buflen);
		break;

		default:
		break;
	}
done:
	nd_buf[strlen(nd_buf) >= buflen ? strlen(nd_buf) - 1 : strlen(nd_buf)] = '\n';
	printk(KERN_INFO "%s", nd_buf);
	kfree(nd_buf);

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

#if defined(CONFIG_IPV6) || (defined(CONFIG_IPV6_MODULE) && defined(MODULE))
static int cdbg_inet6addr_event(struct notifier_block *this,
				unsigned long event, void *ptr)
{
	struct inet6_ifaddr *ifa = (struct inet6_ifaddr *)ptr;
	struct net_device *dev;

	dev = ifa->idev ? ifa->idev->dev : NULL;
	if (dev == NULL)
		goto done;

	if (event > ND_END) {
		printk(KERN_INFO "C: INET6ADDR DEV: %s EVENT: 0x%lx ADDR: %pI6\n", dev->name, event, &ifa->addr);
		goto done;
	}
	printk(KERN_INFO "C: INET6ADDR DEV: %s EVENT: NETDEV_%s (0x%lx) ADDR: %pI6\n", dev->name, ND_EVENTS[event], event, &ifa->addr);

done:
	return NOTIFY_DONE;
}

static struct notifier_block	cdbg_inet6addr_cb = {
	.notifier_call = cdbg_inet6addr_event,
};
#endif /* IPV6 */

static int __init cdbg_init(void)
{
	printk(KERN_INFO "CHAINDBG loading\n");
#ifdef CONFIG_INET
	register_netdevice_notifier(&cdbg_netdev_cb);
	register_inetaddr_notifier(&cdbg_inetaddr_cb);
#endif
#if defined(CONFIG_IPV6) || (defined(CONFIG_IPV6_MODULE) && defined(MODULE))
	register_inet6addr_notifier(&cdbg_inet6addr_cb);
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
#if defined(CONFIG_IPV6) || (defined(CONFIG_IPV6_MODULE) && defined(MODULE))
	unregister_inet6addr_notifier(&cdbg_inet6addr_cb);
#endif
}

module_init(cdbg_init);
module_exit(cdbg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nikolay Aleksandrov <nik@BlackWall.org>");
