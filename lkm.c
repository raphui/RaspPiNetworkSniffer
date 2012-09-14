#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/skbuff.h>

#define DRIVER_NAME "SniffDriver"

struct packet_type proto;

int sniffDriver_sniff( struct sk_buff *skb , struct net_device *dev , struct packet_type *pkt , struct net_device *dev2 )
{
  struct ethhdr *ethH;
  struct iphdr *ipH;
  
  unsigned char *ptr_src;
  unsigned char *ptr_dst;
  
  int len;
  
  len = skb->len;
  
  if( len > ETH_DATA_LEN )
  {
    printk( KERN_ALERT "[-]%s: Error with the len of the packet.\n", DRIVER_NAME );
    
    return -ENOMEM;
  }
  
  ethH = ( struct ethhdr *)skb->mac_header;
  
  if( ethH )
  {
    switch( ntohs( ethH->h_proto ) )
    {
      case ETH_P_RARP:
	break;
	
      case ETH_P_ARP:
	printk( KERN_DEBUG "[+]%s: New ARP Packet received.\n", DRIVER_NAME );
	break;
      
      case ETH_P_IP:
	ipH = ( struct iphdr *)skb->network_header;
	ptr_src = ( unsigned char *) &( ipH->saddr );
	ptr_dst = ( unsigned char *) &( ipH->daddr );
	printk( KERN_DEBUG "[+]%s: New IP Packet received.\n" , DRIVER_NAME );
	printk( KERN_DEBUG "[+] %d.%d.%d.%d ==> %d.%d.%d.%d\n",
	      ptr_src[0], ptr_src[1], ptr_src[2], ptr_src[3],
	      ptr_dst[0], ptr_dst[1], ptr_dst[2], ptr_dst[3] );
	break;
	
      default:
	printk( KERN_DEBUG "[+]%s: Unknown Packet received.\n" , DRIVER_NAME );
	break;
    }
  }
  else
  {	
    printk( KERN_ALERT "[-]%s: Ethernet Header is NULL.\n", DRIVER_NAME );
  }
  
  dev_kfree_skb( skb );
  
  return 0;
  
}

static int __init sniffDriver_init( void )
{
  proto.type = htons( ETH_P_ALL );
  proto.dev = NULL;
  proto.func = sniffDriver_sniff;
  
  dev_add_pack( &proto );
  
  printk( KERN_DEBUG "[+]%s: Load module.\n", DRIVER_NAME );
    
  return 0;
}

static void __exit sniffDriver_exit( void )
{
  dev_remove_pack( &proto );
  
  printk( KERN_DEBUG "[+]%s: Unload module.\n", DRIVER_NAME );
}

module_init( sniffDriver_init );
module_exit( sniffDriver_exit );
