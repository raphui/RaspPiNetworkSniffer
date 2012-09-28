#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h> 
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h> 
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <asm/system.h> 
#include <asm/uaccess.h>

#define DRIVER_NAME "SniffingDriver"
#define SUCCESS 0

/* Declaration of driver.c functions */
int sniffDriver_open(struct inode *inode, struct file *filp);
int sniffDriver_release(struct inode *inode, struct file *filp);
ssize_t sniffDriver_read(struct file *filp, char *buf, size_t count, loff_t *f_pos);
ssize_t sniffDriver_write(struct file *filp, char *buf, size_t count, loff_t *f_pos);
void sniffDriver_exit(void);
int sniffDriver_init(void);
int sniffDriver_sniff( struct sk_buff *skb , struct net_device *dev , struct packet_type *pkt , struct net_device *dev2 );

/* Structure that declares the usual file */
/* access functions */
struct file_operations sniffDriver_fops = {
  read: sniffDriver_read,
  write: sniffDriver_write,
  open: sniffDriver_open,
  release: sniffDriver_release
};

struct packet_type proto;

/* Declaration of the init and exit functions */
module_init(sniffDriver_init);
module_exit(sniffDriver_exit);

/* Global variables of the driver */
/* Major number */
int driver_major = 30;
int driver_busy = 0;
/* Buffer to store data */
char *driver_buffer;

int sniffDriver_sniff( struct sk_buff *skb , struct net_device *dev , struct packet_type *pkt , struct net_device *dev2 )
{
    struct ethhdr *ethH;
    struct iphdr *ipH;
  
    unsigned char *ptr_src;
    unsigned char *ptr_dest;
    int len;

    struct sk_buff *sock_buff;

    len = skb->len;

    if( len > ETH_DATA_LEN )
    {
        printk( KERN_ALERT "[-]%s: ENONMEN error return len ==> ETH_DATA_LEN\n" , DRIVER_NAME );

        return -ENOMEM;
    }

    ethH = ( struct ethhdr *)skb->mac_header;

    if( ethH )
    {


        switch( ( int )ethH->h_proto )
        {
            case ETH_P_RARP:
                break;

            case ETH_P_ARP:
                printk( KERN_INFO "[+]%s: ARP_PACKET has been captured.\n", DRIVER_NAME );
                break;
            case 8:
                ipH = ( struct iphdr *)skb->network_header;
                ptr_src = ( unsigned char * ) (&ipH->saddr);
                ptr_dest = ( unsigned char * ) (&ipH->daddr);

                printk( KERN_INFO "[+]%s: -------IP PACKET has been captured.-------\n", DRIVER_NAME );
                printk( KERN_INFO "[+]%s: %d.%d.%d.%d ==> %d.%d.%d.%d\n", DRIVER_NAME,
                          ptr_src[0] 	, ptr_src[1] 	, ptr_src[2] 	, ptr_src[3] ,
                          ptr_dest[0] 	, ptr_dest[1] 	, ptr_dest[2] 	, ptr_dest[3]);


                printk( KERN_INFO "[+]%s: Modify of the header......", DRIVER_NAME );

                //Use pskb_copy instead of skb_copy, because I just need to modify the header, so pskb_copy -> copy only header , data remains shared , skb_copy -> copy all.
                sock_buff = pskb_copy( skb , GFP_ATOMIC );

                ipH = ( struct iphdr *)sock_buff->network_header;
                ptr_src = ( unsigned char * ) (&ipH->saddr);
                ptr_dest = ( unsigned char * ) (&ipH->daddr);

                ptr_src[0] = 137;
                ptr_src[1] = 137;
                ptr_src[2] = 137;
                ptr_src[3] = 137;

                printk( KERN_INFO "[+]%s: Re-injecting the packet......." , DRIVER_NAME );

                dev_queue_xmit( sock_buff );


                break;

        case ETH_P_IP:
                ipH = ( struct iphdr *)skb->network_header;
                ptr_src = ( unsigned char * ) (&ipH->saddr);
                ptr_dest = ( unsigned char * ) (&ipH->daddr);

                printk( KERN_INFO "[+]%s: IP PACKET has been captured.\n", DRIVER_NAME );
                printk( KERN_INFO "[+]%s: %d.%d.%d.%d ==> %d.%d.%d.%d\n", DRIVER_NAME,
                            ptr_src[0] 	, ptr_src[1] 	, ptr_src[2] 	, ptr_src[3] ,
                            ptr_dest[0] 	, ptr_dest[1] 	, ptr_dest[2] 	, ptr_dest[3]);

                break;

        default:
                printk( KERN_INFO "[+]%s: ------------------ ethH->h_proto == %#x", DRIVER_NAME , ethH->h_proto );
                printk( KERN_INFO "[+]%s: An unknown has been captured.\n", DRIVER_NAME );
                break;

        }
    }
    else
    {
        printk( KERN_ALERT "[-]%s: ethH == NULL\n" , DRIVER_NAME );
    }

    dev_kfree_skb( skb );

    return 0;
}


int sniffDriver_init(void )
{
    int res = register_chrdev( driver_major , DRIVER_NAME , &sniffDriver_fops );

    proto.type = htons( ETH_P_ALL );
    proto.dev = NULL;
    proto.func = sniffDriver_sniff;

    dev_add_pack( &proto );

    if( res < 0 )
    {
        printk( KERN_ALERT "[-]%s: cannot obtain major number %d\n", DRIVER_NAME , driver_major );

        return res;
    }

    driver_buffer = kmalloc( 1 , GFP_KERNEL );

    if( !driver_buffer )
    {
         sniffDriver_exit();

         return res;
    }

    printk( KERN_INFO "[+]%s: Load driver.\n" , DRIVER_NAME);

    return 0;
}

void sniffDriver_exit( void )
{
  
    unregister_chrdev( driver_major , DRIVER_NAME );

    dev_remove_pack( &proto );

    printk( KERN_INFO "[+]%s: Unload driver.\n" , DRIVER_NAME);
}

int sniffDriver_open(struct inode* inode, struct file* filp)
{
    if( driver_busy )
    {
        return -EBUSY;
    }

    driver_busy++;

    try_module_get( THIS_MODULE );


    return SUCCESS;
}

int sniffDriver_release(struct inode* inode, struct file* filp)
{

    driver_busy--;

    module_put( THIS_MODULE );

    return SUCCESS;
}

ssize_t sniffDriver_read(struct file* filp, char* buf, size_t count, loff_t* f_pos)
{
    return 1;
}

ssize_t sniffDriver_write(struct file* filp, char* buf, size_t count, loff_t* f_pos)
{
    return 1;
}
