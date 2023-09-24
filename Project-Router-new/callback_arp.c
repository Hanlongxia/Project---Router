#include "callback_arp.h"
#include "arp_link.h"
//*************************ARP应答的IP和MAC存入缓存链表线程【开始】**************//
void * arp_pthread(void *arg)
{
    arp_mac_ip *p = (arp_mac_ip*)arg;
    
    //printf("将 ARP 应答的 IP 和 MAC 存入缓存链\n");
    //printf("### %s\n", p->stc_ip);
    if(arp_searcharpLink(arplink_head, p->stc_ip) == 0)
    {
        //printf("插入链表中没有的ARP 应答 IP 和 MAC\n");
        arplink_head = arp_pTailInsert( arplink_head, p->stc_mac ,p->stc_ip);
    }

    pthread_exit(NULL);
}
//*************************ARP应答的IP和MAC存入缓存链表线程【结束】***************//
