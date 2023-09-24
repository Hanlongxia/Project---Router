#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define RECV_SIZE 2048

//用来保存线程3中，传递过来的是ICMP包，的MTU包所有数据
typedef struct My_buf
{
    unsigned char buf[RECV_SIZE];
    int my_buf_date_len;
}ip_buf;

//保存arp缓存表信息
typedef struct Arp_mac_ip
{
    char stc_mac[18];
    char stc_ip[16];
}arp_mac_ip;


//*************************arp缓存表*****************************
typedef struct myarp
{
    unsigned char mac[32] ;
    unsigned char ip[32] ;

    struct myarp* next;
}MY_ARP;

//.c文件中定义成全局变量，头文件extern声明，可以被外部的文件使用
//后续对arp头节点的操作，就是用该结构体指针变量
extern MY_ARP * arplink_head;

//arp缓存表尾插
extern MY_ARP *arp_pTailInsert(MY_ARP *head,char *mac,char *ip);
//arp中查找ip
extern int arp_searcharpLink(MY_ARP *head,char *ip);
//遍历arp缓存表
extern void arp_print_link(MY_ARP *head);
//释放arp链表
extern MY_ARP* arp_freeLink(MY_ARP *head);
//*************************arp缓存表*****************************


