#include "arp_link.h"

MY_ARP * arplink_head = NULL;
//*************************arp缓存表*****************************
//arp缓存表尾插
MY_ARP *arp_pTailInsert(MY_ARP *head,char *mac,char *ip)
{
    //申请一个待插入的空间
    MY_ARP *pi=(MY_ARP*)malloc(sizeof(MY_ARP));
    pi->next=NULL;
    //向空间中插入数据
    strcpy(pi->ip,ip);
    strcpy(pi->mac,mac);
    //判断是否有数据
    if(head==NULL)
    {
        head=pi;
    }
    else
    {
        //寻找插入的节点
        MY_ARP *p1=head;
        while(p1->next!=NULL)
        {
            p1=p1->next;
        }
        //插入
        p1->next=pi;
    }
    printf("插入一个ip:%s    mac:%s 到arp缓存表\n",pi->ip,pi->mac);
    return head;
}

//arp中查找ip和mac
int arp_searcharpLink(MY_ARP *head,char *ip)
{
    int i=0;
    while(head!=NULL)
    {
        if(strcmp(ip,head->ip)==0)
        {
            i++;
            //printf("存在相同ip和mac\n");
            return 1;
        }
        head=head->next;
    }
    if(0==i)
    {
        //printf("未找到ip和mac\n");
        return 0;
    }
}

//遍历arp缓存表
void arp_print_link(MY_ARP *head)
{
    if(head==NULL)
    {
        printf("没有数据\n");
    }
    else
    {
        while(head!=NULL)
        {
            printf("ip：%s mac：%s\n",head->ip,head->mac);
            head=head->next;
        }
    }
    return;
}

//释放arp链表
MY_ARP* arp_freeLink(MY_ARP *head)
{
    MY_ARP *pd;
    pd=head;
    while(head!=NULL)
    {
        head=pd->next;
        free(pd);
        pd=head;
    }
    printf("arp链表释放完毕\n");
    return head;
}
//*************************arp缓存表*****************************