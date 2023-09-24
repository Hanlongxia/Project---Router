#ifndef IP_FILE_H
#define IP_FILE_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>


//*************************过滤链表******************************
typedef struct myrouter
{
    unsigned char ip[32] ;
    struct myrouter* next;
}MY_ROU;
extern MY_ROU * roulink_head;
//释放链表
extern MY_ROU* rou_freeLink(MY_ROU *head);
//尾插
extern MY_ROU *rou_pTailInsert(MY_ROU *head);
//遍历
extern void rou_print_link(MY_ROU *head);
//查找ip
extern int rou_searcharpLink(MY_ROU *head,char *ip);
//删除
extern MY_ROU *rou_pDeleteLink(MY_ROU *head);
//*************************过滤链表******************************

/******************************************************************
函	数:	void init_ip_link()
功	能:	读取配置文件数据到链表
参	数:	无
返回值: 无
*******************************************************************/
extern void init_ip_link();

/******************************************************************
函	数:	IP_LINK *find_ip(IP_LINK *head, unsigned char *ip)
功	能:	插入ip过滤链表
参	数:	IP_LINK *head ip过滤链表头  IP_LINK* p 待插入节点
返回值: IP_LINK *找到的节点
*******************************************************************/
extern MY_ROU *inner_ip_link(MY_ROU *head,MY_ROU* p);

/******************************************************************
函	数:	void save_ip_link()
功	能:	保存链表数据到配置文件
参	数:	无
返回值: 无
*******************************************************************/
extern void save_ip_link();

#endif