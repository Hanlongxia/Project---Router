#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "ip_file.h"
#include "arp_link.h"
//回调函数中的函数的参数，记得要是共用的全局变量
typedef void (*FUN) (void);

typedef struct cmd{
	char cmd_str[20];//保存结构体指针数组中的字符串
	FUN fun;//保存回调函数名（相当于指针）
}KEY_CMD;
/******************************************************************
函	数:	void help(char *msg)
功	能:	帮助信息
参	数:	无
返回值: 无
*******************************************************************/
void help()
{

    printf("[人机交互线程的全部功能]\n");
    printf("2：设置过滤 IP \n");
    printf("3：删除过滤 IP \n");
    printf("4：查看过滤 IP \n");
    printf("5：查看 arp 缓存 \n");
    printf("6：保存2命令输入IP \n");
    printf("10：退出路由器\n");

}
/******************************************************************
函	数:	void setip(char *msg)
功	能:	添加IP过滤条件
参	数:	char *msg 待过滤的IP
返回值: 无
*******************************************************************/
void setip()
{
    roulink_head = rou_pTailInsert(roulink_head);
}
/******************************************************************
函	数:	void delip(char *msg)
功	能:	删除IP过滤条件
参	数:	char *msg 待删除的IP
返回值: 无
*******************************************************************/
void delip()
{
    roulink_head = rou_pDeleteLink(roulink_head);
}
/******************************************************************
函	数:	void showip(char *msg)
功	能:	显示IP过滤列表
参	数:	无
返回值: 无
*******************************************************************/
void showip()
{
	rou_print_link(roulink_head);
}
/******************************************************************
函	数:	void showarp(char *msg)
功	能:	显示ARP列表
参	数:	无
返回值: 无
*******************************************************************/
void showarp()
{
	arp_print_link(arplink_head);
}
/******************************************************************
函	数:	void saveset(char *msg)
功	能:	将链表中的过滤条件保存到配置文档
参	数:	无
返回值: 无
*******************************************************************/
void saveset()
{
	save_ip_link();
}
/******************************************************************
函	数:	void exit_route(char *msg)
功	能:	退出程序
参	数:	无
返回值: 无
*******************************************************************/
void exit_route(){
	//save_ip_link();
	roulink_head = rou_freeLink(roulink_head);
	arplink_head = arp_freeLink(arplink_head);
	_exit(1);
}

KEY_CMD key_cmd[]=
{
	{"1",help},
	{"2",setip},
	{"3",delip},
	{"4",showip},
	{"5",showarp},
	{"6",saveset},
	{"10",exit_route}
};

void *key_pthread(void *arg)
{
	printf("------------key_pthread------------------\n");
	help("--");
	while(1)
    {
		char buff[100]="";
		char cmd[100]="";
		char msg[100]="";

		fgets(buff,sizeof(buff),stdin);
		buff[strlen(buff)-1]='\0';
		sscanf(buff,"%s",cmd);
		printf("cmd = %s  \n", cmd);

		int i;
		for(i=0; i < (sizeof(key_cmd)/sizeof(KEY_CMD)); i++)
        {
			//输入的字符串 和 指针数组中（1-10字符串）作比较
			if(strcmp(cmd, key_cmd[i].cmd_str)==0)
            {
				printf("key_cmd[i].cmd_str = %s\n",key_cmd[i].cmd_str);
				key_cmd[i].fun();
				break;
			}
		}
	}
	return NULL;
}