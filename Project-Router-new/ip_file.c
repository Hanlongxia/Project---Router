#include "ip_file.h"
#define ip_config_name "ip_config"

//与main.c共用一个结构体指针变量，保存过滤IP链表头节点
MY_ROU * roulink_head = NULL;

//--------------------操作文件中的过滤IP----------------------//
void init_ip_link()
{
    FILE *ip_config = NULL;
    ip_config = fopen(ip_config_name,"rb+");
	if(ip_config == NULL){
		perror("!!!configure file,in main.c");
		_exit(1);
	}
	puts("filter IP:");
    int i = 0;
    while(1)
    {
        
        char buff[500]="";
        bzero(buff, sizeof(buff));
        int ip;
        if(fgets(buff, sizeof(buff), ip_config) == NULL)
        {
            printf("ip_config 文件为空\n");
            break;
        }
        if(strlen(buff) < 7)//1.1.1.1
        {
            break;
        }
        buff[strlen(buff)-1]=0;                                 //注意文件中存在\r
        inet_pton(AF_INET, buff, &ip);                          //点分十进制->转换成32位无符号整形，4字节大小

        MY_ROU *pb = (MY_ROU *)malloc(sizeof(MY_ROU));          //开辟新的空间，传递堆区地址，安全	
        char ip_buf[16] = "";
        inet_ntop(AF_INET, &ip, ip_buf, 16);                    //32位无符号整形->转换成点分十进制（验证而已）
        memcpy(pb->ip, ip_buf, 16);                             //IP字符串形式是16字节大小
        

        //---------[调试]--------------------------------------//
        //printf("pb->ip[%d] = %s\n", i, pb->ip);
        //printf("IP[%d] = %s\n",i++,buff);
        //printf("ip_buf[%d] = %s\n", ++i, ip_buf);
        //strcpy(pb->ip, ip_buf);
        //---------[调试]--------------------------------------//


        //传入变化的头节点 + 带有IP信息的结构体指针变量
        roulink_head = inner_ip_link(roulink_head, pb);
        i++;
    }

    //rou_print_link(ip_head);
	fclose(ip_config);
}

MY_ROU *inner_ip_link(MY_ROU *head, MY_ROU* p)
{
    MY_ROU * pb = head;
	int a = rou_searcharpLink(head, p->ip);//查找是否有该记录
    if(a == 0)
    {
        if(pb==NULL)
        {//未查找到，插入链表，直接插入表头方便
            p->next = NULL;
            head = p;
        }
        else
        {           
            #if 1  //头插法--寻找插入的节点              
                MY_ROU * p2_new = (MY_ROU*)malloc(sizeof(MY_ROU)); 
                strcpy(p2_new->ip, p->ip);
                p2_new->next = pb->next;
                pb->next = p2_new;
            #endif                                  
            #if 0 //尾插法--正确
                MY_ROU *p1=pb;
                while(p1->next!=NULL)
                {
                    p1=p1->next;
                }
                //插入
                p1->next=p;  
            #endif             
        }
    }
	return head;
}

void save_ip_link()
{
    FILE *ip_config = fopen(ip_config_name,"wb+");
	if(ip_config == NULL){
		perror("!!!configure file,in main.c");
		_exit(1);
	}

    char buff[20]="";
	MY_ROU *pb=roulink_head;
    while(pb != NULL)
    {
        printf("！保存2命令输入IP\n");
        memcpy(buff, pb->ip, 16);//一次拷贝16个字节
        buff[strlen(buff)+1]='\n';//注意文件中存在\r

        //一个IP新切换一行保存到文件
        fprintf(ip_config, "%s\n", buff);
		pb = pb->next;
    }
    fclose(ip_config);
}
//--------------------操作文件中的过滤IP----------------------//




//*************************过滤链表******************************//
//尾插
MY_ROU *rou_pTailInsert(MY_ROU *head)
{

    //申请一个待插入的空间
    MY_ROU *pi=(MY_ROU*)malloc(sizeof(MY_ROU));
    pi->next=NULL;
    printf("输入过滤ip:");
    //向空间中插入数据
    scanf("%s",pi->ip);
    //判断是否有数据
    if(head==NULL)
    {
        head=pi;
    }
    else
    {
        //寻找插入的节点
        MY_ROU *p1=head;
        while(p1->next!=NULL)
        {
            p1=p1->next;
        }
        //插入
        p1->next=pi;
    }
    

    printf("设置完成\n");
    return head;
}

//遍历
void rou_print_link(MY_ROU *head)
{
    if(head==NULL)
    {
        printf("没有数据\n");
    }
    else
    {
        while(head!=NULL)
        {
            printf("ip：%s\n",head->ip);
            head=head->next;
        }
    }
    return;
}

//释放链表
MY_ROU* rou_freeLink(MY_ROU *head)
{
    MY_ROU *pd;
    pd=head;
    while(head!=NULL)
    {
        head=pd->next;
        free(pd);
        pd=head;
    }
    printf("过滤链表释放完毕\n");
    return head;
}

//查找ip
int rou_searcharpLink(MY_ROU *head,char *ip)
{
    MY_ROU * pb = head;
    int i=0;
    while(pb!=NULL)
    {
        if(strcmp(ip, pb->ip)==0)
        {
            i++;
            //printf("存在相同ip\n");
            return 1;
        }
        pb = pb->next;
    }
    if(0==i)
    {
        //printf("未找到ip\n");
        return 0;
    }
}

//删除
MY_ROU *rou_pDeleteLink(MY_ROU *head)
{
    char num[16]="";
    MY_ROU *pe=head;
    MY_ROU *pf=head;

    printf("请输入你要删除的ip：");
    scanf("%s",num);

    if(NULL==head)
    {
        printf("无可删除数据\n");
    }
    else
    {
        while(strcmp(pe->ip,num))
        {
            pf=pe;
            pe=pe->next;
            if(NULL==pf->next)
            {
                printf("未找到要删除数据\n");
                return head;
            }
        }

        if(pe==head)
        {
            head=pe->next;
            free(pe);
        }
        else
        {
            pf->next=pe->next;
            free(pe);
        }
    }
    return head;
}
//*************************过滤链表******************************
