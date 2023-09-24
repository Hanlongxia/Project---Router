#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include "get_interface.h"
#include "arp_link.h"
#include"ip_file.h"
#include "callback_1.h"
#include "callback_arp.h"

extern MY_ROU * roulink_head;//与ip_file.c共用一个结构体指针变量，保存过滤IP链表头节点
extern MY_ARP * arplink_head;//与arp_link.c共用一个结构体指针变量，保存arp缓存表头节点
int sockfd = 0;



//*************************IP包转发线程【开始】**********************************//
void *callback3_ip(void *arg)
{
    
    //发送接口的结构体
    struct sockaddr_ll sll;
    ip_buf *pthread_ip_buf = (ip_buf *)arg;
  

    unsigned char * ip_head= pthread_ip_buf->buf + 14;
    char dst_ip[16] = "";

    inet_ntop(AF_INET, ip_head + 16, dst_ip, 16);
    printf("IP包转发线程中 目的 dst_ip = %s\n", dst_ip);


    int i = 0;
    for (i = 0; i < 16; i++)
    {
       
        unsigned char ip[16]=""; 
        inet_ntop(AF_INET,net_interface[i].ip, ip, 16);//get_interface文件中得到的都是32位无符号整形数据（计算机数据），现转成成点分十进制（人能够书别的）

        //---------------------[调试]----------------------------------------//
        //printf("设置网卡循环进入次数 i = %d\n", i);
        //printf("检索到的所有网卡名字net_interface[i].name = %s\n", net_interface[i].name);
        //printf("net_interface[i].ip = %s\n",ip);
        //---------------------[调试]----------------------------------------//

        if(strncmp(ip,  dst_ip, 9) == 0)//根据目标网段 查找活跃网卡
        {   
            //网卡结构体
            struct ifreq ethreq;
            strncpy(ethreq.ifr_name, net_interface[i].name , IFNAMSIZ);//指定网卡名字
            printf("网卡名字：%s\n", ethreq.ifr_name);
            
            if(ioctl(sockfd, SIOCGIFINDEX, &ethreq) == -1)//获取网卡接口地址
            {
                return 0;
            }

            bzero(&sll, sizeof(sll));
            sll.sll_ifindex = ethreq.ifr_ifindex;//将网卡的接口类型赋值给发送接口
            break;
        }
        else
        {
            //printf("找不到网段对应的网卡,继续查\n");
            continue;
        }
    }

    //--------------------------------------------拿到网卡，开始检索对应网卡所有数据，对比【开始】------------------------------------------------------//
    if(strcmp(dst_ip + strlen(dst_ip) - 3, "255") == 0)//是 否为广 播地址
    {
       // printf("是广播地址, 退出线\n"); 
        return;              
    }
    else
    {
        //printf("不是广播地址，判断是否为回 环地址\n");
        if(strcmp("127.0.0.1",  dst_ip) == 0)
        {
            //printf("是回 环地址, 退出线\n");
            return;                      
        }
        else
        {
            //printf("查找ARP缓存表 对应 MAC\n");
            //指定目的MAC地址
            //可以在链表中找到目的IP，组ICMP包的目的MAC就可以了
            //之所以这样，是因为在网络中的ICMP包里，变化的只有目的MAC，源MAC、IP都不会发生变动
            if(arp_searcharpLink(arplink_head, dst_ip) == 1)
            {  
                //1网段中 指定目标IP是主机的IP、MAC
                //2C-4D-54-57-04-7F
                //printf("****icmp****\n");
                if(strncmp("192.168.1.49", dst_ip, 9) == 0)
                {
                    pthread_ip_buf->buf[0]=0x2C;
                    pthread_ip_buf->buf[1]=0x4D;
                    pthread_ip_buf->buf[2]=0x54;
                    pthread_ip_buf->buf[3]=0x57;
                    pthread_ip_buf->buf[4]=0x04;
                    pthread_ip_buf->buf[5]=0x7F;//目标
                    int send_len = sendto(sockfd, pthread_ip_buf->buf, pthread_ip_buf->my_buf_date_len, 0, (struct sockaddr *)&sll, sizeof(sll));

                    //-------------------[调试]------------------------//
                    //printf("****1 网段 icmp缓存表****\n");   
                    // printf("send_len ICMP 1 = %d\n", send_len);
                    //-------------------[调试]------------------------//

                }
                //2网段中 指定目标IP是开发板的IP、MAC
                //  00:53:50:00:01:33
                else if(strncmp("192.168.2.100", dst_ip, 9) == 0)
                {                   
                    pthread_ip_buf->buf[0]=0x00;
                    pthread_ip_buf->buf[1]=0x53;
                    pthread_ip_buf->buf[2]=0x50;
                    pthread_ip_buf->buf[3]=0x00;
                    pthread_ip_buf->buf[4]=0x2C;
                    pthread_ip_buf->buf[5]=0x98;
                   
                    //发送给套接字的数据长度，是实际传送过来的长度（main中的IP包有收到具体长度信息）
                    int send_len = sendto(sockfd, pthread_ip_buf->buf, pthread_ip_buf->my_buf_date_len, 0, (struct sockaddr *)&sll, sizeof(sll));

                    //-------------------[调试]------------------------//
                    //printf("****2 网段 icmp缓存表****\n");   
                    // printf("send_len ICMP 2 = %d\n", send_len);
                    //-------------------[调试]------------------------//
                }
            }
            else
            {//没在链表中没有找到目的IP，需要重新组arp包才行

                //printf("***************组ARP包\n");
                int i = 0;
                for(; i < 3; i++)
                {     
                    //printf("%s\n",dst_ip);  
                    //比对到1网段的数据             
                    if(strstr(dst_ip,"192.168.1") != 0)                      
                    {
                        printf("发送网段1arp包\n");
                        unsigned char arp_buf[42] = {
                        0xff,0xff,0xff,0xff,0xff,0xff,//目的mac，广播的形式发出去，等待目的IP恢复后覆盖
                        0x00,0x0c,0x29,0xfa,0x7c,0x9e,//源mac
                        0x08, 0x00,//协议类型
                        0, 1,//硬件类型
                        6,
                        4,
                        0, 1,//op
                        0x00,0x0c,0x29,0xfa,0x7c,0x9e,//源mac（网卡1 ech0的MAC）
                        192,168,1,88,//源IP是路由器1网段的网关，通过它发送到2网段
                        0x00,0x00,0x00,0x00,0x00,0x00,//目的mac，等待目的IP恢复后覆盖
                        0,0,0,0
                        //192,168,1,49,
                        };
                        int int_ip=0;
                        inet_pton(AF_INET, dst_ip, &int_ip);
                        unsigned char *intp=(char *)&int_ip;
                        arp_buf[38]=intp[0];
                        arp_buf[39]=intp[1];
                        arp_buf[40]=intp[2];
                        arp_buf[41]=intp[3];
                        int send_len = sendto(sockfd, arp_buf, sizeof(arp_buf), 0, (struct sockaddr *)&sll, sizeof(sll));
                        printf("send_len 11 = %d\n",send_len);

                    }
                    //网卡2，ech1的MAC：00:0c:29:fa:7c:a8
                    else if(strstr(dst_ip,"192.168.2") != 0)                      
                    {
                        printf("发送网段2arp包\n");
                        unsigned char arp_buf[42] = {
                        0xff,0xff,0xff,0xff,0xff,0xff,//目的mac
                        0x00,0x0c,0x29,0xfa,0x7c,0xa8,//源mac
                        0x08, 0x00,//协议类型
                        0, 1,//硬件类型
                        6,
                        4,
                        0, 1,//op
                        0x00,0x0c,0x29,0xfa,0x7c,0xa8,//源mac
                        192,168,2,89,//源IP是路由器2网段的网关，通过它发送到1网段
                        0x00,0x00,0x00,0x00,0x00,0x00,//目的mac
                        192,168,2,100,
                        };
                        int send_len = sendto(sockfd, arp_buf, sizeof(arp_buf), 0, (struct sockaddr *)&sll, sizeof(sll));
                        printf("send_len 22 = %d\n",send_len);

                    }

                    if(arp_searcharpLink(arplink_head, dst_ip) == 1)
                    {
                        //1
                        //2C-4D-54-57-04-7F
                        if(strncmp("192.168.1.49", dst_ip, 9) == 0)
                        {
                            pthread_ip_buf->buf[0] =  0x2C;
                            pthread_ip_buf->buf[1] =  0x4D;
                            pthread_ip_buf->buf[2] =  0x54;
                            pthread_ip_buf->buf[3] =  0x57;
                            pthread_ip_buf->buf[4] =  0x04;
                            pthread_ip_buf->buf[5] =  0x7F;
                            int send_len = sendto(sockfd, pthread_ip_buf->buf, pthread_ip_buf->my_buf_date_len, 0, (struct sockaddr *)&sll, sizeof(sll));
                            //-------------------[调试]------------------------//
                            //printf("****3次发ARP过程中检索到ICMP包 1 网段****\n");   
                            // printf("send_len ICMP 1 = %d\n", send_len);
                            //-------------------[调试]------------------------//
                        }
                        //2
                        // 开发板MAC（每次启动都会变化）：00:53:50:00:3B:DB
                        else if(strncmp("192.168.2.100", dst_ip, 9) == 0)
                        {
                            pthread_ip_buf->buf[0] =  0x00;
                            pthread_ip_buf->buf[1] =  0x53;
                            pthread_ip_buf->buf[2] =  0x50;
                            pthread_ip_buf->buf[3] =  0x00;
                            pthread_ip_buf->buf[4] =  0x2C;
                            pthread_ip_buf->buf[5] =  0x98;
                            int send_len = sendto(sockfd, pthread_ip_buf->buf, pthread_ip_buf->my_buf_date_len, 0, (struct sockaddr *)&sll, sizeof(sll));
                            //-------------------[调试]------------------------//
                            //printf("****3次发ARP过程中检索到ICMP包 2 网段****\n");   
                            // printf("send_len ICMP 2 = %d\n", send_len);
                            //-------------------[调试]------------------------//

                        }
                        break;
                    }
                }
            }

            return;

        }
    } 
    //--------------------------------------------拿到网卡，开始检索对应网卡所有数据，对比【结束】------------------------------------------------------//


    pthread_exit(NULL);

}
//*************************建IP包转发线程【结束】**********************************//

int main()
{
    //初始化 配置文件
	init_ip_link();

    //创建原始套接字，接收发送方的网卡信息
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockfd<0)
    {
        perror("sockfd:");
        return 0;
    }
    getinterface();//拿取网卡信息（虚拟机的所有网卡，包括回环网卡）

    pthread_t pth;
    pthread_create(&pth, NULL, key_pthread, NULL);//人机交互线程，这里可以放在main里面

    int len = 0;

    char recv_buff[RECV_SIZE]="";//原始套接字数据包大约为1500个字节
	ssize_t recv_len=0;
    while(1)
    {              
        //开始接收其他人的网卡信息
        bzero(recv_buff,sizeof(recv_buff));
               
        recv_len = recvfrom(sockfd, recv_buff, sizeof(recv_buff), 0,  NULL, NULL);
        if(recv_len<=0||recv_len>RECV_SIZE)
        {
		    perror("recvfrom");
			continue;
		}
        //printf("链路层截取数据包长度 recv_len=%d\n",recv_len);

        //MAC包类型
        unsigned short mac_type = 0;
        mac_type = ntohs( *((unsigned short *)(recv_buff + 12)));
        if(mac_type == 0x0800)
        {
            //printf("-----------ip数据包------------\n");
            unsigned char *ip_head = recv_buff + 14; 
            unsigned char dst_ip[16] ="";
            inet_ntop(AF_INET, ip_head + 16, dst_ip, 16);

            //IP包的类型
            if(ip_head[9] == 1)
            {
                //printf("-----ICMP数据包\n");
                //查找过滤IP链表中存在我们指定的目的IP吗
                if(rou_searcharpLink(roulink_head, dst_ip) == 0)
                {
                    static int i=0;
                          
                    //-----------调试，打印原始套接字接收到的数据内容是否是空--------------------//           
                    //printf("i=%d   IP包中的目的IP = %d\n",++i, strlen(recv_buff + 30));                             
                    // printf("Rvfbuf=%p\n",recv_buff);
                    // int kk=0;
                    // while(kk<98)
                    // {
                    //     printf("Rvfbuf[%d]=%d\n",kk,recv_buff[kk]);
                    //     kk++;

                    // }
                    //----------------------------[调试]---------------------------------------//

                    usleep(1000); 
                    ip_buf *recv = (ip_buf *)malloc(sizeof(ip_buf));
                    recv->my_buf_date_len = recv_len;
                    memcpy(recv->buf, recv_buff, recv_len);

                    //线程的创建放在满足它的条件中，while循环，满足就进来创建一个，切记不要放到条件外面创建线程，否则只会创建一个，导致所有情况共用一个线程
                    pthread_t pth2;
                    //最后数据包是ICMP的整包
                    pthread_create(&pth2, NULL, callback3_ip, (void*)recv);
                    pthread_detach(pth2);
                }

            }

        }
        else if(mac_type == 0x0806)
        {           
            arp_mac_ip * head_mac_ip = NULL;//保存目的MAC\IP的结构体,安全措施，防止栈空间释放导致给线程传参为空，失败
            head_mac_ip = (arp_mac_ip *)malloc(sizeof(arp_mac_ip ));
            
            
            unsigned char *arp_head = recv_buff + 14;
            unsigned char * arp_src_mac =  arp_head + 8;//跳过[4.硬件类型、5.协议类型、6.硬件地址长度、7.协议地址长度、8.OP，拿到源MAC地址首地址信息]
            unsigned char stc_mac[18] = "";
            sprintf(stc_mac, "%02x:%02x:%02x:%02x:%02x:%02x", arp_src_mac[0],\
                arp_src_mac[1],\
                arp_src_mac[2], \
                arp_src_mac[3],\
                arp_src_mac[4], \
                arp_src_mac[5]);
            strcpy(head_mac_ip->stc_mac, stc_mac);
                   
            unsigned char src_ip[16]  = "";
            inet_ntop(AF_INET, arp_head + 14, src_ip, 16);//拿到源IP           
            strcpy(head_mac_ip->stc_ip, src_ip);

            //-----------------------------------[调试]-----------------------------------//   
            //printf("-----------arp数据包------------\n");
            //printf("arp 源mac：%s\n",head_mac_ip->stc_mac);        
            //printf("arp 源IP：src_ip = %s  \n", src_ip); 
            //-----------------------------------[调试]-----------------------------------//  

            //线程中只保存源ARP的MAC、IP，目的主机的MAC、IP，在IP线程中指定（写死）
            pthread_t pth1;
            pthread_create(&pth1, NULL, arp_pthread, (void*)head_mac_ip);
            pthread_detach(pth1);
        }


    }

    return 0;
}