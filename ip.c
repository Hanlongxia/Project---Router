#include<stdio.h>
#include<stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include<string.h>



int main()
{
    printf("content-type:text/html\n\n");
    



//     //AJAX GET方式
  char *pdata=getenv("QUERY_STRING");
  char Buf[100]={0};
  printf("%s\n",pdata);

  //文件给出绝对路径
  FILE *pf=fopen("/mnt/hgfs/ios2021/xiangmu_luyouqi/ip_config","ab+");
  if(pf==NULL)
  {
  return 0;
  }
  strcpy(Buf,pdata);
  int len=strlen(Buf);
  //int num = atoi(Buf);

  //每次输入文件都换行


  // Buf[len]='\n';//-------方法① 
  // Buf[len+1]='\0';      
  // fwrite(Buf,len+1,1,pf);

  fprintf(pf, "%s\n", Buf);//---------方法②

  fclose(pf);  




    //AJAX POST
  /*     char* str_len=getenv("CONTENT_LENGTH");
       int len=atoi(str_len);
       char Buf[100]={0};
       read(0,Buf,len);
       printf("%s\n",Buf);


       FILE *pf=fopen("ip_config","ab+");
       if(pf==NULL)
       {
            return 0;
       }
       //每次输入文件都换行
       Buf[len]='\n';
       Buf[len+1]='\0';       
       fwrite(Buf,len+1,1,pf);

       fclose(pf);  */


     //表单的方式
    

    return 0;
}