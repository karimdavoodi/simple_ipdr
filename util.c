#pragma once

const char *version = "0.9.18";
const char *copyright = "Copyright 1398, Gasedak Samaneh";
//#define TO_SYSLOG 
#define LICENSE_TIMESTAMP  (1550323770 + 3600*24*365*4) 
/* 365 day after `date +%s`  97/11/27 */
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <pthread.h>
#include <sys/statvfs.h>
#include <semaphore.h>
#define MANUAL_AAA_PORT 9123
#define TRUE  1
#define FALSE 0
#define USERLEN 20
#define GEOLEN 20
#define SHAHKARLEN 16
#define PHONELEN 14
#define TCP 0x6
#define UDP 0x11
#define ICMP 0x1
#define ICMPv6 58
#define MACLEN 20
#define DEFUALT_SERVIVE_NUM   3   /*ADSL */
#define CLASS_FIELD_SEPERATOR '|'
#define MIN_FREE_SPACE  50000 /* in MB */ 
#if APP_IS_IPDR
#define LOG_DIR "/home/ipdr"
#else
#define LOG_DIR "/home/cgnatlog"
#endif
#if TO_SYSLOG
#define KDLOG(a, ...) syslog(LOG_NOTICE,a, ##__VA_ARGS__ );
#else
#define KDLOG(a, ...) printf(a, ##__VA_ARGS__);
#endif
#define FREE(a) { free(a); a = NULL; }
#define MEM_ASSERT(a) {if(!a) KDLOG("Mem Full in %s:%d\n", __func__,__LINE__);}
#define EXTRACT_IP(S,U32) {\
    S.c1 = (U32 & 0xFF000000) >> 24;\
    S.c2 = (U32 & 0x00FF0000) >> 16;\
    S.c3 = (U32 & 0x0000FF00) >> 8;\
    S.c4 = (U32 & 0x000000FF);\
}
typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler);


typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct ipbytes{
    u8 c1, c2, c3, c4;
};
// TREE NODES
struct tnode { void *data; };
struct tnode4{ struct tnode  *n[256];  };
struct tnode3{ struct tnode4 *n[256]; };
struct tnode2{ struct tnode3 *n[256]; };
struct tnode1{ struct tnode2 *n[256]; };

struct service_name {
    int   id;
    const char *name;
} service_names[] = {
    {3, "ADSL"},
    {4 ,"WIRELESS"},
    {4 ,"PTP"},    /* Shatel wireless name ! */
    {5 ,"WIMAX"},
    {1 ,"DIAL UP"},
    {2 ,"IN"},
    {6 ,"TDD-LTE"},
    {7 ,"WIFI"},
    {8 ,"WIFI MOBILE"},
    {9 ,"WIFI OFFLOAD"},
    {10,"MOBILE 2G"},
    {11,"MOBILE 3G"},
    {12,"MOBILE 4G"},
    {13,"MOBILE 5G"},
    {14,"OUTBOUND"},
    {15,"DEDICATED BANDWIDTH"},
    {-1,""}
};
struct service_type {
    int   id;
    int   need;
    int   ready;
    FILE *fd;
    int   is_ipv6;
};
struct service_type services[] = {
    {0 ,0 ,0,NULL,0}, // ignore
    {1 ,0 ,0,NULL,0},
    {2 ,0 ,0,NULL,0},
    {3 ,0 ,0,NULL,0},
    {4 ,0 ,0,NULL,0},
    {5 ,0 ,0,NULL,0},
    {6 ,0 ,0,NULL,0},
    {7 ,0 ,0,NULL,0},
    {8 ,0 ,0,NULL,0},
    {9 ,0 ,0,NULL,0},
    {10,0 ,0,NULL,0},
    {11,0 ,0,NULL,0},
    {12,0 ,0,NULL,0},
    {13,0 ,0,NULL,0},
    {14,0 ,0,NULL,0},
    {15,0 ,0,NULL,0},
    // IPv6
    {1 ,0 ,0,NULL,1},
    {2 ,0 ,0,NULL,1},
    {3 ,0 ,0,NULL,1},
    {4 ,0 ,0,NULL,1},
    {5 ,0 ,0,NULL,1},
    {6 ,0 ,0,NULL,1},
    {7 ,0 ,0,NULL,1},
    {8 ,0 ,0,NULL,1},
    {9 ,0 ,0,NULL,1},
    {10,0 ,0,NULL,1},
    {11,0 ,0,NULL,1},
    {12,0 ,0,NULL,1},
    {13,0 ,0,NULL,1},
    {14,0 ,0,NULL,1},
    {15,0 ,0,NULL,1},
    {-1,0 ,0,NULL,0}
};
struct user_rec {
    u8 service_num;
    u8 name[USERLEN+1];
    u8 phone[PHONELEN+1];
    u8 mac[MACLEN+1]; 
    u8 N[GEOLEN+1];
    u8 E[GEOLEN+1];
    u32 ipv4;
    u8 ipv6_valid;
    u8 ipv6[16];
    u8 imei[20];
    u8 imsi[20];
#if SIMULATE_UDP_SESSION    
    u32 udp_session[UDP_SESSION_NUM];
#endif	
#if REDUCE_TCP_SESSION 
    u32 tcp_session[TCP_SESSION_NUM];
#endif	
};

pthread_attr_t pthread_attr;

int   def_service_num = DEFUALT_SERVIVE_NUM;
pthread_mutex_t usr_t_mutex;
char  class_field_seperator = CLASS_FIELD_SEPERATOR;
pthread_t log_thread[60],free_space_thread_id;
static struct  tnode1 *usr_t;
int debug = 0;
static long    user_num=0;
static long    user_uniq_num=0;
char operator_name[80];
char *log_dir = (char *)LOG_DIR;
static long    log_sum = 0;
int   reverse_ip = 0;

struct tnode1 *t_init()
{
    struct tnode1 *t;
    t = (struct tnode1 *)malloc(sizeof(struct tnode1));
    if (!t){
        MEM_ASSERT(t);
        return NULL;
    }
    memset(t,0,sizeof(struct tnode1));
    return t;
}
int t_add(struct tnode1 *t,void *data,u32 ips)
{
    struct user_rec *u_old,*u_new,*u;
    struct ipbytes ip;
    EXTRACT_IP(ip, ips);
    if (t->n[ip.c1] == NULL)
        t->n[ip.c1] = (struct tnode2 *) t_init ();
    if (t->n[ip.c1]->n[ip.c2] == NULL)
        t->n[ip.c1]->n[ip.c2] = (struct tnode3 *) t_init ();
    if (t->n[ip.c1]->n[ip.c2]->n[ip.c3] == NULL)
        t->n[ip.c1]->n[ip.c2]->n[ip.c3] = (struct tnode4 *) t_init ();
    if (t->n[ip.c1]->n[ip.c2]->n[ip.c3]->n[ip.c4] == NULL){
        t->n[ip.c1]->n[ip.c2]->n[ip.c3]->n[ip.c4] = (struct tnode *)malloc(sizeof(struct tnode));
        t->n[ip.c1]->n[ip.c2]->n[ip.c3]->n[ip.c4]->data = NULL;
    }
    if (t->n[ip.c1]->n[ip.c2]->n[ip.c3]->n[ip.c4] != NULL){
        if(t->n[ip.c1]->n[ip.c2]->n[ip.c3]->n[ip.c4]->data != NULL){
            u_old = (struct user_rec *)t->n[ip.c1]->n[ip.c2]->n[ip.c3]->n[ip.c4]->data;
            u_new = (struct user_rec *)data;
            if(!strncmp((const char *)u_old->name,(const char *)u_new->name,USERLEN)) 
                return TRUE;
            FREE(t->n[ip.c1]->n[ip.c2]->n[ip.c3]->n[ip.c4]->data);
        }else user_uniq_num++;
        u = (struct user_rec*)malloc(sizeof(struct user_rec));
        memcpy(u,data,sizeof(struct user_rec));
        t->n[ip.c1]->n[ip.c2]->n[ip.c3]->n[ip.c4]->data = u;
        if(debug>4)KDLOG("Tree add: %d %d %d %d\n",ip.c1, ip.c2, ip.c3 , ip.c4);
        return TRUE;
    }else{
        MEM_ASSERT(0);
        return FALSE;
    }
}
/*
void t_del(struct tnode1 *t,u32 ips,int type)
{
    int i;
    int del_node;
    struct tnode4 *t4;
    struct tnode3 *t3;
    struct tnode2 *t2;
    struct ipbytes ip;
    EXTRACT_IP(ip, ips);
    if (t->n[ip.c1]!=NULL &&
            t->n[ip.c1]->n[ip.c2]!=NULL &&
            t->n[ip.c1]->n[ip.c2]->n[ip.c3]!=NULL &&
            t->n[ip.c1]->n[ip.c2]->n[ip.c3]->n[ip.c4]!=NULL )
    {
        t4 = t->n[ip.c1]->n[ip.c2]->n[ip.c3];
        FREE(t4->n[ip.c4]->data);
        FREE(t4->n[ip.c4]);
        del_node = TRUE;
        for(i=0; i<256; i++){
            if(t4->n[i]){
                del_node = FALSE;
                break;
            }
        }
        if(del_node)
        {
            t3 = t->n[ip.c1]->n[ip.c2];
            FREE(t3->n[ip.c3]);
            del_node = TRUE;
            for(i=0; i<256; i++){
                if(t3->n[i]){
                    del_node = FALSE;
                    break;
                }
            }
            if(del_node)
            {
                t2 = t->n[ip.c1];
                FREE(t2->n[ip.c2]);
                del_node = TRUE;
                for(i=0; i<256; i++){
                    if(t2->n[i]){
                        del_node = FALSE;
                        break;
                    }
                }
                if(del_node)
                {
                    FREE(t->n[ip.c1]);
                }
            }
        }
    }
}
*/
void add_to_ip_tree(struct user_rec *user)
{
    pthread_mutex_lock(&usr_t_mutex);
    t_add(usr_t,user,user->ipv4);  
    user_num++;
    pthread_mutex_unlock(&usr_t_mutex);
}
struct tnode *t_search(struct tnode1 *t,u32 ips)
{
    struct ipbytes ip;
    EXTRACT_IP(ip, ips);

    if(debug>2)KDLOG("Search: %d %d %d %d\n",ip.c1, ip.c2, ip.c3 , ip.c4);
    if (    t!=NULL &&
            t->n[ip.c1]!=NULL &&
            t->n[ip.c1]->n[ip.c2]!=NULL &&
            t->n[ip.c1]->n[ip.c2]->n[ip.c3]!=NULL &&
            t->n[ip.c1]->n[ip.c2]->n[ip.c3]->n[ip.c4]!=NULL ){
        if(debug>3)KDLOG("Found: %d %d %d %d\n",ip.c1, ip.c2, ip.c3 , ip.c4);
        return t->n[ip.c1]->n[ip.c2]->n[ip.c3]->n[ip.c4];
    }else{
        return NULL;
    }
}
void *manage_log_file(void *arg)
{
    int thrd_id = *(int*)arg;
    int service_id = 0;
    struct stat st;
    time_t rt;
    struct tm *t;
    char fname[255],fname_old[255],cmd[500],day_folder[255];
    char tfname[255],tfname_old[255],ipv6[20];
    fname[0] = '\0';
    tfname[0] = '\0';
    if(debug) KDLOG("Start log thread %d for service:%d ipv6:%d\n",
            thrd_id, services[thrd_id].id, services[thrd_id].is_ipv6);

    while(services[thrd_id].need == 0)
        sleep(2);

#ifndef TO_SYSLOG
    return NULL;
#endif
    if(services[thrd_id].is_ipv6 == 1){
        strcpy(ipv6, "_IPv6");
        service_id = thrd_id - 15;
    }else{
        ipv6[0] = '\0';
        service_id = thrd_id;
    }
    KDLOG("Start log for service:%d in %s\n",service_id,log_dir);
    mkdir(log_dir,0777);
    while(1)
    {	
        if(time(NULL) > LICENSE_TIMESTAMP ){
            KDLOG("License EXPIRE!!!");
            return NULL;
        }
        time(&rt);
        t = localtime(&rt);
        /* Make day folder */
        sprintf(day_folder,"%s/%4d%02d%02d", log_dir,
                1900+t->tm_year,1+t->tm_mon,t->tm_mday);
        mkdir(day_folder,0777);

        strncpy(fname_old,fname,250);
        strncpy(tfname_old,tfname,250);
        sprintf(fname,"%s/%4d%02d%02d%02d%02d_%d_%s%s.csv.gz",day_folder,
                1900+t->tm_year,1+t->tm_mon,t->tm_mday,t->tm_hour,t->tm_min,
                service_id, operator_name, ipv6);
        sprintf(tfname,"%s/.%4d%02d%02d%02d%02d_%d_%s%s.csv",day_folder,
                1900+t->tm_year,1+t->tm_mon,t->tm_mday,t->tm_hour,t->tm_min,
                service_id, operator_name, ipv6);
        services[thrd_id].fd = fopen(tfname,"a");
        if(services[thrd_id].fd == NULL){
            KDLOG("Can't open %s\n",tfname);
            sleep(5);
            continue;
        }
        KDLOG("Create %s\n",tfname);
        services[thrd_id].ready = 1;
        if(tfname_old[0]!='\0'){
            stat(tfname_old, &st);
            if(st.st_size < 10 ){
                sprintf(cmd,"rm  -f %s",tfname_old);
                system(cmd) ;
                if(debug)KDLOG("Remove small file:%s\n",tfname_old);
            }else{
                sprintf(cmd,"(gzip -f %s; mv -f %s.gz %s) &",
                        tfname_old, tfname_old, fname_old);
                system(cmd) ;
                //sprintf(cmd,"mv -f %s.gz %s",tfname_old,fname_old);
                //system(cmd) ;
                if(debug)KDLOG("Move to:%s\n",fname_old);
            }
            if(debug)KDLOG("%s\n",cmd);
        }
        sleep( (( 5 - (t->tm_min % 5))*60) - t->tm_sec - 1 );
        services[thrd_id].ready = 0;
        sleep(1);
        fclose(services[thrd_id].fd);
        services[thrd_id].fd = NULL;
    }
}
void start_manage_log_file_threads()
{
	int	arg_log[60];
	int i;
    for(i=1; (services[i].id != -1) && i<60; i++){
        arg_log[i] = i;
        pthread_create(&log_thread[i], &pthread_attr, manage_log_file,(void*)&arg_log[i]);
        usleep(1000);
    }
}
void ipv6_to_str(char *bin, char *txt)
{
    int i;
    u8 c;
    for(i=0; i<16; i++){
        c = (bin[i] & 0xF0) >> 4; 
        txt[i*2]   = (c<10)?(c+'0'):(c-10+'A');
        c = bin[i] & 0x0F ; 
        txt[i*2+1] = (c<10)?(c+'0'):(c-10+'A');
    } 
    txt[32] = '\0';
}
int read_radius_pkt(u8 *l4_pkt,int l4_len)
{
    struct user_rec user;
    int find_class, find_ipv4, find_ipv6;
    u8 *r,*p;
    int r_len;
    int r_code;
    int type;
    int l,len;
    int i,j,k,max;
    char mac[20],S[25];
    u8 ipv6_interface[16], ipv6_prefix[16];
    int ipv6_prefix_len, ipv6_interface_len;
    ipv6_prefix_len = ipv6_interface_len = 0;
    find_class = find_ipv4 = find_ipv6 = 0;

    r = l4_pkt+8;  /* jump UDP header */
    r_code = r[0];
    if(r_code != 4){
        if(debug) KDLOG("No Radius request packet(code:%d)\n",r_code); 
        return 1;
    }
    r_len  = (r[2]<<8) | r[3];
    if(r_len > l4_len){
        KDLOG("Error in radius pkt len\n");
        return 0;
    }
    if(debug>4) KDLOG("Get radius code %d len %d\n",r_code, r_len); 
    i = 0;
    memset(&user,0,sizeof(struct user_rec));
    mac[0] = '\0';
    for(i = 0; i<r_len-20;){
        p = r + 20 + i; 
        type = p[0];
        len = p[1];
        //if(debug) KDLOG("AVP type %d len %d\n",type,len);
        i += len;
        len = len - 2;
        p   = p + 2;
        switch(type){
#if ONLY_AAA_START_PKT			
            case 40: // Acct-Status-Type
                if(p[3] != 1 /*Start*/) return 0;
                break;
#endif			  
            case 1: // User name
                max = ( len > (USERLEN-1) )?(USERLEN-1):len;
                memcpy(user.name,p,max);
                user.name[max] = '\0';
                break;
            case 8:	//  Frame-IP-Address  
                //NETWORK ORDER : 100.75.152.55 -> 0x644b9837
                memcpy(& user.ipv4, p, 4);	
                if(reverse_ip) user.ipv4 =  htonl(user.ipv4);
                find_ipv4 = 1;
                break;
            case 168:// Frame-IPv6-Address 
                if(len>=16){
                    memcpy(user.ipv6, p, 16);
                    find_ipv6 = 1;
                }
                break;
            case 96:// Framed-IPv6-Interface 
                if(len<=16){
                    memcpy(ipv6_interface, p, len);
                    ipv6_interface_len = len;
                    if(debug) KDLOG("Get IPv6-Interface len:%d\n",len);
                }
                break;
            case 97:// Framed-IPv6-Prefix 
                ipv6_prefix_len = p[1] / 8;
                if(ipv6_prefix_len <= 16){
                    memcpy(ipv6_prefix, p + 2, ipv6_prefix_len);
                    if(debug) KDLOG("Get IPv6-Perfix len:%d\n",
                            ipv6_prefix_len);
                        }
                break;
            case 31: // Calling id (mac)
                max = (len > 18)?18:len;
                memcpy(mac,p,max);
                mac[max] = '\0';
                break;
            case 26: // Vendor Specific  : cisco :  mac
                if (p[3] != 0x9 || p[4] != 0x1 || p[5] != 0x23 ) break;
                memcpy(mac,p+25,14);
                mac[14] = '\0';
                break;
            case 25: // CLASS 
                find_class = 1;
                /*
SHATEL:   [P:0935;N:2134;E:2134;C:3454353;S:ADSL]
ATINEGAR: [P:02125437945|S:WIRELESS|C:|]
P = Phone , N,E = lat,long , C = Shahkar , S = service 
*/
                for(j=0; j<len && p[j]!='[' ; j++) ;
                if(p[j]!='['){
                    if(debug>1)KDLOG("Class invalid field\n");
                    break;
                }
                j+=2;
#define CEND (k<len && p[k]!=';' && p[k]!='|' && p[k]!=']')
                while(j<len && p[j]!=']'){
                    //KDLOG(" [%c%c] ",p[j-1],p[j]);
                    if(p[j-1] == 'P' && p[j]==':'){
                        l = 0;
                        for(k=j+1; l<PHONELEN && CEND; k++){
                            if(p[k]>='0' && p[k]<='9'){
                                user.phone[l++] = p[k];
                            }
                        }
                        user.phone[l] = '\0';
                        if(l<3) user.phone[0] = '\0';
                        j = k+1;
                        if(debug>4)KDLOG("Get P:[%s]\n",user.phone);
                    }else if(p[j-1] == 'N' && p[j]==':'){
                        // N:59.611153;E:36.280078;
                        l = 0;
                        for(k=j+1; l<GEOLEN && CEND; k++){
                            if((p[k]>='0' && p[k]<='9') || p[k] == '.')
                                user.N[l++] = p[k];
                        }
                        user.N[l] = '\0';
                        j = k+1;
                        if(debug>4)KDLOG("Get N:[%s]\n",user.N);
                    }else if(p[j-1] == 'C' && p[j]==':'){
                        for(k=j+1; CEND; k++){
                            // Ignore Shahkar ... 
                        }
                        j = k+1;
                    }else if(p[j-1] == 'E' && p[j]==':'){
                        l = 0;
                        for(k=j+1; l<GEOLEN && CEND; k++){
                            if((p[k]>='0' && p[k]<='9') || p[k] == '.')
                                user.E[l++] = p[k];
                        }
                        user.E[l] = '\0';
                        j = k+1;
                        if(debug>4)KDLOG("Get E:[%s]\n",user.E);
                    }else if(p[j-1] == 'S' && p[j]==':'){
                        l = 0;
                        for(k=j+1; l<20 && CEND;  k++){
                            if(p[k]>='a' && p[k]<='z')
                                S[l++] = p[k] - ('a'-'A');
                            else
                                S[l++] = p[k];
                        }
                        j = k+1;
                        S[l] = '\0';
                        if(debug>4)KDLOG("Get S:[%s]\n",S);
                        for(k=1; service_names[k].id != -1; k++){
                            if(!strcmp(S,service_names[k].name)){
                                user.service_num = service_names[k].id;
                                break;
                            }
                        } 
                    }else {
                        j++;
                    }
                }
                //printf("P:%s,S:%s\n",user.phone,S); 
                break;
        }
    }
    if(ipv6_prefix_len + ipv6_interface_len == 16){
        memcpy((char*)&user.ipv6, ipv6_prefix, ipv6_prefix_len);
        memcpy((char*)&user.ipv6 + ipv6_prefix_len, 
                ipv6_interface, ipv6_interface_len);
        find_ipv6 = 1;
        if(debug) KDLOG("Merg IPv6 prefix + interface\n");
    }
    if(find_ipv6){
        user.ipv6_valid = 1;
        memcpy((char*)&user.ipv4, user.ipv6+12, 4);
        if(debug){
            char ipv6_str[35];
            ipv6_to_str((char*)user.ipv6, ipv6_str);
            KDLOG("user has ipv6:%s\n",ipv6_str);
        }
    }
    if(find_ipv4 + find_ipv6 == 0){
        if(debug>3) KDLOG("Ignor user that dosn't have IP fileds\n");
        return 0;
    }
    if(find_class == 0 ){
        if(debug>3) KDLOG("user dosn't have CLASS fileds\n");
        //return 0;
    }
    if(user.service_num == 0 || user.phone[0] == '\0'){
        if(debug>3) KDLOG("user dosn't have P,S field in Class\n");
        // return 0;
    }
    if(user.service_num == 0 ) 
        user.service_num = def_service_num;

    /* MAC convert */
    if(mac[0] != '\0' ){
        for(k=0,j=0; mac[j]!='\0' && k < 12 ; j++){
            if((mac[j] >= '0' && mac[j] <= '9') || 
                    (mac[j] >= 'a' && mac[j] <= 'f')){
                user.mac[k++] = mac[j];
            }
            else if((mac[j] >= 'A' && mac[j] <= 'F')){
                user.mac[k++] = mac[j] + ('a'-'A');
            }
        }	
        user.mac[k] = '\0';
    }
    if(debug>1){
        KDLOG("user: name:[%s] IP:[%X] MAC:[%s] P:[%s] N:[%s] E:[%s] service:%d \n",
                user.name,user.ipv4,user.mac, user.phone,user.N,user.E,user.service_num);
    }
    add_to_ip_tree(&user);
    return 0;
}
int is_free_space(const char* path)
{
    struct statvfs stat;
    long _free,total;

    if (statvfs(path, &stat) != 0) {
        KDLOG("Error in statvfs in %s\n",path);
        return 1;
    }
    _free =  stat.f_bsize * stat.f_bavail/1000000;
    total = stat.f_frsize * stat.f_blocks/1000000; 
    if(_free < MIN_FREE_SPACE ){ 
        KDLOG("Free Space: %ld MB from %ld MB in %s\n",_free,total,path);
        return 0;
    }else
        return 1;
}
void *manage_free_space(void *arg)
{
    long log_sum_t;
    char cmd[250];
    sleep(10);
    while(1){
        if(!is_free_space(log_dir)){
            KDLOG("Make free space. delete oldest day log.\n");
            sprintf(cmd,"rm -rf %s/`ls -t %s/ | tail -1` ", log_dir, log_dir ); 
            system(cmd); 
        }
        log_sum_t = log_sum;
        sleep(3600);
        if(log_sum_t == log_sum){
            KDLOG("Don't log for 1 hour. Exit!");
            exit(0);
        }
    }
}
void process_put(char *req, char *resp)
{
    struct user_rec user;
    char *pre,*tok,*usr,*pass,*uid,*mac,*ip,
         *service,*phone;
    char r[1024];
    char body[1024];
    const char* Error = "HTTP/1.1 403 Error\n\r\n\r";
    // PUT /usr/pass/service/uid/ip/mac/phone"
    resp[0] = '\0';
    strncpy(r,req,1023);
    int i;
    for(i=0; r[i]!='\0' && r[i]!='/'; ++i);
    for(; r[i]!='\0' && r[i]!=' '; ++i);
    r[i] = '\0';
    KDLOG("REQ:%s\n", r);
    pre     = strtok_r (r ,"/",&tok);  
    usr     = strtok_r (NULL,"/",&tok);  
    pass    = strtok_r (NULL,"/",&tok);  

    service = strtok_r (NULL,"/",&tok);  
    uid     = strtok_r (NULL,"/",&tok);  
    ip      = strtok_r (NULL,"/",&tok);  
    mac     = strtok_r (NULL,"/",&tok);  
    phone   = strtok_r (NULL,"/",&tok);  
    if(usr == NULL || pass == NULL || uid == NULL || ip == NULL){
        strcpy(resp, Error); 
        return;
    }
    if(strcmp(usr, "IPDR_AAA") || strcmp(pass, "A31233123")){
        strcpy(resp, Error); 
        return;
    }
    memset(&user,0,sizeof(struct user_rec));

    user.ipv4 = inet_addr(ip);
    strncpy((char*)user.name, uid, MACLEN);
    if(mac != NULL)
        strncpy((char*)user.mac, mac, MACLEN);
    if(phone != NULL)
        strncpy((char*)user.phone, phone, PHONELEN);
    user.service_num = 3;
    if(service != NULL){
        for(i=1; service_names[i].id != -1; i++){
            if(!strcmp(service,service_names[i].name)){
                user.service_num = service_names[i].id;
                break;
            }
        } 
    }
    sprintf(body,"User:%s\n"
            "Phone:%s\n"
            "IP(hex):%X\n"
            "Mac:%s\n"
            "ServiceID:%d\n",
            user.name,
            user.phone,
            ntohl(user.ipv4),
            user.mac,
            (int)user.service_num
           );
    sprintf(resp,
            "HTTP/1.1 200 OK\r\n"
            "Server: IPDR %s\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %d\r\n\r\n"
            "SAVED:\n%s\n", version,
            (int)strlen(body),
            body);
    add_to_ip_tree(&user);
    return;

}
void process_get(char *req, char *resp)
{
    struct tnode *node = NULL;
    struct user_rec *user = NULL;
    char *pre,*tok,*usr,*pass,*ip;
    char r[1024];
    char body[1024];
    const char* Error = "HTTP/1.1 403 Error\n\r\n\r";
    // GET /usr/pass/ip"
    resp[0] = '\0';
    strncpy(r,req,1023);
    int i;
    for(i=0; r[i]!='\0' && r[i]!='/'; ++i);
    for(; r[i]!='\0' && r[i]!=' '; ++i);
    r[i] = '\0';
    KDLOG("REQ:%s\n", r);
    pre     = strtok_r (r ,"/",&tok);  
    usr     = strtok_r (NULL,"/",&tok);  
    pass    = strtok_r (NULL,"/",&tok);  
    ip      = strtok_r (NULL,"/",&tok);  

    if(usr == NULL || pass == NULL || ip == NULL ){
        strcpy(resp, Error); 
        return;
    }
    if(strcmp(usr, "IPDR_AAA") || strcmp(pass, "A31233123")){
        strcpy(resp, Error); 
        sleep(2);
        return;
    }
    u32 ipv4 = inet_addr(ip);
    node = t_search(usr_t, ipv4);
    if(node == NULL){
        strcpy(body, "Not Found\n");
    }else{
        user = (struct user_rec *) node->data;	
        sprintf(body,"User:%s\n"
                "Phone:%s\n"
                "IP(hex):%X\n"
                "Mac:%s\n"
                "ServiceID:%d\n",
                user->name,
                user->phone,
                ntohl(user->ipv4),
                user->mac,
                (int)user->service_num
               );

    }
    sprintf(resp,
            "HTTP/1.1 200 OK\r\n"
            "Server: IPDR %s\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %d\r\n\r\n"
            "%s", version,
            (int)strlen(body),
            body);
    return;
}
void process_cmd(char *req, char *resp)
{
    if(strstr(req, "PUT /"))
        process_put(req, resp);
    else if(strstr(req, "GET /"))
        process_get(req, resp);
}
void *manual_aaa_server(void *arg)
{
    int parentfd,clifd;
    int optval;
    struct sockaddr_in tmpsock;
    struct sockaddr_in serveraddr;
    socklen_t clientlen;
    int n;
    char req[512],resp[512];

    KDLOG("Start aaa api server\n");
    if((parentfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ){
        KDLOG("Error opening record server!\n");
        return NULL;
    }
    optval = 1;
    setsockopt(parentfd, SOL_SOCKET, SO_REUSEADDR,
            (const void *)&optval , sizeof(int));

    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serveraddr.sin_port = htons((unsigned short) MANUAL_AAA_PORT );

    optval = 0;
    while (bind(parentfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0){ 
        if(++optval > 5){
            close(parentfd);
            exit(0);
        }
        KDLOG("Error bind http socket\n");
        sleep(5);
    }
    KDLOG("Listen to port %d\n",MANUAL_AAA_PORT);
    if (listen(parentfd, 20) < 0){
        KDLOG("Error listen http socket\n");
        close(parentfd);
        exit(0);
    }
    clientlen = sizeof(serveraddr);
    while (1) {
        if((clifd = accept(parentfd, (struct sockaddr *) &tmpsock, &clientlen))<0){
            KDLOG("Error accept http socket\n");
            sleep(1);
            continue;
        }
        if((n=read(clifd, req, 500)) > 0 ){
            req[n] = '\0';
            resp[0] = '\0';
            process_cmd(req,resp);
            if(resp[0] != '\0'){
                KDLOG(" send resp:%s\n",resp);
                write(clifd, resp, strlen(resp));
            }
        }
        close(clifd);
    }
    close(parentfd);
}
#if 0
void append_tmp_log_file(char *to_file)
{
    FILE *f;
    int n;
    char buf[2050];
    if(log_file_tmp == NULL) return;
    if(to_file[0] == '\0'  ) return;
    sleep(1);
    f = fopen(to_file,"a");
    if(f == NULL) return;
    if(debug)KDLOG("Append temp file to %s\n",to_file);
    fseek(log_file_tmp,0,SEEK_SET);
    while(!feof(log_file_tmp)){
        n = fread(buf,1,2048,log_file_tmp);
        if(n>0){
            fwrite(buf,1,n,f);
            if(debug>4)KDLOG("Append %d byte\n",n);
        }else break;
    }
    fclose(f);
    fclose(log_file_tmp);
    log_file_tmp = fopen("/home/ipdr/tmp.txt","w");
}
int read_diameter_pkt(u8 *tcp_pkt,int l4_len)
{
    char tmp[100];
    struct user_rec user;
    u8 *r,*p,*q;
    int len,tcp_hdr_len,r_len;
    int base,i,j,k;
    int align,align_j;
    int avp_code, avp_len, q_len, q_code;
    int s_code,s_len,ip_type;
    int find = 0;
    tcp_hdr_len = ((tcp_pkt[12] & 0xF0)>>4)*4;
    r = tcp_pkt + tcp_hdr_len;
    if(r[0]  != 0x01) return -1; // version == 0x01
    if(r[11] != 0x04) return -2; // ApplicationID == 0x04
    r_len  = (r[1]<<16) | (r[2]<<8) | r[3];
    i = 0;
    align = align_j = 0;
    for(i = 0; i<r_len-20;){
        if( align != 0 ) j = 4 - align;
        else j = 0;
        p = r + 20 + i + j;   // 20 : account packet header
        memcpy(tmp,p,50);
        avp_code = (p[0]<<24) | (p[1]<<16) | (p[2]<<8) | p[3];
        avp_len  = (p[5]<<16) | (p[6]<<8) | p[7];
        i += avp_len+j;
        align = avp_len % 4;
        switch(avp_code){
            case 416: // CC-Req type
                if(avp_len != 12) return -3; // invalid packat!
                if( p[11] == 3 ) return  -4; // TERMINATION_REQ
                //if( p[11] == 2 ) return -5; // UPDATE_REQ
                break;
            case 443: // SubscriptionID : mobile number or IMEI
                base = 8+12;
                len = ( (p[base+5]<<16) | (p[base+6]<<8) | p[base+7]) - 8 ;
                if(p[8+8+3] == 0){  // mobile number
                    memcpy(user.phone,p+base+8,len);
                    user.phone[len] = '\0';
                }
                if(p[8+8+3] == 1){  // mobile IMSI
                    memcpy(user.imsi,p+base+8,len);
                    user.imsi[len] = '\0';
                }
                break;
            case 458: // User Equipment Info : IMEI
                base = 8+12;
                len = ( (p[base+5]<<16) | (p[base+6]<<8) | p[base+7]) - 8 ;
                if(p[8+8+3] == 0){  // mobile IMEISV
                    memcpy(user.imei,p+base+8,len);
                    user.imei[len] = '\0';
                }
                break;
            case 873:	// Service Information
                s_code = (p[12+0]<<24) | (p[12+1]<<16) | (p[12+2]<<8) | p[12+3];
                s_len  = (p[12+5]<<16) | (p[12+6]<<8) | p[12+7];
                if(s_code != 874) break; // not PS-Information !
                for(j = 0; j<s_len-24;){
                    if( align_j != 0 ) k = 4 - align_j;
                    else k = 0;
                    q = p + 24 + j + k;
                    q_code = (q[0]<<24) | (q[1]<<16) | (q[2]<<8) | q[3];
                    q_len  = (q[5]<<16) | (q[6]<<8) | q[7];
                    j += q_len + k;
                    align_j = q_len % 4;
                    switch(q_code){
                        case 22: // 3GPP User Location
                            memcpy(user.cell_loc,q+12,q_len - 12);
                            user.cell_loc[q_len-12] = '\0';
                            break;
                        case 1227: // PDP-Address : user IP
                            ip_type = (q[12]<<8) | q[13];
                            if(ip_type == 1){ // IPv4
                                memcpy((void *)&user.ipv4,q+14,4);
                                find = 1;
                            }
                            break;
                    }
                }
        }
    }
    if(find){
        add_to_ip_tree(&user);
    }
    return 0;

}
#endif
/*
 * 9001300208|d4ca6d60ea20|1577768160|6|||97F0B75E|21665|86AB1B68|80|||||
                            AAA =  0x5eb7f097 ->  94.183.240.151
                            USER=  0x5eb7f097

 *
 * */
