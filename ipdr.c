#define APP_IS_IPDR     1
#define AAA_MAX_PKT     2048 /* size of capture data */
#define USR_MAX_PKT     64   /* size of capture data */
#define AAA_THREAD_NUM  3  
#define USR_THREAD_NUM  8    /* per intereface */
#define USR_NIC_MAX     10 
#define USR_NET_MAX     50
#define REDUCE_SESSION  1 
#ifdef  REDUCE_SESSION
#define UDP_SESSION_NUM 500
#define UDP_SESSION_TTL 30
#define TCP_SESSION_NUM 500
#define TCP_SESSION_TTL 30
#define SIMULATE_UDP_SESSION  1   /*  */
#define REDUCE_TCP_SESSION    1   /* not log all sessions of user for one destination in same time */
#define IGNORE_SRC_PORT       1   /* ignore src_port in session hash */
#endif
#define ONLY_AAA_START_PKT    0   /* get AAA when Acct-Status-Type==Start */

/* TCP FLAGS not filter in IPv6! (in tcpdump). in IPv6 clear filter and check 'tcp sync' manualy */
//#define USR_FILTER  "udp or ( (tcp[tcpflags]&tcp-syn)!=0 and (tcp[tcpflags]&tcp-ack)==0 )" 
#define USR_FILTER  "" 
/***************   DEFINATIONS ***************************************************/
#include "util.c"

struct node_pkt_t {
    u8    ipv4;
	u8    protocol;
	u32   src_ip4;
	u32   dst_ip4;
	u8    src_ip6[16];
	u8    dst_ip6[16];
	u16   src_port;
	u16   dst_port;
	long  timestamp;
	struct node_pkt_t *next;
};
struct node_aaa_t {
	u8 *pkt;
	u16 pkt_len;
	struct node_aaa_t *next;
};
/***************   VARIABLES ***************************************************/
u32   usr_net[USR_NET_MAX];
u32   usr_net_mask[USR_NET_MAX];
int   log_ipv4 = 0;
int   log_ipv6 = 0;
int   usr_net_i = 0;
int   radius_port = 1815;
int   users_num = 0;
char *nic_aaa=NULL,*nic_usr[USR_NIC_MAX];
int   nic_usr_i = 0;
int   is_netflow = 0;
int   is_radius = 1;
// Counters
u64    ignore_without_aaa  = 0;
u64    pkt_count_user_all = 0;
u64    pkt_count_not_ip = 0;
u64    pkt_count_user_ipv4 = 0;
u64    pkt_count_user_ipv6 = 0;
u64    pkt_count_aaa = 0;
u64    pkt_count_usr[USR_NIC_MAX];
u64    udp_pkt_ignore = 0;
u64    tcp_pkt_ignore = 0;
u64    udp_pkt_log = 0;
u64    tcp_pkt_log = 0;
u64    log_a_sum = 0;
u64    acc_not_user = 0;	
u64    ignore_without_aaa_num = 0;
time_t  start_time = 0;

pthread_t user_thread_id[USR_NIC_MAX],aaa_thread_id;
pthread_mutex_t pkt_mutex_aaa;
pthread_mutex_t pkt_mutex_usr[USR_NIC_MAX];
struct node_aaa_t *pkt_head_aaa;
struct node_pkt_t *pkt_head_usr[USR_NIC_MAX];
/***************   FUNCTIONS ***************************************************/
void print_stat(int);
void *process_pkt_of_aaa(void *p);
void *process_pkt_of_usr(void *arg);
void write_log(struct node_pkt_t *pkt);
void *start_aaa_thread(void *arg);
void *start_usr_log_thread(void *arg);
void sig_handler(int);
void *manage_log_file(void *);
void *manage_free_space(void *);
int read_radius_pkt(u8 *l4_pkt,int l4_len);
int read_diameter_pkt(u8 *l4_pkt,int l4_len);
int user_find(char *name); 
int is_usr_pkt(struct node_pkt_t *pkt);
int check_udp_session(u32* udp_session,struct node_pkt_t *pkt);
int check_tcp_session(u32* tcp_session,struct node_pkt_t *pkt);

void usage(){
	printf("ipdr %s, %s\n",version,copyright);
	printf("Usage: ipdr -a <aaa_nic_name> -u <user_nic_name> \n"
		   "\t -o <operator_name>\n"
		   "\t -s <service_id>      /* ADSL=3,2G=10,3G=11,4G=12,...     */\n"
		   "\t [-R]                 /* RADIUS                           */ \n"
		   "\t [-D]                 /* DIAMETER                         */ \n"
		   "\t [-I]                 /* ignore users that don't have AAA */ \n"
		   "\t [-A]                 /* reverse ip                       */ \n"
		   "\t [-4]                 /* ipv4 log                         */ \n"
		   "\t [-6]                 /* ipv6 log                         */ \n"
		   "\t [-l log_dir ]        /* set log dir                      */ \n"
		   "\t [-n ip/mask ]        /* user net                         */ \n"
		   "\t [-r port]            /* radius port                      */ \n"
		   "\t [-d level]           /* debug level=0,1,2,3              */ \n"
		   "\t [-f sepetator]       /* class field seperator            */ \n"
		   "\t [-t <user_log_type>] /* 'netflow' or 'raw'               */\n");
}
int main(int argc, char* argv[])
{
	int i;
	int	arg[USR_NIC_MAX];
	char c;
	char *p;
	int mask;

    operator_name[0] = '\0';
	while ((c = getopt(argc, argv, (const char *)"46AIRDd:a:u:t:o:s:r:n:f:l:")) != -1){
		switch (c)
		{
		  case 'a':
			  nic_aaa = optarg;
			  break;
		  case 'u':
			  nic_usr[nic_usr_i++] = optarg;
			  break;
		  case 'l':
			  log_dir = optarg;
			  break;
		  case 'o':
			  strncpy(operator_name,optarg,50);
			  break;
		  case 's':
			  def_service_num = atoi(optarg);
			  break;
		  case 'f':
			  class_field_seperator = optarg[1];
			  //printf("FIELD:%c\n",class_field_seperator); 
			  break;
		  case 'n':
			  if(usr_net_i >= USR_NET_MAX) break;
			  p = strchr(optarg,'/'); /* 150.0.0.0/8 */
			  if(p == NULL) break;
			  *p = '\0';
			  p++;
			  mask = atoi(p);
			  mask = 0xffffffff << (32 - mask);
			  usr_net[usr_net_i] = htonl(inet_addr(optarg)) & mask;
			  usr_net_mask[usr_net_i] = mask;
			  usr_net_i++;
			  break;
		  case 'R':
			  is_radius  = 1;
			  break;
		  case 'D':
			  is_radius  = 0;
			  break;
		  case 'A':
			  reverse_ip  = 1;
			  break;
		  case '4':
			  log_ipv4  = 1;
			  break;
		  case '6':
			  log_ipv6  = 1;
			  break;
		  case 'I':
			  ignore_without_aaa  = 1;
			  break;
		  case 't':
			  if(!strncmp(optarg,"netlog",6))
				  is_netflow = 1;
			  break;
		  case 'r':
			  radius_port = atoi(optarg);
			  break;
		  case 'd':
			  debug = atoi(optarg);
			  break;
		}
	}
    if(!log_ipv4 && !log_ipv6){ // if no set, enable both of them
        log_ipv4 = 1; log_ipv6 = 1;
    }
	openlog("IPDR",  LOG_NDELAY , LOG_LOCAL0);
	KDLOG("Start IPDR %s,%s\n",version,copyright);
	start_time = time(NULL);
    // must set AAA and User interface and operator name
	if(!nic_aaa || !nic_usr[0] || !operator_name[0]){
		usage();
		return 0;
	}
	if(!is_radius){ /* TODO: diameter */
		KDLOG("ONLY RADIUS IMPLEMENT\n");
		return 0;
	}
	if(is_netflow){ /* TODO: NETFLOW */
		KDLOG("NETFLOW NOT IMPLEMENT\n");
		return 0;
	}
	if(ignore_without_aaa){ 
		KDLOG("ATTENTION: ignore users that don't have AAA log!\n");
	}
	if(start_time > LICENSE_TIMESTAMP){
		KDLOG("License time out.\n");
		return 0;
	}
	if(1){ // Verbose state
		KDLOG("seperator=%c "
			  "nic_aaa=%s, nic_usr=%s, "
              "operator_name=%s, service_num=%d, "
              "log_ipv4=%d, log_ipv6=%d\n",
			  class_field_seperator,
			  nic_aaa,nic_usr[0],
              operator_name,
              def_service_num,
              log_ipv4, 
              log_ipv6
              );
		for(i=0; i<nic_usr_i; i++){
			KDLOG("User nic%d:%s\n",i,nic_usr[i]);
		} 
		for(i=0; i<usr_net_i; i++){
			KDLOG("User IP%d:%08X/%08X\n",i,usr_net[i],usr_net_mask[i]);
		} 
	}
//	signal(SIGTERM, sig_handler);
//	signal(SIGINT, sig_handler);

	signal(20, print_stat);
    usr_t = t_init(); // init user DB
    // detached threads attribute
    pthread_attr_init(&pthread_attr);
    pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED);

	start_manage_log_file_threads();
    pthread_create(&free_space_thread_id, &pthread_attr, manage_free_space,NULL);
    pthread_create(&aaa_thread_id, &pthread_attr, start_aaa_thread, NULL);
    if(!is_netflow){
        /* Start User */
        for(i=0; i<nic_usr_i; i++){
            usleep(10000);
            arg[i] = i;
            pthread_create(&user_thread_id[i], &pthread_attr, 
                    start_usr_log_thread, 
                    (void*)&arg[i]);
        } 
    }else{
        /* TODO: impliment NETFLOW reciever */

    }

    pthread_t aaa_api_thread_id;

    pthread_create(&aaa_api_thread_id, NULL, manual_aaa_server, NULL); 
    pthread_join(aaa_api_thread_id, NULL);
    /* LIVE LOOP */
    while(1)
    {
        sleep(60);
    }

    return 0;
}
void dump(char *buf,int len,int n)
{
    int i;
    KDLOG("\nDump:")
        for(i=0; i<n && i<len; i++)
            KDLOG("%02X",buf[i] & 0xff);
    KDLOG("\n");
}
void print_stat(int sig)
{
    int i;
    int d = time(NULL) -  start_time;
    if(d <= 0 ) return;
    KDLOG("Start(sec): %d "
            "user_pkts:%5ld "
            "user_pkts_not_ip:%5ld "
            "user_pkts_ipv4:%5ld "
            "user_pkts_ipv6:%5ld "
            "aaa_pkt_add:%5ld "
            "user_uniq: %5ld "
            "log:%4ld "
            "log_full:%4ld "
            "AAA_pkt_no_user_ignore:%5ld "
            "log/s:%3.3f "
            "ignore_usr_without_aaa:%4ld "
            "udp_pkt_ignore:%ld "
            "udp_pkt_log:%ld "
            "tcp_pkt_ignore:%ld "
            "tcp_pkt_log:%ld "
            " \n",
            d, pkt_count_user_all, pkt_count_not_ip, 
            pkt_count_user_ipv4, pkt_count_user_ipv6,
            user_num, user_uniq_num,log_sum,log_a_sum, 
            acc_not_user,(float)log_sum/d,ignore_without_aaa_num,
            udp_pkt_ignore,udp_pkt_log,
            tcp_pkt_ignore,tcp_pkt_log
         );
    KDLOG("NIC %s Queue len:%lu\n",nic_aaa,pkt_count_aaa);
    for(i=0; i<nic_usr_i; i++){
        KDLOG("NIC %s Queue len:%ld\n",nic_usr[i],pkt_count_usr[i]);
    } 
}
/////////////// TREE FUNCTIONS
#ifdef REDUCE_SESSION
u32 dest_mac(struct node_pkt_t *pkt, int session_num){
    u32 dst;
    u32 dst_ip;
    dst_ip =  pkt->dst_ip4;
#ifdef IGNORE_SRC_PORT
    dst = (pkt->dst_port + dst_ip) % session_num;
#else
    dst = (pkt->src_port + pkt->dst_port + dst_ip) % session_num;
#endif	
    return dst;
}
int check_tcp_session(u32* tcp_session,struct node_pkt_t *pkt){
    u32 t;
    int dst = dest_mac(pkt, TCP_SESSION_NUM);
    t = time(NULL);
    if((t - tcp_session[dst]) < TCP_SESSION_TTL ){	
        tcp_pkt_ignore++;
        return FALSE;
    }else{
        tcp_session[dst] = t;
        tcp_pkt_log++;
        return TRUE;
    }
}
int check_udp_session(u32* udp_session,struct node_pkt_t *pkt){
    u32 t;
    int dst = dest_mac(pkt, UDP_SESSION_NUM);
    t = time(NULL);
    if((t - udp_session[dst]) < UDP_SESSION_TTL ){	
        udp_pkt_ignore++;
        return FALSE;
    }else{
        udp_session[dst] = t;
        udp_pkt_log++;
        return TRUE;
    }
}
#endif	
void write_log(struct node_pkt_t *pkt)
{
    int service_num = def_service_num;
    struct tnode *node = NULL;
    struct user_rec *user = NULL;
    u8 *log[16];
    u8 null[1];
    u8 log_str[1024];
    u8 src_ip[40],dst_ip[40];
    int i;

    null[0] = '\0';
    if(pkt->timestamp > LICENSE_TIMESTAMP){
        KDLOG("License time out.");
        return;
    }
    for(i=0;i<16;i++) log[i] = null;
    log_sum++;

    //if(pkt->ipv4 == 1){  // TEMPORARY
        //ipv4 = (reverse_ip) ? htonl(pkt->src_ip4) : pkt->src_ip4;
        node = t_search(usr_t,pkt->src_ip4);
    //}

    if(node != NULL){
        user = (struct user_rec *) node->data;	
        if(user != NULL){
#ifdef SIMULATE_UDP_SESSION    
            if(pkt->protocol == UDP)
                if(!check_udp_session(user->udp_session,pkt))
                    return;
#endif			
#ifdef REDUCE_TCP_SESSION 
            if(pkt->protocol == TCP)
                if(!check_tcp_session(user->tcp_session,pkt))
                    return;
#endif			

            if(strlen((const char *)user->phone) > 5)	
                log[1] = user->phone;      
            else						
                log[1] = user->name;      
            log[2] = user->mac;
            log[11] = user->E; 
            log[12] = user->N; 
            log[14] = user->imsi;     // imsi
            log[15] = user->imei;    // imei
            log_a_sum++;
            service_num = user->service_num;
        }
    }else if(ignore_without_aaa){
        if(debug>5) KDLOG("ignore user that not have aaa");
        ignore_without_aaa_num++;
        return;
    }
    if(pkt->ipv4){
        sprintf((char*)src_ip,"%08X",ntohl(pkt->src_ip4));
        sprintf((char*)dst_ip,"%08X",ntohl(pkt->dst_ip4));
    }else{
        ipv6_to_str((char*) pkt->src_ip6, (char*)src_ip);
        ipv6_to_str((char*) pkt->dst_ip6, (char*)dst_ip);
        //KDLOG("Log IPv6:%s->%s",src_ip,dst_ip);
    }
    sprintf((char *)log_str,"%s|%s|%ld|%d|||%s|%d|%s|%d|%s|%s|%s|%s|%s\n",
            log[1],log[2],
            pkt->timestamp,
            pkt->protocol,
            src_ip,pkt->src_port,
            dst_ip,pkt->dst_port,
            log[11],log[12],log[13],log[14],log[15]);
#ifndef TO_SYSLOG
    KDLOG("%s",log_str);
    return;
#endif
    if(service_num < 1 || service_num > 15){
        KDLOG("Service num error %d!\n",service_num);
        return;
    }
    int thrd_id = pkt->ipv4 ? service_num : service_num + 15;
    services[thrd_id].need = 1;
    if(services[thrd_id].ready && (services[thrd_id].fd!=NULL) ){ 
        fputs((const char *)log_str,services[thrd_id].fd);
    }else{
        // KDLOG("%s",log_str);  /* file is not ready! Write in syslog */ 
    }


}
void pkt_handler_usr(u_char *arg, const struct pcap_pkthdr *header, 
        const u_char *data)
{
    int nic_id = *(int*)arg;
    u8 *ip,*l4, *ether_type;
    u8 ip_version;
    struct node_pkt_t  *node;
    u16 src_port = 0,dst_port = 0;
    u32 src_ip4,dst_ip4;
    u8  protocol,flags;
    int len = header->len;

    if(len < 34){
        if(debug>3)KDLOG("PKT len is %d\n",len);
        return;
    }
    ip = (u8*)data+14; // Ignore Ethernet 
    ether_type = (u8*)data + 12; 
    if( ether_type[0] == 0x81 && ether_type[1] == 0x00 ){ 
        if(debug>5)KDLOG("PKT is 802.1Q\n");
        ip = ip + 4; 
    }else if(ether_type[0] == 0x88 && 
             (ether_type[1]&0xf0) == 0x60){
        if(debug>5)KDLOG("PKT is PPPoE\n");
        ip = ip + 6 + 2; // Ignore Ethernet + PPPoE + PPP
    } // TODO: check other Ether_type ... 

    //L3
    ip_version = (ip[0] & 0xf0);
    if(ip_version == 0x40){ 
        l4 = ip + (ip[0] & 0x0F)*4;
        protocol = ip[9];
        if(!log_ipv4) return;
    }else if(ip_version == 0x60){ 
        l4 = ip + 40;
        protocol = ip[6];
        if(!log_ipv6) return;
    }else{
        if(debug>1)KDLOG("PKT is not IPv4 or "
                "IPv6(start:%02x%02x%02x%02x end:%02x%02x%02x%02x)\n",
                data[0], data[1], data[2], data[3],
                ip[0], ip[1], ip[2], ip[3]);
        pkt_count_not_ip++;
        return;
    }
    //L4
    if(protocol == TCP || protocol == UDP){
        src_port = (l4[0]<<8) | l4[1];
        dst_port = (l4[2]<<8) | l4[3];
        if(protocol == TCP){
            flags = l4[13]; 
            // syn ==  00000010,  ack = 00010000, fin = 00000001
            if(debug>5) KDLOG("TCP Flags:%X)\n",flags);
            if((flags & 0x03) == 0x0){   // not Syn and not Fin
                if(debug>3) 
                    KDLOG("Ignore TCP middle packets(f:%X)\n",flags);
                return;  
            }else{
                if(debug>3) 
                    KDLOG("TCP start/stop packets(f:%X)\n",flags);
            }
        }
    }else if(protocol != ICMP  && protocol != ICMPv6){
        if(debug>1)KDLOG("PKT is not TCP|UDP|ICMP(%d)\n",protocol);
        return;
    }
    node = (struct node_pkt_t *)malloc(sizeof(struct node_pkt_t));
    node->protocol = protocol;
    pkt_count_user_all++;
    if(ip_version == 0x40){ 
        node->ipv4 = 1;
        memcpy((void *)&src_ip4,ip+12,4);
        memcpy((void *)&dst_ip4,ip+16,4);
        //node->src_ip4 = ntohl(src_ip4);  
        //node->dst_ip4 = ntohl(dst_ip4); FIXME 
        node->src_ip4 = src_ip4;  
        node->dst_ip4 = dst_ip4;
        if(debug>3) KDLOG("Capture PKT: src:%X dst:%X\n",node->src_ip4,node->dst_ip4);
        pkt_count_user_ipv4++;
    }else{
        node->ipv4 = 0;
        memcpy(node->src_ip6, ip+8, 16);
        memcpy(node->dst_ip6, ip+24, 16);
        memcpy((char*)&node->src_ip4, ip+8+12, 4);// last 4 byte of ipv6 AS ipv4
        memcpy((char*)&node->dst_ip4, ip+24+12, 4);// last 4 byte of ipv6 AS ipv4
        //KDLOG("Capture PKT: IPv6\n");
        pkt_count_user_ipv6++;
    }
    node->src_port = src_port;
    node->dst_port = dst_port;
    node->timestamp = time(NULL);

    /* Insert USR packet in Queue */
    pthread_mutex_lock(&pkt_mutex_usr[nic_id]);
    node->next = pkt_head_usr[nic_id];
    pkt_head_usr[nic_id]   = node;
    pkt_count_usr[nic_id]++;
    pthread_mutex_unlock(&pkt_mutex_usr[nic_id]);
}
int is_usr_pkt(struct node_pkt_t *pkt)
{
    int i; 
    u32 ip = ntohl(pkt->src_ip4);   // TEST IT
    if(usr_net_i == 0) return TRUE;
    if(pkt->ipv4 == 0) return TRUE; // FIXME (ignore for IPv6)
    for(i=0; i<usr_net_i; i++){
        if( (ip & usr_net_mask[i]) == usr_net[i] ) {
            if(debug>4)KDLOG("Is User %08X\n",pkt->src_ip4);
            return TRUE;
        }
    } 
    if(debug>4)KDLOG("Not User %08X\n",pkt->src_ip4);
    return FALSE;
}
void *process_pkt_of_usr(void *arg)
{
    struct node_pkt_t  *node;
    int nic_id = *(int*)arg;

    if(debug) KDLOG("Start Process_pkt_of_usr for NIC %d\n",nic_id);
    while(1){
        node = NULL;
        if(pkt_count_usr[nic_id]>0){
            pthread_mutex_lock(&pkt_mutex_usr[nic_id]);
            if(pkt_count_usr[nic_id]>0){
                node = pkt_head_usr[nic_id];
                pkt_head_usr[nic_id] = pkt_head_usr[nic_id]->next;
                pkt_count_usr[nic_id]--;
            }
            pthread_mutex_unlock(&pkt_mutex_usr[nic_id]);
            if(node != NULL){
                if(is_usr_pkt(node)){
                    if(debug>3){ 
                        if(node->ipv4){
                            KDLOG("USE PKT: src:%X dst:%X\n",node->src_ip4, 
                                    node->dst_ip4);
                        }else
                            KDLOG("USE PKT: type ipv6\n");
                    }
                    write_log(node);
                }else{
                    if(debug>3) KDLOG("IGNORE PKT: src:%X dst:%X\n",node->src_ip4, 
                            node->dst_ip4);
                }
                free(node);
            }
        }else{
            usleep(50000);
        }
    }
}
void pkt_handler_aaa(u_char *temp1, const struct pcap_pkthdr *header, 
        const u_char *data)
{
    u8 *ip,*l4,*pkt;
    struct node_aaa_t  *node;
    int dst_port;
    int iphdr_len;
    int l4_len;
    int len = header->len;
    ip = (u8*)data+14; // Ignore Layer 2 header
    if(debug>6) dump((char *)data,len,20);
    /* ONLY IPv4 Packet!  */
    if((ip[0] & 0xf0) != 0x40){ 
        if(debug>1) KDLOG("AAA packet is no IPv4");
        return;
    }
    if(ip[9] != UDP ){
        if(debug>1) KDLOG("AAA packet is no UDP");
        return;  
    }
    iphdr_len = (ip[0] & 0x0F)*4;
    l4 = ip + iphdr_len;
    l4_len = len - 14/*l2*/ - iphdr_len;
    dst_port = ntohs( (l4[3]<<8) | l4[2] );
    if( dst_port != radius_port){
        if(debug>1) KDLOG("AAA packet is no RADIUS");
        return;  
    }
    pkt = (u8*)malloc(l4_len);
    node = (struct node_aaa_t *)malloc(sizeof(struct node_aaa_t));
    memcpy(pkt,l4,l4_len);
    node->pkt     = pkt;
    node->pkt_len = l4_len;
    /* Insert AAA packet in Queue */
    pthread_mutex_lock(&pkt_mutex_aaa);
    node->next = pkt_head_aaa;
    pkt_head_aaa = node;
    pkt_count_aaa++;
    pthread_mutex_unlock(&pkt_mutex_aaa);
}

void *process_pkt_of_aaa(void *p)
{
    struct node_aaa_t  *node;

    if(debug) KDLOG("Start Process_pkt_of_aaa\n");
    while(1){
        node = NULL;
        if(pkt_count_aaa>0){
            pthread_mutex_lock(&pkt_mutex_aaa);
            if(pkt_count_aaa>0){
                node = pkt_head_aaa;
                pkt_head_aaa = pkt_head_aaa->next;
                pkt_count_aaa--;
            }
            pthread_mutex_unlock(&pkt_mutex_aaa);
            if(node != NULL){
                read_radius_pkt(node->pkt, node->pkt_len);
                free(node->pkt);
                free(node);
            }
        }else{
            usleep(50000);
        }
    }
}
void *start_aaa_thread(void *arg)
{
    int i;
    u32 net;
    u32 mask;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    pthread_t pkt_thread_aaa[AAA_THREAD_NUM];
    char aaa_filter[500];

    if(debug) KDLOG("Start Start_aaa_thread\n");
    sprintf(aaa_filter,"udp dst port %d",radius_port);
    pkt_head_aaa = NULL;
    pthread_mutex_init(&usr_t_mutex, NULL);
    pthread_mutex_init(&pkt_mutex_aaa, NULL);
    /* Start AAA packet parser threads */
    for(i=0; i<AAA_THREAD_NUM; i++){
        pthread_create(&pkt_thread_aaa[i], &pthread_attr, process_pkt_of_aaa, NULL);
    } 
    /* Init PCAP of AAA */
    if (pcap_lookupnet(nic_aaa, &net, &mask, errbuf) == -1)
    {
        //KDLOG("Could not get netmask for device %s: %s\n", nic_aaa, errbuf);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(nic_aaa, AAA_MAX_PKT, 1, 1000, errbuf);
    if (handle == NULL)
    {
        KDLOG("could not open device %s: %s\n", nic_aaa, errbuf);
        return NULL;
    }
    if (pcap_compile(handle, &fp, aaa_filter, 0, net) == -1) {
        KDLOG("Couldn't parse filter %s: %s\n", 
                aaa_filter, pcap_geterr(handle));
        return NULL;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        KDLOG("Couldn't install filter %s: %s\n", 
                aaa_filter, pcap_geterr(handle));
        return NULL;
    }
    pcap_loop(handle, 0, pkt_handler_aaa, NULL);
    return NULL;
}
void *start_usr_log_thread(void *arg)
{
    int nic_id = *(int*)arg;
    int i;
    u32 net;
    u32 mask;
    pcap_t *handle;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    pthread_t pkt_thread_usr[USR_THREAD_NUM];

    if(debug) KDLOG("Start Start_usr_thread for NIC %d\n",nic_id);
    pkt_head_usr[nic_id] = NULL;
    pkt_count_usr[nic_id] = 0;
    pthread_mutex_init(&pkt_mutex_usr[nic_id], NULL);
    /* Start USR packet parser threads */
    for(i=0; i<USR_THREAD_NUM; i++){
        pthread_create(&pkt_thread_usr[i], &pthread_attr, process_pkt_of_usr, arg);
    } 
    /* Init PCAP of USR */
    if (pcap_lookupnet(nic_usr[nic_id], &net, &mask, errbuf) == -1)
    {
        //KDLOG("Could not get netmask for device %s: %s\n", 
        //		nic_usr[nic_id], errbuf);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(nic_usr[nic_id], USR_MAX_PKT, 1, 1000, errbuf);
    if (handle == NULL)
    {
        KDLOG("could not open device %s: %s\n", nic_usr[nic_id], errbuf);
        return NULL;
    }
    if (pcap_compile(handle, &fp, USR_FILTER, 0, net) == -1) {
        KDLOG("Couldn't parse filter %s: %s\n", 
                USR_FILTER, pcap_geterr(handle));
        return NULL;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        KDLOG("Couldn't install filter %s: %s\n", 
                USR_FILTER, pcap_geterr(handle));
        return NULL;
    }
    pcap_loop(handle, 0, pkt_handler_usr, (unsigned char*)&nic_id);
    return NULL;
}
void sig_handler(int sig)
{
    KDLOG("Exit with signal %d\n",sig);
    exit(0);
}
