#define APP_IS_CGNAT_LOG 1
#define USER_MAX_NUM 20000
/*
    KERNEL CGNAT -> syslog -> /var/log/logcgnat/fifo ----> this   
    PCAP_AAA --------------------------------------------> this  ------> /var/log/cgnatlog/

    IN rsyslog.cong:
        kern.*                      
        local0.*                    /var/log/cgnatlog/cgnat

*/
#include "util.c"
#define SYSLOG_FIFO "/var/log/cgnat_fifo"
#define SYSLOG_BUF 256	
#define SYSLOG_BUFFER 10000000L	

struct syslog_node_t {
	u8 buf[SYSLOG_BUF];
	u16 len;
	struct syslog_node_t *next;
};
struct node_t {
	u8 *pkt;
	u8  pkt_protocol;
	u16 pkt_len;
	struct node_t *next;
};

struct node_t *pkt_head;
struct syslog_node_t *syslog_head;

//////////////////////////////////////////////////////////////////////////////
void *process_syslog(void *);
void *process_pkt(void *);
void *process_syslog_buf(void *p);
void pkt_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *data);
void log_generate(char *log[22]);
int read_syslog_packet(u8 *udp_pkt);
int read_radius_pkt(u8 *udp_pkt,int len);
void read_syslog_data(u8 *data,int data_len);
void print_stat(int sig);

static long    syslog_count = 0;
static long    syslog_count_overflow = 0;
static long    pkt_count = 0;
static long    nat_not_user = 0;
static long    acc_not_user = 0;	
static time_t start_time = 0;
pthread_mutex_t pkt_mutex;
pthread_mutex_t syslog_mutex;
pthread_t pkt_thread,syslog_thread;
pthread_t syslog_pool[100];

int  diameter_port = 6001,
     radius_port   = 1815,
     syslog_port   = 514;
u32  users_ip, users_mask;
int is_user(u32 ip)
{
	if((ip & users_mask) == (users_ip & users_mask) ) {
		//if(debug)printf("+++ %08X & %08X == %08X & %08X\n",ip,users_mask,users_ip,users_mask);
		return 1;
	}else{
		//if(debug)printf("--- %08X & %08X == %08X & %08X\n",ip,users_mask,users_ip,users_mask);
		return 0;
	}
}
void exit_prog(int sig)
{
	pthread_cancel(pkt_thread);
	pthread_cancel(syslog_thread);
	KDLOG("Exit!");
	exit(0);
}
  

int main(int argc, char **argv) 
{
	pcap_t *handle;
	u32 net;
	u32 mask;
    int i;
	struct bpf_program fp;
	//const char *filter_exp = "udp port 1815";	
	char filter_exp[80];	
	const char *syslog_id  = "CGNAT";	
	char nic[50];
	char errbuf[PCAP_ERRBUF_SIZE];
	debug = 0;
	if(argc < 7){
		printf("Usage: %s <nic> <users_ip> <users_mask> <operator_name> <def_service> <log_dir>" ,argv[0]); 
			// /bin/cgnatd_log eth0 172.22.0.0 255.255.0.0  /var/log/cgnatlog
		return 0;
	}
	sprintf(filter_exp,"udp port %d",radius_port);
	signal(15, exit_prog);
	signal(9 , exit_prog);
	strcpy(nic,argv[1]);
	users_ip   = ntohl(inet_addr(argv[2]));
	users_mask = ntohl(inet_addr(argv[3]));
	strcpy(operator_name,argv[4]);
	def_service_num = atoi(argv[5]);
	log_dir = strdup(argv[6]);
	//printf("user_ip: %08X mask: %08X s:%d\n",users_ip,users_mask,sizeof(users_ip));
	start_time = time(NULL);
	signal(20, print_stat);
	pkt_count = 0;
	syslog_count = 0;
	syslog_count_overflow = 0;
	pkt_head = NULL;
	syslog_head = NULL;
	usr_t = t_init();
	mkfifo(SYSLOG_FIFO, 0666);
	pthread_mutex_init(&usr_t_mutex, NULL);
	pthread_mutex_init(&pkt_mutex, NULL);
	pthread_mutex_init(&syslog_mutex, NULL);
	start_manage_log_file_threads();
	pthread_create(&free_space_thread_id, NULL, manage_free_space,NULL);

	pthread_create(&pkt_thread, NULL, process_pkt, NULL);
	pthread_create(&syslog_thread, NULL, process_syslog, NULL);
    for(i=0; i<12; i++){
        pthread_create(&syslog_pool[i], NULL, process_syslog_buf, NULL);
    } 
	openlog(syslog_id, LOG_PID, LOG_LOCAL0);
	//lookup netmask
	if (pcap_lookupnet(nic, &net, &mask, errbuf) == -1)
	{
		KDLOG("Could not get netmask for device %s: %s\n", nic, errbuf);
		net = 0;
		mask = 0;
	}
	handle = pcap_open_live(nic, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		KDLOG("could not open device %s: %s\n", nic, errbuf);
		return -1;
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		KDLOG("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -1;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		KDLOG("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -1;
	}

	pcap_loop(handle, 0, pkt_handler, NULL);
	KDLOG("NUMBER OF SENT DATA PACKETS: %ld \n",pkt_count);
	getchar();
	getchar();
	return -1;
}
void print_stat(int sig)
{
	int d = time(NULL) -  start_time;
	if(d <= 0 ) return;
	KDLOG("Start(sec): %d AAA_pkt_queue_num:%5ld user_num:%5ld "
            "user_uniq_num: %5ld log_num:%4ld no_user_log_ignore:%5ld "
            "AAA_pkt_no_user_ignore:%5ld log/s:%ld syslog_count:%ld "
            "syslog_count_overflow:%ld ",
	 		d,pkt_count,user_num, user_uniq_num,log_sum,nat_not_user, 
            acc_not_user,log_sum/d, syslog_count, syslog_count_overflow);
}
void pkt_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *data)
{
	u8 pkt_data[65000];
	u8 *ip,*l4,*pkt;
	struct node_t  *node;
	int iphdr_len;
	int l4_len;
	int len = header->len;
	if(len < 100) return;
	memcpy(pkt_data,data,len);
	ip = (u8*)pkt_data+14; // Ignore Layer 2 header  
	if(pkt_data[12] == 0x81) ip = ip + 4; // Ignore VLAN
	if((ip[0] & 0xf0) != 0x40){ // no IP
		if(debug) printf("AAA packet is no IP %X",ip[0]);
		return;
	}
	iphdr_len = (ip[0] & 0x0F)*4;
	if(ip[9] != UDP ){
		if(debug) printf("AAA packet is no UDP");
		return; // no UDP 
}
	l4 = ip + iphdr_len;
	l4_len = len - 14/*l2*/ - iphdr_len;
	pkt = (u8*)malloc(l4_len);
	node = (struct node_t *)malloc(sizeof(struct node_t));
	memcpy(pkt,l4,l4_len);
	node->pkt = pkt;
	node->pkt_protocol = ip[9];
	node->pkt_len      = l4_len;

	pthread_mutex_lock(&pkt_mutex);
	node->next = pkt_head;
	pkt_head   = node;
	pkt_count++;
	pthread_mutex_unlock(&pkt_mutex);
	//if(debug) printf("A");
}

void *process_syslog(void *p)
{
	int fd = -1;
	int n;
	u8 buf[SYSLOG_BUF];
    struct syslog_node_t *node;

	while(fd == -1){
		fd = open(SYSLOG_FIFO, O_RDONLY);
		sleep(1);
		if(fd <= 0 ) KDLOG("Error in fifo open\n"); 
	}
	while (1)
	{
		n = read(fd, buf, SYSLOG_BUF);
		if(n <= 0) continue;
        if(syslog_count > SYSLOG_BUFFER){
            syslog_count_overflow++;
            continue;
        }

        node = (struct syslog_node_t *) malloc(sizeof(struct syslog_node_t));
        if(node == NULL) continue;
        memcpy(node->buf, buf, n);
        node->len = n;
        
        pthread_mutex_lock(&syslog_mutex);
        node->next  = syslog_head;
        syslog_head = node;
        syslog_count++;
        pthread_mutex_unlock(&syslog_mutex);
    }

}
void *process_pkt(void *p)
{
	int dst_port;
	struct node_t  *node;

	while(1){
		if(pkt_count>0){
			pthread_mutex_lock(&pkt_mutex);
			node = pkt_head;
			pkt_head = pkt_head->next;
			pkt_count--;
			pthread_mutex_unlock(&pkt_mutex);
			dst_port = ntohs( (node->pkt[3]<<8) | node->pkt[2] );
			if(node->pkt_protocol == UDP && dst_port == radius_port)
				read_radius_pkt(node->pkt, node->pkt_len);

			free(node->pkt);
			free(node);
		}else{
			usleep(1000);
		}
	}
}

void *process_syslog_buf(void *p)
{
	struct syslog_node_t  *node;

	while(1){
		if(syslog_count>0){
			node = NULL;
			pthread_mutex_lock(&syslog_mutex);
			if(syslog_count>0){
				node = syslog_head;
				syslog_head = syslog_head->next;
				syslog_count--;
			}
			pthread_mutex_unlock(&syslog_mutex);
			if(node != NULL) read_syslog_data(node->buf, node->len);
			free(node);
		}else{
			usleep(1000);
		}
	}
}

void read_syslog_data(u8 *data,int data_len)
{
    int service_num = def_service_num;
	struct tnode *node = NULL;
	struct user_rec *user = NULL;
	u32 ips;
	int i,j;
	u8 *tokens[22];
	u8 *log[22];
	u8 *null =(u8 *)  "";
    char log_str[1024];
	
	//myCGNAT	
	//... |1486389844|UDP|5.221.101.1|54646|5.221.101.1|54646|91.243.171.171|1812|30
	// 0     1        2       3        4      5          6         7          8   9
	// ...|1506406909|17|330F2A09|5066|330F2A09|5066|AC1C0BC2|5160|1506406939|
	// 0       1      2     3      4      5      6     7       8       9
	//
	for(i=0;i<21;i++) log[i] = null;
	j = 0;
	tokens[j++] = data;
	for(i=1; i<data_len; i++){
		if(j>20) break;
		if(data[i] == '|'){
			data[i] = '\0';
			tokens[j++] = data + i + 1;
		}
	}
	if(j<10){
		//if(debug) printf("is less field %d\n",j);
		return;
	}
	//tmp[0] = '0'; tmp[1] = 'x'; tmp[2] = '\0';
	//strncat(tmp,tokens[3],20);
	ips = strtol((const char *)tokens[3],(char**)0,16);
	if(is_user(ips) == 0){
		nat_not_user++;
		//if(debug) printf("is not user %s\n",tokens[3]);
		return;
	}
	log_sum++;
	node = t_search(usr_t,ips);
	if(node != NULL)
		user = (struct user_rec *) node->data;	
	else return;
	log[3] = tokens[1]; // timestamp
	log[4] = tokens[2]; // TCP/UDP 
	log[5] = tokens[3];  // user invalid IP
	log[6] = tokens[4];  // user invalid port
	log[7] = tokens[5];  // valid ip
	log[8] = tokens[6];  // valid port
	log[9] = tokens[7];  // dest ip
	log[10] = tokens[8];  // dest port
	if(user != NULL){
		if(strlen((const char*)user->phone)>1)	log[1] = user->phone;      
		else				log[1] = user->name;      
		log[2] = user->mac;
		log[11] = user->E; // loc
		log[12] = user->N; // loc
		log[14] = user->imsi;     // imsi
		log[15] = user->imei;    // imei
	}
		sprintf(log_str,"%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n",
		log[1],log[2],log[3],log[4],log[5],log[6],log[7],log[8],log[9],
		log[10],log[11],log[12],log[13],log[14],log[15]);
    if(debug>5) KDLOG("%s",log_str);
    if(service_num < 1 || service_num > 14){
        KDLOG("Service num error %d!\n",service_num);
        return;
    }
    services[service_num].need = 1;
    if(services[service_num].ready && (services[service_num].fd!=NULL) ){ 
        fputs(log_str,services[service_num].fd);
    }else{
        //KDLOG("%s",log_str);  /* file is not ready! Write in syslog */ 
    }
}

