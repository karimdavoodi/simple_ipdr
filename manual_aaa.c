#include "util.c"


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

    user.ipv4 = htonl(inet_addr(ip));
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
            user.ipv4,
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
    u32 ipv4 = htonl(inet_addr(ip));
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
                user->ipv4,
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
void *manual_aaa_server()
{
    int parentfd,clifd;
    int optval;
    struct sockaddr_in tmpsock;
    struct sockaddr_in serveraddr;
    socklen_t clientlen;
    int n;
    char req[512],resp[512];

    usr_t = t_init(); // init user DB
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
int main()
{
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, manual_aaa_server, NULL); 
    while(1) sleep(10);
}
