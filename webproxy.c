#include <stdio.h>
#include <stdlib.h>
#include <string.h>     /* for fgets */
#include <strings.h>    /* for bzero, bcopy */
#include <unistd.h>     /* for read, write */
#include <sys/socket.h> /* for socket use */
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <sys/select.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <ctype.h>
#include <openssl/md5.h>
#include <dirent.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>

#define DEFAULT_PORT 80
#define MAXLINE 2048
#define MAXBUF 3*8192  /* max I/O buffer size */
#define MIDBUF 150
#define LISTENQ 1024 /* second argument to listen() */
#define CACHE_TIMEOUT 60
#define DEFAULT_TIMEOUT 10000

#define CACHE_PATH              "./cache"
#define CACHE_FULL_PATH         "./cache/"
#define BLACKLIST               "blacklist"
#define DNS_CACHE_PATH          "./dns_cache"
#define DNS_CACHE_FULL_PATH     "./dns_cache/"
#define LINE                    "-------------------------------------"
#define CHECK(X) ({int __val = (X); (__val == (-1) ? ({fprintf(stderr, "ERROR ("__FILE__":%d) -- %s\n", __LINE__, strerror(errno)); exit(-1); -1;}) : __val);})

typedef struct clnt_rq_s {
    char Method[MIDBUF];
    char URL[MIDBUF];
    char Version[MIDBUF];
    char Host[MIDBUF];
} clnt_rq_t;

typedef enum err_code {
    NOT_SUPPORTED_METHOD,   //400 Bad Request
    HOSTNAME_ERROR,         //404 Not Found
    FORBIDDEN,              //403 Forbidden
    SUCCESS, 
}err_code_t;

typedef struct cpid_node {
    pid_t cpid;
    struct cpid_node *next;
}cpid_node_t;

static int client_connection(int port);
static void handle_request(int cfd, int port,cpid_node_t **head_node, int *pipefd);
static void error_handling(int cfd, err_code_t err);
static void server_connection(char *server_node, int *sfd, int cfd, err_code_t *err);
static void server_response(clnt_rq_t client_request, int cfd,int sfd, err_code_t err);
static void host_lookup(char *in,clnt_rq_t *rq);
static void parse_client_request(char *in, clnt_rq_t *rq);
static void server_close(int sfd);
static void client_close(int cfd);
static void caching(char *buf, char *URL, int content_len, FILE *cache_fp, bool need_cache,char *cache_name);
static void md5(char* str, char* md5buf);
static void send_from_cache(char *URL, int cfd);
static void is_blacklist(char *host, int cfd);
static bool is_cache_expired(char *cache_name);
static void caching_dns(char *server_node, in_addr_t s_addr);
static void get_dns_from_cache(char *server_node, in_addr_t *s_addr);
static char *strcasestr(char * haystack, char *needle);
static void prefetch_all_url(char *html, char *host);
static void lookup_html(char *host);
static void prefetch_connection(char *server_node, int *sfd);
static void prefetching(char *url, char *host);
static void prefetching_all(char *host);
static void add_cpid(cpid_node_t **head_node, pid_t cpid);
static void remove_cpid(cpid_node_t **head_node, pid_t cpid);
static void remove_all_cpid(cpid_node_t **head_node);
static void child_state(int *pipefd,cpid_node_t **head_node);
static void open_pipe(int *pipe_fd);
static void parent_exiting(pid_t pid, int pipe_fdw);


int main(int argc, char **argv){
    int client_listenfd, cfd=-1, port, clientlen = sizeof(struct sockaddr_in);
    int timeout = 0;
    struct timespec now, start;
    struct sockaddr_in clientaddr;
    pid_t pid = getpid();
    if (argc > 3){
        fprintf(stderr, "usage: %s <port> <timeout>\n", argv[0]);
        exit(0);
    }
    cpid_node_t *cpid_head = NULL;
    int pipe_fd[2];
    open_pipe(pipe_fd);
    system("rm -rf cache dns_cache");
    port = (argc==1) ? DEFAULT_PORT:atoi(argv[1]);    
    timeout = (argc==3)? atoi(argv[2]):DEFAULT_TIMEOUT;
    printf("Timeout: %d sec\n", timeout);
    clock_gettime(CLOCK_REALTIME, &start);
    clock_gettime(CLOCK_REALTIME, &now);
    client_listenfd = client_connection(port);
    while (((now.tv_sec - start.tv_sec) < timeout)){
        child_state(pipe_fd,&cpid_head);
        clock_gettime(CLOCK_REALTIME, &now);
        cfd = accept(client_listenfd, (struct sockaddr *)&clientaddr, (socklen_t * )&clientlen);
        handle_request(cfd, port,&cpid_head,pipe_fd);
    }
    remove_all_cpid(&cpid_head);
    parent_exiting(pid, pipe_fd[1]);
}

void travese_cpid(cpid_node_t *head_node){
    printf("link list:");
    cpid_node_t *temp =head_node ;
    while(temp!=NULL){
        printf("%d ", temp->cpid);
        temp=temp->next;
    }
    printf("\n");
}

void add_cpid(cpid_node_t **head_node, pid_t cpid){
    cpid_node_t *temp = (*head_node);
    cpid_node_t *new_node = NULL;
    if((*head_node)==NULL){
        (*head_node) = (cpid_node_t *)malloc(sizeof(cpid_node_t));
        (*head_node)->cpid = cpid;
        (*head_node)->next = NULL;
        printf("cpid %d added\n",(*head_node)->cpid);
        return;
    }
    while(temp->next != NULL){
        temp = temp->next;
    }
    new_node = (cpid_node_t *)malloc(sizeof(cpid_node_t));
    new_node->next = NULL;
    new_node->cpid = cpid;
    temp->next = new_node;
    printf("cpid %d added\n",temp->cpid);
}



void remove_cpid(cpid_node_t **head_node, pid_t cpid){
    cpid_node_t *temp = *head_node; 
    cpid_node_t *rm_node = NULL; 
    if((*head_node)==NULL){
        printf("no available cpid\n");
        return;
    }
    if(temp->cpid==cpid){
        (*head_node) = (*head_node)->next;
        free(temp);
        printf("cpid %d removed\n",cpid);
        return;
    }
    
    while(temp->next!=NULL){
        if((temp->next->cpid)==cpid){
            rm_node = temp->next;
            temp->next = temp->next->next;
            free(rm_node);
            rm_node = NULL;
            printf("cpid %d removed\n",cpid);
            break;
        };
        temp = temp->next;
    }
}

void remove_all_cpid(cpid_node_t **head_node){
    cpid_node_t *temp=NULL;
    while((*head_node)!=NULL){
        temp = (*head_node);
        *head_node = (*head_node)->next;
        kill(temp->cpid, SIGKILL);
        printf("cpid %d terminated\n", temp->cpid);
        free(temp);
    }
}


static void child_state(int *pipefd,cpid_node_t **head_node){
    pid_t cpid = -1;
    
    //read at parents
    read(pipefd[0], &cpid, sizeof(int));
    if(cpid!=-1){
        remove_cpid(head_node, cpid);
    }
}

/*
 * handle_request - handling request like 
 * request parse, request connection state
 * transfer file and clean up
 */
static void handle_request(int cfd, int port, cpid_node_t **head_node, int *pipefd){ 
    pid_t child_pid = -1;
    if(cfd==-1)
        return;
    if((child_pid = fork())==0){
        pid_t cpid = getpid();
        openlog("webproxy:child", LOG_PID, LOG_USER);
        char buf[MAXLINE];
        clnt_rq_t client_request;
        err_code_t err;
        int sfd=-1, status;
        pid_t pid;
        memset(&client_request, 0, sizeof(client_request));
        CHECK(read(cfd, buf, MAXLINE));
        parse_client_request(buf, &client_request);
        is_blacklist(client_request.Host, cfd);
        prefetching_all(client_request.Host);
        send_from_cache(client_request.URL, cfd);
        server_connection(client_request.Host,&sfd, cfd, &err);
        server_response(client_request, cfd,sfd,err);
        server_close(sfd);
        client_close(cfd);
        closelog();
        while ((pid=waitpid(-1,&status,0))!=-1) {
            printf("Grand Child %d terminated\n",pid);
        }        
        close(pipefd[0]);
        write(pipefd[1],&cpid,sizeof(int));
        close(pipefd[1]);
        exit(0);
    }else if(child_pid!=-1){
        add_cpid(head_node, child_pid);
    }
}




static void host_lookup(char *in,clnt_rq_t *rq){
    char in_cp[MAXBUF];
    char *p= NULL;
    char host[MIDBUF], domain[MIDBUF];
    strcpy(in_cp, in);
    //check everyline with dimiliter "\r\n"
    p = strtok(in_cp, "\r\n");
    while (p!= NULL){
        sscanf(p, "%s %s", host,domain);
        if((strcmp(host, "Host:")==0)){
            strcpy((*rq).Host, domain);
            return;
        }
        p = strtok(NULL, "\r\n"); 
    }
    (*rq).Host[0] = '\0';
}

static void server_close(int sfd){
    if(sfd==-1)
        return;
    CHECK(shutdown(sfd, SHUT_RDWR));
    close(sfd);
}

static void client_close(int cfd){
    if(cfd==-1)
        return;
    CHECK(shutdown(cfd, SHUT_RDWR));
    close(cfd);
}

static void parse_client_request(char *in, clnt_rq_t *rq){
    char in_cp[MAXBUF];
    char *line= NULL;
    char line_cp[MAXBUF],url_cp[MAXBUF] ;
    char *token[3], *p;
    int i =0;
    host_lookup(in,rq);
    strcpy(in_cp, in);
    line = strtok(in_cp, "\r\n");
    strcpy(line_cp, line);

    p = strtok(line_cp, " ");
    while(p!=NULL){
        token[i++]=p;
        p=strtok(NULL, " ");
    }
    strcpy(url_cp,      token[1]);
    p = strtok(url_cp, ":");
    token[i++]=p;
    if(token!=NULL && strcmp(token[3], "http")!=0){
        strcpy((*rq).URL, token[3]);
    }else{
        strcpy((*rq).URL, token[1]);
    }    

    strcpy((*rq).Method,  token[0]);
    strcpy((*rq).Version, token[2]);
    printf("%s\nMethod: [%s]\nURL: [%s]\nVersion: [%s]\n%s\n", \
    LINE,rq->Method, rq->URL, rq->Version, LINE);
}

/*
 * error_handling - transfer 500 on error
 */
static void error_handling(int fd, err_code_t err){
    char header[MAXBUF];
    uint32_t header_len=0;
    int content_len = 0;
    char content[MIDBUF];
    switch(err){
        case NOT_SUPPORTED_METHOD:
            CHECK(content_len = snprintf(content, MIDBUF, "<html><head></head><body><h1>%s<h1></body></html>","400 Bad Request"));
            CHECK(header_len = snprintf(header, MAXBUF, "HTTP/1.1 400 Bad Request\r\n"));
            break;
        case HOSTNAME_ERROR:
            CHECK(content_len = snprintf(content, MIDBUF, "<html><head></head><body><h1>%s<h1></body></html>","404 Not Found"));
            CHECK(header_len = snprintf(header, MAXBUF, "HTTP/1.1 404 Not Found\r\n"));
            break;
        case FORBIDDEN:
            CHECK(content_len = snprintf(content, MIDBUF, "<html><head></head><body><h1>%s<h1></body></html>","403 Forbidden"));
            CHECK(header_len = snprintf(header, MAXBUF, "HTTP/1.1 403 Forbidden\r\n"));
            break;
        case SUCCESS:
            return;
    }
    CHECK(header_len+= snprintf(header+header_len, MAXBUF-header_len, "Content-Type: text/html\r\n"));
    CHECK(header_len+= snprintf(header+header_len, MAXBUF-header_len, "Content-Length: %u\r\n\r\n", content_len));
    CHECK(send(fd, header, header_len, 0));
    CHECK(send(fd, content, content_len,0));
}



 



/*
 * client_connection - open and return a listening socket on port
 * Returns -1 in case of failure
 */
int client_connection(int port)
{
    int listenfd, optval = 1;
    struct sockaddr_in serveraddr;
    int flags;
    /* Create a socket descriptor */
    listenfd = CHECK(socket(AF_INET, SOCK_STREAM, 0));
    flags = CHECK(fcntl(listenfd,F_GETFL));
    CHECK(fcntl(listenfd,F_SETFL, flags | O_NONBLOCK));
    /* Eliminates "Address already in use" error from bind. */
    CHECK(setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *)&optval, sizeof(int)));

    /* listenfd will be an endpoint for all requests to port
       on any IP address for this host */
    bzero((char *)&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)port);
    CHECK(bind(listenfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)));

    /* Make it a listening socket ready to accept connection requests */
    CHECK(listen(listenfd, LISTENQ));
    return listenfd;
} /* end open_listenfd */


void server_connection(char *server_node, int *sfd, int cfd, err_code_t *err){
    struct hostent *hostnm;         /*host name information*/
    struct sockaddr_in server;      /*server address*/
    unsigned short port = 80;
    in_addr_t s_addr = -1;
    if(server_node==NULL){
        *err = HOST_NOT_FOUND;
        return;
    }
    get_dns_from_cache(server_node, &s_addr);
    if(s_addr!=-1){
        server.sin_addr.s_addr = s_addr;
    }else{
        hostnm = gethostbyname(server_node);
        if(hostnm == NULL){
            //printf("HOST: DNS Not Found\n");
            *err = HOST_NOT_FOUND;
            return;
        }
        server.sin_addr.s_addr = *((unsigned long *)hostnm->h_addr);
    }
    
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    caching_dns(server_node,server.sin_addr.s_addr);

    CHECK(*sfd = socket(AF_INET, SOCK_STREAM, 0));
    if(connect(*sfd, (struct sockaddr *)&server, sizeof(server))==-1){
        server_close(*sfd);
    }
    *err = SUCCESS;
}


void caching_dns(char *server_node, in_addr_t s_addr){
    char dns_cache_name[MIDBUF]=DNS_CACHE_FULL_PATH, s_addr_str[MIDBUF], md5buf[MIDBUF]={0}; 
    FILE *dns_fp;
    struct stat st = {0};
    if(stat(DNS_CACHE_PATH, &st)==-1){
        mkdir(DNS_CACHE_PATH, 0777);
    }
    md5(server_node, md5buf);
    strcat(dns_cache_name, md5buf);

    sprintf(s_addr_str, "%u", s_addr);
    if(access(dns_cache_name,F_OK)==0){
        return;
    }
    
    dns_fp = fopen(dns_cache_name, "wb");
    if(!dns_fp){
        printf("CACHE_DNS: %s %s\n",strerror(errno),dns_cache_name);
        return;
    }
    fwrite(s_addr_str,1,strlen(s_addr_str), dns_fp);
    printf("CACHE_DNS: %s Cached\n", server_node);
    fclose(dns_fp);
}


void get_dns_from_cache(char *server_node, in_addr_t *s_addr){
    char md5buf[MIDBUF]={0};
    char dns_cache_name[MIDBUF]=DNS_CACHE_FULL_PATH;
    char dns_buf[MIDBUF]={0};
    char *endptr;
    md5(server_node, md5buf);
    strcat(dns_cache_name, md5buf);
    FILE* dns_fd = fopen(dns_cache_name, "rb");
    if(!dns_fd){
        *s_addr = -1;
        return;
    }
    if((fread(dns_buf, 1, MAXBUF, dns_fd))>0){
        *s_addr = strtol(dns_buf,&endptr,10);
    }
    printf("CACHE_DNS: %s Sent From Cache\n", server_node);

}

void server_response(clnt_rq_t client_request, int cfd, int sfd, err_code_t err){
    char s_buf[MIDBUF];
    char r_buf[MAXBUF];
    char md5buf[MIDBUF]={0};
    int header_len = 0, content_len=0;
    bool need_cached = 0;
    FILE *cache_fp =NULL;
    struct stat st = {0};
    char cache_name[MIDBUF] = CACHE_FULL_PATH;
    if(err == HOST_NOT_FOUND){
        error_handling(cfd,HOST_NOT_FOUND);
        return;
    }
    if(strcmp(client_request.Method, "GET")!=0){
        error_handling(cfd,NOT_SUPPORTED_METHOD);
        return;
    }
    
    CHECK(header_len = snprintf(s_buf, MIDBUF, "%s %s %s\r\n", client_request.Method, client_request.URL,client_request.Version));
    CHECK(header_len += snprintf(s_buf+header_len, MIDBUF-header_len, "Host: %s\r\n\r\n", client_request.Host));
    
    md5(client_request.URL, md5buf);
    strcat(cache_name, md5buf);
    
    need_cached = (access(cache_name, F_OK)==0)? false: true;
    if(need_cached){
        if(stat(CACHE_PATH, &st)==-1){
            mkdir(CACHE_PATH, 0777);
        }
        cache_fp = fopen(cache_name, "wb");
    }

    CHECK(send(sfd, s_buf, header_len, 0));
    while((content_len = read(sfd, r_buf, MAXBUF))>0){
        caching(r_buf, client_request.URL, content_len, cache_fp,need_cached,cache_name);
        CHECK(send(cfd, r_buf, content_len, 0));
    }
    printf("SERVER: Sent From Remote Server %s\n ", client_request.URL);
    //syslog(LOG_INFO, "%s->%s is CACHED", client_request.URL, cache_name);
    if(need_cached){
        printf("CACHE_PAGE: %s->%s is Cached\n", client_request.URL, cache_name);
        fclose(cache_fp);
    }
}

void caching(char *buf, char *URL, int content_len, FILE *cache_fp, bool need_cache, char *cache_name){
    if(need_cache==false){
        return;
    }
    if(cache_fp==NULL){
        printf("%s %s\n",strerror(errno),cache_name);
        return;
    }
    
    fwrite(buf,1,content_len, cache_fp);
}

void prefetching_all(char *host){
    if(fork()==0){
        lookup_html(host);
        closelog();
        printf("grandchild exiting %d\n", getpid());
        exit(0);
    }
}


void send_from_cache(char *URL, int cfd){
    int content_len;
    char cache_buf[MAXBUF] = {0};
    char cache_name[MIDBUF] = CACHE_FULL_PATH, md5buf[MIDBUF]={0};
    md5(URL, md5buf);
    char rm_file[MIDBUF];
    strcat(cache_name, md5buf);
    FILE* cache_fd = fopen(cache_name, "rb");
    if(!cache_fd){
        return;
    }
    if(!is_cache_expired(cache_name)){
        printf("CACHE_PAGE: Cache Expired\nCACHE_PAGE: Requesting From Server\n");
        snprintf(rm_file,MIDBUF+4, "rm %s", cache_name);
        system(rm_file);
        return;
    }
    while((content_len = fread(cache_buf, 1, MAXBUF, cache_fd))>0){
        CHECK(send(cfd, cache_buf, content_len, 0));
    }
    printf("CACHE_PAGE: Sent From Cache %s\n", cache_name);
    fclose(cache_fd);
    client_close(cfd);
    closelog();
    exit(0);
}

//ref: https://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c
void md5(char* str, char* md5buf){
  unsigned char md5sum[16];
  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, str, strlen(str));
  MD5_Final(md5sum, &ctx);

  for(int i = 0; i < 16; ++i){
    sprintf(md5buf+i*2, "%02x", (unsigned int)md5sum[i]);
  }
}


void is_blacklist(char *host, int cfd){
    FILE *bl_fp;
    bl_fp = fopen(BLACKLIST, "r");
    char *line= NULL;
    size_t len = 0;
    ssize_t nread;
    if(!bl_fp) 
        return;
    while((nread = getline(&line, &len, bl_fp)) != -1){
        if(strcmp(host, line)==0){
            error_handling(cfd, FORBIDDEN);
            exit(0);
        }
    }
}


bool is_cache_expired(char *cache_name){
    struct stat attr;
    struct timespec now;
    stat(cache_name, &attr);
    clock_gettime(CLOCK_REALTIME, &now);
    if((now.tv_sec - attr.st_mtim.tv_sec) > CACHE_TIMEOUT){
        return false;
    }
    return true;
}


//ref https://stackoverflow.com/questions/61143649/extract-all-urls-from-html-in-c
char * strcasestr(char * haystack, char *needle){
  while (*haystack){
    char * ha = haystack;
    char * ne = needle;

    while (tolower(*ha) == tolower(*ne)){
      if (!*++ne)
        return haystack;
      ha += 1;
    }
    haystack += 1;
  }
  return NULL;
}

//ref https://stackoverflow.com/questions/61143649/extract-all-urls-from-html-in-c
void prefetch_all_url(char *html, char *host){
    char * begin = html;
    char * end;
    char url[MIDBUF] = {0};
    while ((begin = strcasestr(begin, "<a href=\"")) != NULL){
        begin += 9; 
        end = strchr(begin, '"');
        if (end != NULL){
            strncpy(url, begin, (int) (end - begin));
            prefetching(url, host);
            begin = end + 1;
        }
    }
}

void lookup_html(char *host){
    char md5buf[MIDBUF]={0}, host_name[MIDBUF] = CACHE_FULL_PATH;
    char html_buf[MAXBUF] = {0}, url_buf[MIDBUF] = {0};  
    int html_len = 0,url_len = 0;
    FILE *cache_fp;
    openlog("webproxy:grandchild", LOG_PID, LOG_USER);
    if(host==NULL){
        return;
    }
    CHECK(url_len = snprintf(url_buf, MIDBUF, "http://%s/",host));
    md5(url_buf, md5buf);
    strcat(host_name, md5buf);
    cache_fp = fopen(host_name, "r");
    
    //html cache not found
    if(cache_fp==NULL){
        exit(0);
    }
    while((html_len = fread(html_buf, 1, MAXBUF, cache_fp))>0){
        prefetch_all_url(html_buf, host);
    }
}

//use ather cache name
void prefetching(char *url, char *host){
    char *http;
    char url_buf[MIDBUF] = {0}, link[MIDBUF] = {0}, md5buf[MIDBUF];
    char r_buf[MAXBUF]={0}, cache_name[MIDBUF] = CACHE_FULL_PATH;
    int url_len = 0;
    http = strstr(url, "http");
    int sfd, content_len=0;
    FILE *prefect_fp;
    if(http){
        strcat(link, http);
        CHECK(url_len = snprintf(url_buf, MIDBUF, "GET %s HTTP/1.1\r\n",http));
    }else{
        CHECK(snprintf(link, MIDBUF, "http://%s/%s",host, url));
        CHECK(url_len = snprintf(url_buf, MIDBUF, "GET http://%s/%s HTTP/1.1\r\n",host, url));
    }
    CHECK(url_len += snprintf(url_buf+url_len, MIDBUF-url_len, "Host: %s\r\n\r\n", host));
    
    md5(link, md5buf);
    strcat(cache_name, md5buf);
    if(access(cache_name, F_OK)==0){
        return;
    }

    prefetch_connection(host, &sfd);
    CHECK(send(sfd, url_buf, url_len, 0));
    prefect_fp = fopen(cache_name, "wb");
    if(!prefect_fp) {
        return;
    }
    while((content_len = read(sfd, r_buf, MAXBUF))>0){
        fwrite(r_buf,1,content_len, prefect_fp);
    }
    fclose(prefect_fp);
    printf("PREFETCH: %s->%s Prefetched\n", link,cache_name);
    //syslog(LOG_INFO, "%s->%s is PREFETCHED", link, cache_name);
    server_close(sfd);
}


void prefetch_connection(char *server_node, int *sfd){
    struct hostent *hostnm;         /*host name information*/
    struct sockaddr_in server;      /*server address*/
    unsigned short port = 80;
    if(server_node==NULL){
        return;
    }
    
    hostnm = gethostbyname(server_node);
    if(hostnm == NULL){
        printf("PREFETCH: Host Not Found\n");
        exit(0);
    }
    
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = *((unsigned long *)hostnm->h_addr);    
    CHECK(*sfd = socket(AF_INET, SOCK_STREAM, 0));
    CHECK(connect(*sfd, (struct sockaddr *)&server, sizeof(server)));   
}

void open_pipe(int *pipe_fd){
    int flags;
    CHECK(pipe(pipe_fd));
    flags = CHECK(fcntl(*pipe_fd,F_GETFL));
    CHECK(fcntl(*pipe_fd,F_SETFL, flags | O_NONBLOCK));
}

static void parent_exiting(pid_t pid, int pipe_fdw){
    if(pid!=0){
        wait(NULL);
        if(pipe_fdw!=-1)
            close(pipe_fdw);
        printf("Connection:Close\n");
    }
}