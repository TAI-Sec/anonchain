/*
 * anonchain_preload.c — LD_PRELOAD shim
 * Hooks connect() + getaddrinfo() → routes via SOCKS5 local proxy.
 * Non-loopback TCP connect is tunneled; DNS resolution is delegated
 * to the local chain via SOCKS5h (ATYP=3) hostname form.
 *
 * Build:
 *   gcc -shared -fPIC -O2 -o anonchain_preload.so anonchain_preload.c -ldl
 * Use:
 *   LD_PRELOAD=/usr/local/lib/anonchain/anonchain_preload.so \
 *   ANONCHAIN_PORT=9050  <tool> args...
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static int (*real_connect)(int,const struct sockaddr*,socklen_t)=NULL;
static int (*real_getaddrinfo)(const char*,const char*,
                               const struct addrinfo*,struct addrinfo**)=NULL;
static __thread int busy=0;

static int proxy_port(void){
    const char*p=getenv("ANONCHAIN_PORT");
    if(!p) return 0;
    int v=atoi(p);
    return (v>0&&v<65536)?v:0;
}

static int is_loopback(const struct sockaddr*a){
    if(a->sa_family==AF_INET){
        unsigned int ip=ntohl(((struct sockaddr_in*)a)->sin_addr.s_addr);
        return (ip>>24)==127;
    }
    if(a->sa_family==AF_INET6){
        static const unsigned char lo[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        return memcmp(&((struct sockaddr_in6*)a)->sin6_addr,lo,16)==0;
    }
    return 0;
}

static int socks5_hs_addr(int fd,const struct sockaddr*t){
    unsigned char g[3]={5,1,0};
    if(send(fd,g,3,0)!=3) return -1;
    unsigned char r[2];
    if(recv(fd,r,2,0)!=2) return -1;
    if(r[0]!=5||r[1]!=0){errno=ECONNREFUSED;return -1;}
    unsigned char req[22]; int n;
    req[0]=5; req[1]=1; req[2]=0;
    if(t->sa_family==AF_INET){
        req[3]=1;
        memcpy(req+4,&((struct sockaddr_in*)t)->sin_addr,4);
        memcpy(req+8,&((struct sockaddr_in*)t)->sin_port,2);
        n=10;
    } else if(t->sa_family==AF_INET6){
        req[3]=4;
        memcpy(req+4,&((struct sockaddr_in6*)t)->sin6_addr,16);
        memcpy(req+20,&((struct sockaddr_in6*)t)->sin6_port,2);
        n=22;
    } else {errno=EAFNOSUPPORT;return -1;}
    if(send(fd,req,n,0)!=n) return -1;
    unsigned char hdr[4];
    if(recv(fd,hdr,4,0)!=4) return -1;
    if(hdr[0]!=5||hdr[1]!=0){errno=ECONNREFUSED;return -1;}
    int extra=(hdr[3]==1)?6:(hdr[3]==4)?18:0;
    if(hdr[3]==3){
        unsigned char l;
        if(recv(fd,&l,1,0)!=1) return -1;
        extra=l+2;
    }
    unsigned char b[260]; int g2=0;
    while(g2<extra){
        int k=recv(fd,b+g2,extra-g2,0);
        if(k<=0) return -1;
        g2+=k;
    }
    return 0;
}

static int socks5_hs_host(int fd,const char*host,unsigned short port){
    unsigned char g[3]={5,1,0};
    if(send(fd,g,3,0)!=3) return -1;
    unsigned char r[2];
    if(recv(fd,r,2,0)!=2) return -1;
    if(r[0]!=5||r[1]!=0){errno=ECONNREFUSED;return -1;}
    size_t hl=strlen(host);
    if(hl>255){errno=ENAMETOOLONG;return -1;}
    unsigned char req[4+256+2];
    req[0]=5; req[1]=1; req[2]=0; req[3]=3;
    req[4]=(unsigned char)hl;
    memcpy(req+5,host,hl);
    req[5+hl]=(port>>8)&0xFF;
    req[6+hl]=port&0xFF;
    int n=7+hl;
    if(send(fd,req,n,0)!=n) return -1;
    unsigned char hdr[4];
    if(recv(fd,hdr,4,0)!=4) return -1;
    if(hdr[0]!=5||hdr[1]!=0){errno=ECONNREFUSED;return -1;}
    int extra=(hdr[3]==1)?6:(hdr[3]==4)?18:0;
    if(hdr[3]==3){
        unsigned char l;
        if(recv(fd,&l,1,0)!=1) return -1;
        extra=l+2;
    }
    unsigned char b[260]; int g2=0;
    while(g2<extra){
        int k=recv(fd,b+g2,extra-g2,0);
        if(k<=0) return -1;
        g2+=k;
    }
    return 0;
}

int connect(int fd,const struct sockaddr*addr,socklen_t len){
    if(!real_connect) real_connect=dlsym(RTLD_NEXT,"connect");
    int p=proxy_port();
    if(!p||busy||!addr) return real_connect(fd,addr,len);
    if(addr->sa_family!=AF_INET&&addr->sa_family!=AF_INET6)
        return real_connect(fd,addr,len);
    if(is_loopback(addr)) return real_connect(fd,addr,len);
    struct sockaddr_in px;
    memset(&px,0,sizeof(px));
    px.sin_family=AF_INET; px.sin_port=htons((unsigned short)p);
    px.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    busy=1;
    int r=real_connect(fd,(struct sockaddr*)&px,sizeof(px));
    if(r==0) r=socks5_hs_addr(fd,addr);
    busy=0;
    return r;
}

/*
 * getaddrinfo hook: when ANONCHAIN_RESOLVE=1, force resolution through
 * the local DNS bridge at 127.0.0.1:5353 (which forwards to DoH).
 * This closes the DNS leak for tools that use getaddrinfo().
 */
int getaddrinfo(const char*node,const char*service,
                const struct addrinfo*hints,struct addrinfo**res){
    if(!real_getaddrinfo) real_getaddrinfo=dlsym(RTLD_NEXT,"getaddrinfo");
    const char*use=getenv("ANONCHAIN_RESOLVE");
    if(!use||strcmp(use,"1")!=0||!node)
        return real_getaddrinfo(node,service,hints,res);

    /* If node is already an IP literal, bypass. */
    struct in_addr a4; struct in6_addr a6;
    if(inet_pton(AF_INET,node,&a4)==1||inet_pton(AF_INET6,node,&a6)==1)
        return real_getaddrinfo(node,service,hints,res);

    /* Query our local DNS bridge directly */
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    if(fd<0) return real_getaddrinfo(node,service,hints,res);
    struct sockaddr_in dns;
    memset(&dns,0,sizeof(dns));
    dns.sin_family=AF_INET; dns.sin_port=htons(5353);
    dns.sin_addr.s_addr=htonl(INADDR_LOOPBACK);

    unsigned char q[512]; int qn=0;
    q[0]=0xAB; q[1]=0xCD; q[2]=0x01; q[3]=0x00;
    q[4]=0x00; q[5]=0x01; q[6]=0; q[7]=0; q[8]=0; q[9]=0;
    q[10]=0; q[11]=0; qn=12;
    const char*p=node;
    while(*p){
        const char*dot=strchr(p,'.');
        size_t l=dot?(size_t)(dot-p):strlen(p);
        if(l==0||l>63){close(fd);return real_getaddrinfo(node,service,hints,res);}
        q[qn++]=(unsigned char)l;
        memcpy(q+qn,p,l); qn+=l;
        p=dot?dot+1:p+l;
        if(!dot) break;
    }
    q[qn++]=0;
    q[qn++]=0x00; q[qn++]=0x01; /* A */
    q[qn++]=0x00; q[qn++]=0x01; /* IN */

    if(sendto(fd,q,qn,0,(struct sockaddr*)&dns,sizeof(dns))<0){
        close(fd); return real_getaddrinfo(node,service,hints,res);
    }
    struct timeval tv={2,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    unsigned char rb[1024];
    ssize_t rn=recv(fd,rb,sizeof(rb),0);
    close(fd);
    if(rn<12) return real_getaddrinfo(node,service,hints,res);

    /* very small answer parser: find first A record rdata */
    int ancount=rb[6]<<8|rb[7];
    if(ancount<1) return real_getaddrinfo(node,service,hints,res);
    int i=12;
    while(i<(int)rn && rb[i]!=0) i+=1+rb[i];
    i+=5; /* null + type + class */
    char ipstr[64]={0};
    for(int k=0;k<ancount&&i+10<(int)rn;k++){
        if(rb[i]&0xC0){i+=2;} else {while(i<(int)rn&&rb[i]) i+=1+rb[i]; i++; }
        unsigned short t=(rb[i]<<8)|rb[i+1]; i+=8;
        unsigned short rl=(rb[i]<<8)|rb[i+1]; i+=2;
        if(t==1&&rl==4){
            snprintf(ipstr,sizeof(ipstr),"%u.%u.%u.%u",
                     rb[i],rb[i+1],rb[i+2],rb[i+3]);
            break;
        }
        i+=rl;
    }
    if(!ipstr[0]) return real_getaddrinfo(node,service,hints,res);
    return real_getaddrinfo(ipstr,service,hints,res);
}
