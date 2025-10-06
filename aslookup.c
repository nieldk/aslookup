#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <curl/curl.h>

#define DNS_PORT 53
#define DNS_SERVER "8.8.8.8"
#define BUF_SIZE 512

struct DNS_HEADER {
    unsigned short id;
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
    unsigned char rcode :4;
    unsigned char z :3;
    unsigned char ra :1;
    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
};

struct QUESTION {
    unsigned short qtype;
    unsigned short qclass;
};

void reverse_ip(char *ip, char *out) {
    int a, b, c, d;
    sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d);
    sprintf(out, "%d.%d.%d.%d.origin.asn.cymru.com", d, c, b, a);
}

void format_dns_name(unsigned char *dns, const char *host) {
    int lock = 0 , i;
    strcat((char*)host, ".");
    for(i = 0 ; i < strlen(host) ; i++) {
        if(host[i]=='.') {
            *dns++ = i-lock;
            for(;lock<i;lock++) {
                *dns++=host[lock];
            }
            lock++;
        }
    }
    *dns++='\0';
}

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    fwrite(contents, 1, total, stdout);
    return total;
}

void query_hackertarget(const char *asn) {
    CURL *curl = curl_easy_init();
    if (curl) {
        char url[256];
        snprintf(url, sizeof(url), "https://api.hackertarget.com/aslookup/?q=AS%s", asn);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "asnlookup-c-client/1.0");

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
            fprintf(stderr, "libcurl error: %s\n", curl_easy_strerror(res));

        curl_easy_cleanup(curl);
    } else {
        fprintf(stderr, "Failed to initialize libcurl\n");
    }
    printf("\n");
}

int main() {
    char ip[100], reversed[100];
    unsigned char buf[BUF_SIZE], *qname, *reader;
    struct sockaddr_in dest;
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

    printf("Enter IP address: ");
    scanf("%99s", ip);

    reverse_ip(ip, reversed);

    int sock = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    dest.sin_addr.s_addr = inet_addr(DNS_SERVER);

    dns = (struct DNS_HEADER *)&buf;
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; dns->opcode = 0; dns->aa = 0; dns->tc = 0; dns->rd = 1;
    dns->ra = 0; dns->z = 0; dns->rcode = 0;
    dns->q_count = htons(1);
    dns->ans_count = 0; dns->auth_count = 0; dns->add_count = 0;

    qname = (unsigned char*)&buf[sizeof(struct DNS_HEADER)];
    format_dns_name(qname, reversed);

    qinfo = (struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1];
    qinfo->qtype = htons(16); // TXT
    qinfo->qclass = htons(1); // IN

    int packet_size = sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION);
    sendto(sock, buf, packet_size, 0, (struct sockaddr*)&dest, sizeof(dest));

    int i = sizeof(dest);
    recvfrom(sock, buf, BUF_SIZE, 0, (struct sockaddr*)&dest, (socklen_t*)&i);

    reader = &buf[packet_size + 12]; // Skip header and question

    // Correct TXT record parsing
    char txt[256] = {0};
    int offset = 0;
    int total_len = 0;
    while (offset < BUF_SIZE && reader[offset] != 0) {
        int chunk_len = reader[offset];
        if (chunk_len + offset + 1 >= BUF_SIZE) break;
        strncat(txt, (char*)&reader[offset + 1], chunk_len);
        total_len += chunk_len;
        offset += chunk_len + 1;
    }
    txt[total_len] = '\0';

    printf("\nASN Info: %s\n", txt);

    char asn[20];
    char *token = strtok(txt, " |");
    if (token != NULL) {
        strncpy(asn, token, sizeof(asn));
        asn[sizeof(asn) - 1] = '\0';
    }

    printf("\nQuerying HackerTarget for ASN %s...\n\n", asn);
    query_hackertarget(asn);

    close(sock);
    return 0;
}
