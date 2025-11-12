#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <curl/curl.h>
#include "cJSON.h" // Make sure cJSON.h and cJSON.c are included in your project

#pragma comment(lib, "ws2_32.lib")

struct MemoryStruct {
    char *memory;
    size_t size;
};

size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + total + 1);
    if (!ptr) return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, total);
    mem->size += total;
    mem->memory[mem->size] = 0;
    return total;
}

void init_winsock() {
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        exit(1);
    }
}

void cleanup_winsock() {
    WSACleanup();
}

void print_latest_github_version() {
    CURL *curl = curl_easy_init();
    if (!curl) {
        printf("curl init failed\n");
        return;
    }
    struct MemoryStruct chunk = {malloc(1), 0};
    curl_easy_setopt(curl, CURLOPT_URL, "https://api.github.com/repos/nieldk/aslookup/releases/latest");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "aslookup-c-client/1.0");
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        cJSON *root = cJSON_Parse(chunk.memory);
        if (root) {
            cJSON *tag = cJSON_GetObjectItem(root, "tag_name");
            if (tag && tag->valuestring) {
                printf("Latest GitHub release: %s\n", tag->valuestring);
            } else {
                printf("Could not find version info in GitHub release.\n");
            }
            cJSON_Delete(root);
        } else {
            printf("Failed to parse JSON from GitHub.\n");
        }
    } else {
        printf("Failed to fetch release info from GitHub: %s\n", curl_easy_strerror(res));
    }
    curl_easy_cleanup(curl);
    free(chunk.memory);
}

// Uses hackertarget.com API for ASN lookup
char *get_asn_from_ip(const char *ip) {
    static char asn[16] = {0};
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    char url[256];
    snprintf(url, sizeof(url), "https://api.hackertarget.com/aslookup/?q=%s", ip);
    struct MemoryStruct chunk = {malloc(1), 0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "aslookup-c-client/1.0");
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK && chunk.size > 0) {
        // The response is plain text, first line is ASN
        sscanf(chunk.memory, "%15s", asn);
    } else {
        asn[0] = '\0';
    }
    curl_easy_cleanup(curl);
    free(chunk.memory);
    return asn[0] ? asn : NULL;
}

void fetch_ip_ranges(const char *asn, FILE *output) {
    CURL *curl = curl_easy_init();
    if (!curl) return;
    char url[256];
    snprintf(url, sizeof(url), "https://api.hackertarget.com/aslookup/?q=AS%s", asn);
    struct MemoryStruct chunk = {malloc(1), 0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "asnlookup-c-client/1.0");
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        fprintf(output, "\nIP Ranges:\n%s\n", chunk.memory);
    } else {
        fprintf(stderr, "Error fetching IP ranges: %s\n", curl_easy_strerror(res));
    }
    curl_easy_cleanup(curl);
    free(chunk.memory);
}

void fetch_bgpview_info(const char *asn, FILE *output) {
    CURL *curl = curl_easy_init();
    if (!curl) return;
    char url[256];
    snprintf(url, sizeof(url), "https://api.bgpview.io/asn/%s", asn);
    struct MemoryStruct chunk = {malloc(1), 0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "asnlookup-c-client/1.0");
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Error fetching BGPView info: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return;
    }
    cJSON *root = cJSON_Parse(chunk.memory);
    if (!root) {
        fprintf(stderr, "Failed to parse JSON.\n");
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return;
    }
    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (!data) {
        fprintf(stderr, "No data in JSON.\n");
        cJSON_Delete(root);
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return;
    }
    fprintf(output, "\nASN Number: %d\n", cJSON_GetObjectItem(data, "asn")->valueint);
    fprintf(output, "Name: %s\n", cJSON_GetObjectItem(data, "name")->valuestring);
    fprintf(output, "Description: %s\n", cJSON_GetObjectItem(data, "description_short")->valuestring);
    fprintf(output, "Country: %s\n", cJSON_GetObjectItem(data, "country_code")->valuestring);
    fprintf(output, "Website: %s\n", cJSON_GetObjectItem(data, "website")->valuestring);
    cJSON *emails = cJSON_GetObjectItem(data, "email_contacts");
    if (emails) {
        fprintf(output, "\nEmail Contacts:\n");
        for (int i = 0; i < cJSON_GetArraySize(emails); i++) {
            fprintf(output, " - %s\n", cJSON_GetArrayItem(emails, i)->valuestring);
        }
    }
    cJSON *abuse = cJSON_GetObjectItem(data, "abuse_contacts");
    if (abuse) {
        fprintf(output, "\nAbuse Contacts:\n");
        for (int i = 0; i < cJSON_GetArraySize(abuse); i++) {
            fprintf(output, " - %s\n", cJSON_GetArrayItem(abuse, i)->valuestring);
        }
    }
    cJSON *address = cJSON_GetObjectItem(data, "owner_address");
    if (address) {
        fprintf(output, "\nOwner Address:\n");
        for (int i = 0; i < cJSON_GetArraySize(address); i++) {
            fprintf(output, " %s\n", cJSON_GetArrayItem(address, i)->valuestring);
        }
    }
    fprintf(output, "Traffic Ratio: %s\n", cJSON_GetObjectItem(data, "traffic_ratio")->valuestring);
    fprintf(output, "Updated: %s\n", cJSON_GetObjectItem(data, "date_updated")->valuestring);
    cJSON_Delete(root);
    curl_easy_cleanup(curl);
    free(chunk.memory);
}

void print_help(const char *progname, FILE *output) {
    fprintf(output, "Usage: %s <options>\n", progname);
    fprintf(output, "Options:\n");
    fprintf(output, " -i <IP[,IP,...]> Specify one or more IP addresses (comma-separated)\n");
    fprintf(output, " -d <domain[,domain,...]> Specify one or more domain names (comma-separated)\n");
    fprintf(output, " -f <file> Save output to a formatted text file\n");
    fprintf(output, " --help Show this help message\n");
    fprintf(output, " --version Show latest GitHub release version\n");
}

char *resolve_domain_to_ip(const char *domain) {
    struct addrinfo hints, *res;
    static char ip[INET6_ADDRSTRLEN] = {0};
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(domain, NULL, &hints, &res) != 0) {
        return NULL;
    }
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ip, sizeof(ip));
    freeaddrinfo(res);
    return ip;
}

// Simple argument parser for Windows (no getopt)
int main(int argc, char *argv[]) {
    init_winsock();

    char ips[1024] = {0};
    char domains[1024] = {0};
    char filename[256] = {0};
    FILE *output = stdout;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            print_latest_github_version();
            cleanup_winsock();
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0) {
            print_help(argv[0], stdout);
            cleanup_winsock();
            return 0;
        }
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            strncpy(ips, argv[i + 1], sizeof(ips) - 1);
            i++;
        }
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            strncpy(domains, argv[i + 1], sizeof(domains) - 1);
            i++;
        }
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            strncpy(filename, argv[i + 1], sizeof(filename) - 1);
            i++;
        }
    }

    if (strlen(filename) > 0) {
        output = fopen(filename, "w");
        if (!output) {
            fprintf(stderr, "Failed to open file for writing.\n");
            cleanup_winsock();
            return 1;
        }
    }

    if (strlen(ips) == 0 && strlen(domains) == 0) {
        print_help(argv[0], output);
        if (output != stdout) fclose(output);
        cleanup_winsock();
        return 1;
    }

    char *token;
    if (strlen(ips) > 0) {
        token = strtok(ips, ",");
        while (token != NULL) {
            char *asn = get_asn_from_ip(token);
            if (!asn) {
                fprintf(stderr, "Failed to resolve ASN from IP: %s\n", token);
            } else {
                fprintf(output, "Resolved ASN for IP %s: %s\n", token, asn);
                fetch_ip_ranges(asn, output);
                fetch_bgpview_info(asn, output);
            }
            token = strtok(NULL, ",");
        }
    }
    if (strlen(domains) > 0) {
        token = strtok(domains, ",");
        while (token != NULL) {
            char *resolved_ip = resolve_domain_to_ip(token);
            if (!resolved_ip) {
                fprintf(stderr, "Failed to resolve domain to IP: %s\n", token);
            } else {
                char *asn = get_asn_from_ip(resolved_ip);
                if (!asn) {
                    fprintf(stderr, "Failed to resolve ASN from domain %s (IP %s)\n", token, resolved_ip);
                } else {
                    fprintf(output, "Resolved ASN for domain %s (IP %s): %s\n", token, resolved_ip, asn);
                    fetch_ip_ranges(asn, output);
                    fetch_bgpview_info(asn, output);
                }
            }
            token = strtok(NULL, ",");
        }
    }
    if (output != stdout) fclose(output);
    cleanup_winsock();
    return 0;
}
