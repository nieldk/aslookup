#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <curl/curl.h>
#include "cJSON.h"

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

char *get_asn_from_ip(const char *ip) {
    static char asn[32] = {0};
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    char url[256];
    snprintf(url, sizeof(url), "https://api.hackertarget.com/aslookup/?q=%s", ip);
    struct MemoryStruct chunk = {malloc(1), 0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "aslookup-c-client/1.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK && chunk.size > 0 && strstr(chunk.memory, "AS")) {
        sscanf(chunk.memory, "%31s", asn);
    } else {
        fprintf(stderr, "Error resolving ASN from IP %s (Code %d): %s\n", ip, res, curl_easy_strerror(res));
        asn[0] = '\0';
    }
    curl_easy_cleanup(curl);
    free(chunk.memory);
    return asn[0] ? asn : NULL;
}

void fetch_bgpview_info(const char *asn, FILE *output) {
    if (!asn || strncmp(asn, "AS", 2) != 0) {
        fprintf(stderr, "Skipping BGPView ASN lookup: invalid ASN (%s)\n", asn ? asn : "NULL");
        return;
    }
    CURL *curl = curl_easy_init();
    if (!curl) return;
    char url[256];
    snprintf(url, sizeof(url), "https://api.bgpview.io/asn/%d", atoi(asn + 2));
    struct MemoryStruct chunk = {malloc(1), 0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "asnlookup-c-client/1.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Error fetching BGPView info (Code %d): %s\n", res, curl_easy_strerror(res));
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
    fprintf(output, "\nBGPView ASN Info:\n");
    cJSON *asn_num = cJSON_GetObjectItem(data, "asn");
    if (asn_num) fprintf(output, "ASN Number: %d\n", asn_num->valueint);
    cJSON *name = cJSON_GetObjectItem(data, "name");
    if (name && name->valuestring) fprintf(output, "Name: %s\n", name->valuestring);
    cJSON *desc = cJSON_GetObjectItem(data, "description_short");
    if (desc && desc->valuestring) fprintf(output, "Description: %s\n", desc->valuestring);
    cJSON *country = cJSON_GetObjectItem(data, "country_code");
    if (country && country->valuestring) fprintf(output, "Country: %s\n", country->valuestring);

    // Contact info
    cJSON *emails = cJSON_GetObjectItem(data, "email_contacts");
    if (emails) {
        fprintf(output, "\nEmail Contacts:\n");
        for (int i = 0; i < cJSON_GetArraySize(emails); i++) {
            cJSON *email = cJSON_GetArrayItem(emails, i);
            if (email && email->valuestring) fprintf(output, " - %s\n", email->valuestring);
        }
    }

    cJSON *abuse = cJSON_GetObjectItem(data, "abuse_contacts");
    if (abuse) {
        fprintf(output, "\nAbuse Contacts:\n");
        for (int i = 0; i < cJSON_GetArraySize(abuse); i++) {
            cJSON *contact = cJSON_GetArrayItem(abuse, i);
            if (contact && contact->valuestring) fprintf(output, " - %s\n", contact->valuestring);
        }
    }

    cJSON *address = cJSON_GetObjectItem(data, "owner_address");
    if (address) {
        fprintf(output, "\nOwner Address:\n");
        for (int i = 0; i < cJSON_GetArraySize(address); i++) {
            cJSON *addr_line = cJSON_GetArrayItem(address, i);
            if (addr_line && addr_line->valuestring) fprintf(output, " %s\n", addr_line->valuestring);
        }
    }

    cJSON_Delete(root);
    curl_easy_cleanup(curl);
    free(chunk.memory);
}

void fetch_all_prefixes_from_asn(const char *asn, FILE *output) {
    if (!asn || strncmp(asn, "AS", 2) != 0) {
        fprintf(stderr, "Skipping prefix fetch: invalid ASN (%s)\n", asn ? asn : "NULL");
        return;
    }
    CURL *curl = curl_easy_init();
    if (!curl) return;
    char url[256];
    snprintf(url, sizeof(url), "https://api.bgpview.io/asn/%d/prefixes", atoi(asn + 2));
    struct MemoryStruct chunk = {malloc(1), 0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "asnlookup-c-client/1.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Error fetching ASN prefixes (Code %d): %s\n", res, curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return;
    }
    cJSON *root = cJSON_Parse(chunk.memory);
    if (!root) {
        fprintf(stderr, "Failed to parse JSON for ASN prefixes.\n");
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return;
    }
    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (!data) {
        fprintf(stderr, "No data in ASN prefix JSON.\n");
        cJSON_Delete(root);
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return;
    }
    fprintf(output, "\nAll IP Prefixes for ASN %s:\n", asn);
    cJSON *ipv4_prefixes = cJSON_GetObjectItem(data, "ipv4_prefixes");
    if (ipv4_prefixes) {
        fprintf(output, "\nIPv4 Prefixes:\n");
        for (int i = 0; i < cJSON_GetArraySize(ipv4_prefixes); i++) {
            cJSON *prefix = cJSON_GetArrayItem(ipv4_prefixes, i);
            cJSON *prefix_str = cJSON_GetObjectItem(prefix, "prefix");
            if (prefix_str && prefix_str->valuestring) {
                fprintf(output, " - %s\n", prefix_str->valuestring);
            }
        }
    }
    cJSON *ipv6_prefixes = cJSON_GetObjectItem(data, "ipv6_prefixes");
    if (ipv6_prefixes) {
        fprintf(output, "\nIPv6 Prefixes:\n");
        for (int i = 0; i < cJSON_GetArraySize(ipv6_prefixes); i++) {
            cJSON *prefix = cJSON_GetArrayItem(ipv6_prefixes, i);
            cJSON *prefix_str = cJSON_GetObjectItem(prefix, "prefix");
            if (prefix_str && prefix_str->valuestring) {
                fprintf(output, " - %s\n", prefix_str->valuestring);
            }
        }
    }
    cJSON_Delete(root);
    curl_easy_cleanup(curl);
    free(chunk.memory);
}

int fetch_bgpview_info_ip(const char *ip, FILE *output) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;
    char url[256];
    snprintf(url, sizeof(url), "https://api.bgpview.io/ip/%s", ip);
    struct MemoryStruct chunk = {malloc(1), 0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "asnlookup-c-client/1.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Error fetching BGPView IP info (Code %d): %s\n", res, curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return 0;
    }
    cJSON *root = cJSON_Parse(chunk.memory);
    if (!root) {
        fprintf(stderr, "Failed to parse JSON.\n");
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return 0;
    }
    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (!data) {
        fprintf(stderr, "No data in JSON.\n");
        cJSON_Delete(root);
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return 0;
    }
    fprintf(output, "\nBGPView IP Info for %s:\n", ip);
    int asn_value = 0;
    cJSON *prefixes = cJSON_GetObjectItem(data, "prefixes");
    if (prefixes) {
        for (int i = 0; i < cJSON_GetArraySize(prefixes); i++) {
            cJSON *prefix = cJSON_GetArrayItem(prefixes, i);
            cJSON *asn = cJSON_GetObjectItem(prefix, "asn");
            if (asn) {
                asn_value = cJSON_GetObjectItem(asn, "asn")->valueint;
                fprintf(output, " ASN: %d\n", asn_value);
                fprintf(output, " Name: %s\n", cJSON_GetObjectItem(asn, "name")->valuestring);
            }
            cJSON *prefix_str = cJSON_GetObjectItem(prefix, "prefix");
            if (prefix_str && prefix_str->valuestring) {
                fprintf(output, " Prefix: %s\n", prefix_str->valuestring);
            }
        }
    }
    cJSON_Delete(root);
    curl_easy_cleanup(curl);
    free(chunk.memory);
    return asn_value;
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

void print_help(const char *progname, FILE *output) {
    fprintf(output, "Usage: %s <options>\n", progname);
    fprintf(output, "Options:\n");
    fprintf(output, " -i <IP[,IP,...]> Specify one or more IP addresses (comma-separated)\n");
    fprintf(output, " -d <domain[,domain,...]> Specify one or more domain names (comma-separated)\n");
    fprintf(output, " -f <file> Save output to a formatted text file\n");
    fprintf(output, " --help Show this help message\n");
}

int main(int argc, char *argv[]) {
    init_winsock();

    char ips[1024] = {0};
    char domains[1024] = {0};
    char filename[256] = {0};
    FILE *output = stdout;

    for (int i = 1; i < argc; i++) {
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
            if (!asn || strncmp(asn, "AS", 2) != 0) {
                fprintf(stderr, "ASN lookup failed for IP %s. Trying BGPView fallback...\n", token);
                int asn_num = fetch_bgpview_info_ip(token, output);
                if (asn_num > 0) {
                    char asn_str[16];
                    snprintf(asn_str, sizeof(asn_str), "AS%d", asn_num);
                    fetch_bgpview_info(asn_str, output);
                    fetch_all_prefixes_from_asn(asn_str, output);
                }
            } else {
                fprintf(output, "Resolved ASN for IP %s: %s\n", token, asn);
                fetch_bgpview_info(asn, output);
                fetch_all_prefixes_from_asn(asn, output);
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
                if (!asn || strncmp(asn, "AS", 2) != 0) {
                    fprintf(stderr, "ASN lookup failed for domain %s (IP %s). Trying BGPView fallback...\n", token, resolved_ip);
                    int asn_num = fetch_bgpview_info_ip(resolved_ip, output);
                    if (asn_num > 0) {
                        char asn_str[16];
                        snprintf(asn_str, sizeof(asn_str), "AS%d", asn_num);
                        fetch_bgpview_info(asn_str, output);
                        fetch_all_prefixes_from_asn(asn_str, output);
                    }
                } else {
                    fprintf(output, "Resolved ASN for domain %s (IP %s): %s\n", token, resolved_ip, asn);
                    fetch_bgpview_info(asn, output);
                    fetch_all_prefixes_from_asn(asn, output);
                }
            }
            token = strtok(NULL, ",");
        }
    }

    if (output != stdout) fclose(output);
    cleanup_winsock();
    return 0;
}
