// aslookup_win.c
#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

// --- Windows-specific Headers ---
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>

// --- End Windows-specific Headers ---

#include "cjson/cJSON.h" // Local cJSON header

// Define colors, though they might not work perfectly in all Windows consoles
#define GREEN "\033[32m"
#define CYAN "\033[36m"
#define RED "\033[31m"
#define YELLOW "\033[33m"
#define WHITE "\033[37m"
#define RESET "\033[0m"

#ifndef VERSION
#define VERSION "unknown"
#endif

#include <stdio.h>

void print_installed_version() {
    printf("aslookup version: %s\n", VERSION);
}

// Memory struct and callback remain the same (curl compatible)
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

// Function to print latest GitHub version (no change needed)
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

// --- Windows-specific DNS Lookup for ASN ---
char *get_asn_from_ip(const char *ip) {
    static char asn[16] = {0};
    int a, b, c, d;
    if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return NULL;
    char query[256];
    snprintf(query, sizeof(query), "%d.%d.%d.%d.origin.asn.cymru.com", d, c, b, a);
    
    PDNS_RECORD pDnsRecord;
    // DNS_TYPE_TXT fix: ensure _WIN32_WINNT is defined high enough (e.g., 0x0600)
    DNS_STATUS status = DnsQuery_A(query, DNS_TYPE_TXT, DNS_QUERY_STANDARD, NULL, &pDnsRecord, NULL);
    
    if (status != ERROR_SUCCESS) {
        return NULL;
    }

    for (PDNS_RECORD pRec = pDnsRecord; pRec != NULL; pRec = pRec->pNext) {
        if (pRec->wType == DNS_TYPE_TXT) {
            // FIX: Use pStringArray instead of cStringArray for MinGW
            if (pRec->Data.Txt.pStringArray[0]) {
                sscanf(pRec->Data.Txt.pStringArray[0], "%15s", asn);
                DnsFree(pDnsRecord, DnsFreeRecordList);
                return asn;
            }
        }
    }

    DnsFree(pDnsRecord, DnsFreeRecordList);
    return NULL;
}

// The rest of the API fetching functions (curl and cJSON based) remain the same
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
        fprintf(output, CYAN "\nIP Ranges:\n" WHITE "%s\n" RESET, chunk.memory);
    } else {
        fprintf(stderr, RED "Error fetching IP ranges: %s\n" RESET, curl_easy_strerror(res));
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
        fprintf(stderr, RED "Error fetching BGPView info: %s\n" RESET, curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return;
    }
    cJSON *root = cJSON_Parse(chunk.memory);
    if (!root) {
        fprintf(stderr, RED "Failed to parse JSON.\n" RESET);
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return;
    }
    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (!data) {
        fprintf(stderr, RED "No data in JSON.\n" RESET);
        cJSON_Delete(root);
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return;
    }
    fprintf(output, GREEN "\nASN Number: %d\n", cJSON_GetObjectItem(data, "asn")->valueint);
    fprintf(output, GREEN "Name: %s\n", cJSON_GetObjectItem(data, "name")->valuestring);
    fprintf(output, GREEN "Description: %s\n", cJSON_GetObjectItem(data, "description_short")->valuestring);
    fprintf(output, GREEN "Country: %s\n", cJSON_GetObjectItem(data, "country_code")->valuestring);
    fprintf(output, GREEN "Website: %s\n", cJSON_GetObjectItem(data, "website")->valuestring);
    cJSON *emails = cJSON_GetObjectItem(data, "email_contacts");
    if (emails) {
        fprintf(output, CYAN "\nEmail Contacts:\n");
        for (int i = 0; i < cJSON_GetArraySize(emails); i++) {
            fprintf(output, WHITE " - %s\n", cJSON_GetArrayItem(emails, i)->valuestring);
        }
    }
    cJSON *abuse = cJSON_GetObjectItem(data, "abuse_contacts");
    if (abuse) {
        fprintf(output, RED "\nAbuse Contacts:\n");
        for (int i = 0; i < cJSON_GetArraySize(abuse); i++) {
            fprintf(output, WHITE " - %s\n", cJSON_GetArrayItem(abuse, i)->valuestring);
        }
    }
    cJSON *address = cJSON_GetObjectItem(data, "owner_address");
    if (address) {
        fprintf(output, YELLOW "\nOwner Address:\n");
        for (int i = 0; i < cJSON_GetArraySize(address); i++) {
            fprintf(output, WHITE " %s\n", cJSON_GetArrayItem(address, i)->valuestring);
        }
    }
    fprintf(output, GREEN "Traffic Ratio: %s\n", cJSON_GetObjectItem(data, "traffic_ratio")->valuestring);
    fprintf(output, GREEN "Updated: %s\n", cJSON_GetObjectItem(data, "date_updated")->valuestring);
    cJSON_Delete(root);
    curl_easy_cleanup(curl);
    free(chunk.memory);
}

void print_help(const char *progname, FILE *output) {
    fprintf(output, CYAN "Usage: %s <options>\n", progname);
    fprintf(output, CYAN "Options:\n");
    fprintf(output, WHITE " -i <IP[,IP,...]> Specify one or more IP addresses (comma-separated)\n");
    fprintf(output, WHITE " -d <domain[,domain,...]> Specify one or more domain names (comma-separated)\n");
    fprintf(output, WHITE " -f <file> Save output to a formatted text file\n");
    fprintf(output, WHITE " --help Show this help message\n");
    fprintf(output, WHITE " --version Show installed version\n");
    fprintf(output, WHITE " --ghversion Show latest GitHub release version\n");
}

// --- Windows-specific Domain Resolution ---
char *resolve_domain_to_ip(const char *domain) {
    struct addrinfo hints, *res = NULL;
    static char ip[INET6_ADDRSTRLEN] = {0};
    
    // Windows Sockets (WSA) initialization is not required here for getaddrinfo
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      // IPv4 only for simplicity and get_asn_from_ip
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(domain, NULL, &hints, &res) != 0) {
        // fprintf(stderr, "getaddrinfo failed: %d\n", WSAGetLastError());
        return NULL;
    }
    
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    // Use the MinGW-w64 compatible inet_ntop
    if (inet_ntop(AF_INET, &(ipv4->sin_addr), ip, sizeof(ip)) == NULL) {
        freeaddrinfo(res);
        return NULL;
    }
    
    freeaddrinfo(res);
    return ip;
}

// --- Main function with Manual Argument Parsing (replacing getopt) ---
int main(int argc, char *argv[]) {
    char ips[1024] = {0};
    char domains[1024] = {0};
    char filename[256] = {0};
    FILE *output = stdout;
    
    // Manual argument parsing loop
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            print_installed_version();
            return 0;
        } else if (strcmp(argv[i], "--ghversion") == 0) {
            print_latest_github_version();
            return 0;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_help(argv[0], stdout);
            return 0;
        } else if (strcmp(argv[i], "-i") == 0 && (i + 1) < argc) {
            strncpy(ips, argv[i+1], sizeof(ips) - 1);
            i++; // Skip the next argument (the value)
        } else if (strcmp(argv[i], "-d") == 0 && (i + 1) < argc) {
            strncpy(domains, argv[i+1], sizeof(domains) - 1);
            i++; // Skip the next argument (the value)
        } else if (strcmp(argv[i], "-f") == 0 && (i + 1) < argc) {
            strncpy(filename, argv[i+1], sizeof(filename) - 1);
            i++; // Skip the next argument (the value)
        }
    }

    // Since we removed getopt, we need to initialize Winsock manually for safety.
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, RED "WSAStartup failed.\n" RESET);
        return 1;
    }

    if (strlen(filename) > 0) {
        output = fopen(filename, "w");
        if (!output) {
            fprintf(stderr, RED "Failed to open file for writing.\n" RESET);
            WSACleanup();
            return 1;
        }
    }

    if (strlen(ips) == 0 && strlen(domains) == 0) {
        print_help(argv[0], output);
        if (output != stdout) fclose(output);
        WSACleanup();
        return 1;
    }

    char *token;
    char *ips_copy = NULL; // Use a copy because strtok modifies the string
    
    if (strlen(ips) > 0) {
        ips_copy = strdup(ips);
        token = strtok(ips_copy, ",");
        while (token != NULL) {
            char *asn = get_asn_from_ip(token);
            if (!asn) {
                fprintf(stderr, RED "Failed to resolve ASN from IP: %s\n" RESET, token);
            } else {
                fprintf(output, GREEN "Resolved ASN for IP %s: %s\n", token, asn);
                fetch_ip_ranges(asn, output);
                fetch_bgpview_info(asn, output);
            }
            token = strtok(NULL, ",");
        }
        free(ips_copy);
    }

    char *domains_copy = NULL;
    if (strlen(domains) > 0) {
        domains_copy = strdup(domains);
        token = strtok(domains_copy, ",");
        while (token != NULL) {
            char *resolved_ip = resolve_domain_to_ip(token);
            if (!resolved_ip) {
                fprintf(stderr, RED "Failed to resolve domain to IP: %s\n" RESET, token);
            } else {
                char *asn = get_asn_from_ip(resolved_ip);
                if (!asn) {
                    fprintf(stderr, RED "Failed to resolve ASN from domain %s (IP %s)\n" RESET, token, resolved_ip);
                } else {
                    fprintf(output, GREEN "Resolved ASN for domain %s (IP %s): %s\n", token, resolved_ip, asn);
                    fetch_ip_ranges(asn, output);
                    fetch_bgpview_info(asn, output);
                }
            }
            token = strtok(NULL, ",");
        }
        free(domains_copy);
    }

    if (output != stdout) fclose(output);
    WSACleanup(); // Clean up Winsock
    return 0;
}