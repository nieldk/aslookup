#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

// --- Windows-Specific Headers ---
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h> // For DnsQuery

// Undefining conflicting types that might be defined by resolv.h if it was included
#ifdef __GNUC__
#undef ns_msg
#undef ns_rr
#endif

// --- Unix-like functions replaced with standard or equivalent for Windows ---
#define strtok_r(s, delim, saveptr) strtok(s, delim)
#define getaddrinfo(domain, service, hints, res) GetAddrInfo(domain, service, hints, res)
#define freeaddrinfo(res) FreeAddrInfo(res)

// --- Color definitions for Windows Console API ---
#define COLOR_GREEN FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define COLOR_CYAN FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define COLOR_RED FOREGROUND_RED | FOREGROUND_INTENSITY
#define COLOR_YELLOW FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define COLOR_WHITE FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY
#define COLOR_RESET 0 // This will be handled by restoring attributes

#ifndef VERSION
#define VERSION "unknown"
#endif

// Global variable for Windows Console handle
HANDLE hConsole = NULL;
WORD saved_attributes = 0;

void set_console_color(WORD color) {
    if (hConsole) {
        SetConsoleTextAttribute(hConsole, color);
    }
}

void reset_console_color() {
    if (hConsole && saved_attributes != 0) {
        SetConsoleTextAttribute(hConsole, saved_attributes);
    }
}

void print_installed_version() {
    printf("aslookup version: %s\n", VERSION);
}

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
    
    // GitHub API requires a User-Agent header
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: aslookup-c-client/1.0");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers); // Clean up the headers list
    
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

// --- Windows-specific function to replace get_asn_from_ip (using DnsQuery) ---
char *get_asn_from_ip(const char *ip) {
    static char asn[16] = {0};
    int a, b, c, d;
    // Perform standard IP validation
    if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return NULL;

    // Construct the reverse DNS query: d.c.b.a.origin.asn.cymru.com
    char query[256];
    snprintf(query, sizeof(query), "%d.%d.%d.%d.origin.asn.cymru.com", d, c, b, a);

    PDNS_RECORD pDnsRecord = NULL;
    char txt[256] = {0};

    // Use the native Windows DNS Client API to query for a TXT record
    DWORD dns_status = DnsQuery_A(
        query,                   // Query name
        DNS_TYPE_TEXT,           // Query type for TXT records
        DNS_QUERY_STANDARD,      // Standard query flags
        NULL,                    // No specific server list
        &pDnsRecord,             // Pointer to the response record list
        NULL                     // Reserved
    );

    if (dns_status == ERROR_SUCCESS) {
        for (PDNS_RECORD p = pDnsRecord; p != NULL; p = p->pNext) {
            if (p->wType == DNS_TYPE_TEXT) {
                // The TXT record often contains multiple strings (pTxtRecord->StringArray)
                // but the cymru response is a single field.
                
                // FIX: MinGW structure member names corrected to dwStringCount and pStringArray.
                if (p->Data.Txt.dwStringCount > 0 && p->Data.Txt.pStringArray[0]) {
                    strncpy(txt, p->Data.Txt.pStringArray[0], sizeof(txt) - 1);
                }

                // The TXT record is typically in the format: "ASN | IP prefix | CC | Registry | Allocated"
                // We only want the first part (the ASN).
                // The sscanf parsing logic from the original code:
                sscanf(txt, "%15s", asn);
                DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
                return asn;
            }
        }
    }} // FIX: Added two missing closing braces to close the for loop and the if (dns_status) block

    if (pDnsRecord) {
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    }
    return NULL;
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
        set_console_color(COLOR_CYAN);
        fprintf(output, "\nIP Ranges:\n");
        set_console_color(COLOR_WHITE);
        fprintf(output, "%s\n", chunk.memory);
        reset_console_color();
    } else {
        set_console_color(COLOR_RED);
        fprintf(stderr, "Error fetching IP ranges: %s\n", curl_easy_strerror(res));
        reset_console_color();
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
        set_console_color(COLOR_RED);
        fprintf(stderr, "Error fetching BGPView info: %s\n", curl_easy_strerror(res));
        reset_console_color();
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return;
    }
    cJSON *root = cJSON_Parse(chunk.memory);
    if (!root) {
        set_console_color(COLOR_RED);
        fprintf(stderr, "Failed to parse JSON.\n");
        reset_console_color();
        cJSON_Delete(root);
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return;
    }
    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (!data) {
        set_console_color(COLOR_RED);
        fprintf(stderr, "No data in JSON.\n");
        reset_console_color();
        cJSON_Delete(root);
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return;
    }
    set_console_color(COLOR_GREEN);
    fprintf(output, "\nASN Number: %d\n", cJSON_GetObjectItem(data, "asn")->valueint);
    fprintf(output, "Name: %s\n", cJSON_GetObjectItem(data, "name")->valuestring);
    fprintf(output, "Description: %s\n", cJSON_GetObjectItem(data, "description_short")->valuestring);
    fprintf(output, "Country: %s\n", cJSON_GetObjectItem(data, "country_code")->valuestring);
    fprintf(output, "Website: %s\n", cJSON_GetObjectItem(data, "website")->valuestring);
    cJSON *emails = cJSON_GetObjectItem(data, "email_contacts");
    if (emails) {
        set_console_color(COLOR_CYAN);
        fprintf(output, "\nEmail Contacts:\n");
        set_console_color(COLOR_WHITE);
        for (int i = 0; i < cJSON_GetArraySize(emails); i++) {
            fprintf(output, " - %s\n", cJSON_GetArrayItem(emails, i)->valuestring);
        }
    }
    cJSON *abuse = cJSON_GetObjectItem(data, "abuse_contacts");
    if (abuse) {
        set_console_color(COLOR_RED);
        fprintf(output, "\nAbuse Contacts:\n");
        set_console_color(COLOR_WHITE);
        for (int i = 0; i < cJSON_GetArraySize(abuse); i++) {
            fprintf(output, " - %s\n", cJSON_GetArrayItem(abuse, i)->valuestring);
        }
    }
    cJSON *address = cJSON_GetObjectItem(data, "owner_address");
    if (address) {
        set_console_color(COLOR_YELLOW);
        fprintf(output, "\nOwner Address:\n");
        set_console_color(COLOR_WHITE);
        for (int i = 0; i < cJSON_GetArraySize(address); i++) {
            fprintf(output, " %s\n", cJSON_GetArrayItem(address, i)->valuestring);
        }
    }
    set_console_color(COLOR_GREEN);
    fprintf(output, "Traffic Ratio: %s\n", cJSON_GetObjectItem(data, "traffic_ratio")->valuestring);
    fprintf(output, "Updated: %s\n", cJSON_GetObjectItem(data, "date_updated")->valuestring);
    reset_console_color();

    cJSON_Delete(root);
    curl_easy_cleanup(curl);
    free(chunk.memory);
}

void print_help(const char *progname, FILE *output) {
    set_console_color(COLOR_CYAN);
    fprintf(output, "Usage: %s <options>\n", progname);
    fprintf(output, "Options:\n");
    set_console_color(COLOR_WHITE);
    fprintf(output, " -i <IP[,IP,...]> Specify one or more IP addresses (comma-separated)\n");
    fprintf(output, " -d <domain[,domain,...]> Specify one or more domain names (comma-separated)\n");
    fprintf(output, " -f <file> Save output to a formatted text file\n");
    fprintf(output, " --help Show this help message\n");
    fprintf(output, " --version Show installed version\n");
    fprintf(output, " --ghversion Show latest GitHub release version\n");
    reset_console_color();
}

char *resolve_domain_to_ip(const char *domain) {
    // Note: getaddrinfo is available in Winsock, but requires WSAStartup
    struct addrinfo hints, *res;
    static char ip[INET6_ADDRSTRLEN] = {0};
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Force IPv4
    hints.ai_socktype = SOCK_STREAM;
    
    // Use the Winsock version (GetAddrInfo)
    if (getaddrinfo(domain, NULL, &hints, &res) != 0) {
        return NULL;
    }
    
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ip, sizeof(ip));
    
    // Use the Winsock version (FreeAddrInfo)
    freeaddrinfo(res);
    return ip;
}

// --- Windows-specific main function ---
int main(int argc, char *argv[]) {
    // Initialize Windows Console for color support
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole != INVALID_HANDLE_VALUE) {
        CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
        GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
        saved_attributes = consoleInfo.wAttributes;
    }

    // Initialize Winsock for network calls (required by getaddrinfo and DnsQuery)
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        set_console_color(COLOR_RED);
        fprintf(stderr, "WSAStartup failed.\n");
        reset_console_color();
        return 1;
    }

    char ips[1024] = {0};
    char domains[1024] = {0};
    char filename[256] = {0};
    FILE *output = stdout;
    int opt;

    // Custom argument parsing to handle --long-options, as getopt is not native
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            print_installed_version();
            WSACleanup();
            return 0;
        }
        if (strcmp(argv[i], "--ghversion") == 0) {
            print_latest_github_version();
            WSACleanup();
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0) {
            print_help(argv[0], stdout);
            WSACleanup();
            return 0;
        }
    }

    // Simple manual getopt emulation for -i, -d, -f
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            strncpy(ips, argv[i+1], sizeof(ips) - 1);
            i++;
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            strncpy(domains, argv[i+1], sizeof(domains) - 1);
            i++;
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            strncpy(filename, argv[i+1], sizeof(filename) - 1);
            i++;
        }
    }

    if (strlen(filename) > 0) {
        output = fopen(filename, "w");
        if (!output) {
            set_console_color(COLOR_RED);
            fprintf(stderr, "Failed to open file for writing.\n");
            reset_console_color();
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
    char *saveptr = NULL; // Required for strtok_r, but used as NULL for strtok
    
    // IP Lookup
    if (strlen(ips) > 0) {
        token = strtok_r(ips, ",", &saveptr);
        while (token != NULL) {
            char *asn = get_asn_from_ip(token);
            if (!asn) {
                set_console_color(COLOR_RED);
                fprintf(stderr, "Failed to resolve ASN from IP: %s\n", token);
                reset_console_color();
            } else {
                set_console_color(COLOR_GREEN);
                fprintf(output, "Resolved ASN for IP %s: %s\n", token, asn);
                reset_console_color();
                fetch_ip_ranges(asn, output);
                fetch_bgpview_info(asn, output);
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
    }

    // Domain Lookup
    if (strlen(domains) > 0) {
        token = strtok_r(domains, ",", &saveptr);
        while (token != NULL) {
            char *resolved_ip = resolve_domain_to_ip(token);
            if (!resolved_ip) {
                set_console_color(COLOR_RED);
                fprintf(stderr, "Failed to resolve domain to IP: %s\n", token);
                reset_console_color();
            } else {
                char *asn = get_asn_from_ip(resolved_ip);
                if (!asn) {
                    set_console_color(COLOR_RED);
                    fprintf(stderr, "Failed to resolve ASN from domain %s (IP %s)\n", token, resolved_ip);
                    reset_console_color();
                } else {
                    set_console_color(COLOR_GREEN);
                    fprintf(output, "Resolved ASN for domain %s (IP %s): %s\n", token, resolved_ip, asn);
                    reset_console_color();
                    fetch_ip_ranges(asn, output);
                    fetch_bgpview_info(asn, output);
                }
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
    }

    if (output != stdout) fclose(output);
    WSACleanup(); // Clean up Winsock
    return 0;
}