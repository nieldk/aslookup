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
// NOTE: strtok_r is not strictly thread-safe with this macro, but works for this single-threaded use.
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
    if (hConsole) {
        SetConsoleTextAttribute(hConsole, saved_attributes);
    }
}

// Memory structure for cURL callbacks
struct MemoryStruct {
    char *memory;
    size_t size;
};

// cURL callback function to store received data
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *chunk = (struct MemoryStruct *)userp;

    char *ptr = realloc(chunk->memory, chunk->size + realsize + 1);
    if (ptr == NULL) {
        fprintf(stderr, "not enough memory (realloc returned NULL)\n");
        return 0;
    }

    chunk->memory = ptr;
    memcpy(&(chunk->memory[chunk->size]), contents, realsize);
    chunk->size += realsize;
    chunk->memory[chunk->size] = 0;

    return realsize;
}

// Function to resolve a domain name to an IP address (using Windows API)
char *resolve_domain_to_ip(const char *domain) {
    struct addrinfo hints, *res, *p;
    char ipstr[INET6_ADDRSTRLEN];
    char *resolved_ip = NULL;
    int status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;

    // GetAddrInfoA attempts to resolve the domain name
    if ((status = GetAddrInfoA(domain, NULL, &hints, &res)) != 0) {
        return NULL;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            // Use inet_ntop to convert IP to string
            InetNtopA(AF_INET, addr, ipstr, sizeof(ipstr));
            resolved_ip = strdup(ipstr);
            break; // We only need the first valid IPv4 address
        }
        // IPv6 lookup is also possible, but sticking to IPv4 for simplicity for now
    }

    FreeAddrInfo(res);

    return resolved_ip;
}

// Function 1: Get ASN from IP
char *get_asn_from_ip(const char *ip_address) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    char url[256];
    char *asn = NULL;

    chunk.memory = malloc(1);
    chunk.size = 0;

    snprintf(url, sizeof(url), "https://api.bgpview.io/ip/%s", ip_address);

    curl = curl_easy_init();
    if (curl) {
        // --- CRITICAL FIX: Force TLS 1.2 for MinGW Schannel compatibility ---
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        // -------------------------------------------------------------------
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "aslookup-win/1.0");

        res = curl_easy_perform(curl);
        if (res == CURLE_OK && chunk.size > 0) {
            cJSON *json = cJSON_Parse(chunk.memory);
            if (json) {
                cJSON *data = cJSON_GetObjectItemCaseSensitive(json, "data");
                if (data) {
                    cJSON *asn_data = cJSON_GetObjectItemCaseSensitive(data, "asn");
                    if (asn_data && cJSON_IsNumber(asn_data)) {
                        char asn_str[32];
                        snprintf(asn_str, sizeof(asn_str), "%d", asn_data->valueint);
                        asn = strdup(asn_str);
                    }
                }
                cJSON_Delete(json);
            } else {
                // Not a valid JSON response (likely the issue you are seeing)
                // We don't print anything here to avoid mixing output
            }
        }
        curl_easy_cleanup(curl);
    }
    free(chunk.memory);
    return asn;
}

// Function 2: Fetch IP Ranges (Prefixes)
void fetch_ip_ranges(const char *asn, FILE *output) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    char url[256];

    chunk.memory = malloc(1);
    chunk.size = 0;

    snprintf(url, sizeof(url), "https://api.bgpview.io/asn/%s/prefixes", asn);

    curl = curl_easy_init();
    if (curl) {
        // --- CRITICAL FIX: Force TLS 1.2 for MinGW Schannel compatibility ---
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        // -------------------------------------------------------------------
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "aslookup-win/1.0");

        res = curl_easy_perform(curl);
        if (res == CURLE_OK && chunk.size > 0) {
            cJSON *json = cJSON_Parse(chunk.memory);
            if (json) {
                cJSON *data = cJSON_GetObjectItemCaseSensitive(json, "data");
                if (data) {
                    cJSON *asn_details = cJSON_GetObjectItemCaseSensitive(data, "asn");
                    if (asn_details) {
                        cJSON *name = cJSON_GetObjectItemCaseSensitive(asn_details, "name");
                        cJSON *country_code = cJSON_GetObjectItemCaseSensitive(asn_details, "country_code");
                        
                        set_console_color(COLOR_CYAN);
                        fprintf(output, "IP Ranges:\n");
                        fprintf(output, "ASN: %s, Name: %s, Country: %s\n", asn, 
                            cJSON_IsString(name) ? name->valuestring : "N/A", 
                            cJSON_IsString(country_code) ? country_code->valuestring : "N/A");
                        reset_console_color();
                    }

                    cJSON *ipv4_prefixes = cJSON_GetObjectItemCaseSensitive(data, "ipv4_prefixes");
                    if (ipv4_prefixes && cJSON_IsArray(ipv4_prefixes)) {
                        cJSON *prefix_item = NULL;
                        fprintf(output, "--- IPv4 Prefixes ---\n");
                        cJSON_ArrayForEach(prefix_item, ipv4_prefixes) {
                            cJSON *prefix = cJSON_GetObjectItemCaseSensitive(prefix_item, "prefix");
                            if (prefix && cJSON_IsString(prefix)) {
                                fprintf(output, "%s\n", prefix->valuestring);
                            }
                        }
                    }
                    
                    cJSON *ipv6_prefixes = cJSON_GetObjectItemCaseSensitive(data, "ipv6_prefixes");
                    if (ipv6_prefixes && cJSON_IsArray(ipv6_prefixes)) {
                        cJSON *prefix_item = NULL;
                        fprintf(output, "--- IPv6 Prefixes ---\n");
                        cJSON_ArrayForEach(prefix_item, ipv6_prefixes) {
                            cJSON *prefix = cJSON_GetObjectItemCaseSensitive(prefix_item, "prefix");
                            if (prefix && cJSON_IsString(prefix)) {
                                fprintf(output, "%s\n", prefix->valuestring);
                            }
                        }
                    }
                }
                cJSON_Delete(json);
            } else {
                set_console_color(COLOR_RED);
                fprintf(output, "Failed to parse JSON for IP Ranges.\n");
                reset_console_color();
            }
        } else {
            set_console_color(COLOR_RED);
            fprintf(output, "Failed to fetch IP Ranges for ASN %s (cURL error: %s).\n", asn, curl_easy_strerror(res));
            reset_console_color();
        }
        curl_easy_cleanup(curl);
    }
    free(chunk.memory);
}

// Function 3: Fetch ASN Info (includes contact details)
void fetch_bgpview_info(const char *asn, FILE *output) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    char url[256];

    chunk.memory = malloc(1);
    chunk.size = 0;

    snprintf(url, sizeof(url), "https://api.bgpview.io/asn/%s", asn);

    set_console_color(COLOR_YELLOW);
    fprintf(output, "\nASN Information:\n");
    reset_console_color();

    curl = curl_easy_init();
    if (curl) {
        // --- CRITICAL FIX: Force TLS 1.2 for MinGW Schannel compatibility ---
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        // -------------------------------------------------------------------
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "aslookup-win/1.0");

        res = curl_easy_perform(curl);
        if (res == CURLE_OK && chunk.size > 0) {
            cJSON *json = cJSON_Parse(chunk.memory);
            if (json) {
                cJSON *data = cJSON_GetObjectItemCaseSensitive(json, "data");
                if (data) {
                    cJSON *abuse = cJSON_GetObjectItemCaseSensitive(data, "abuse");
                    cJSON *emails = cJSON_GetObjectItemCaseSensitive(data, "emails");
                    
                    if (abuse && cJSON_IsObject(abuse)) {
                        cJSON *abuse_email = cJSON_GetObjectItemCaseSensitive(abuse, "email");
                        if (abuse_email && cJSON_IsString(abuse_email)) {
                            fprintf(output, "Abuse Contact: %s\n", abuse_email->valuestring);
                        }
                    }
                    
                    if (emails && cJSON_IsArray(emails)) {
                        cJSON *email_item = NULL;
                        cJSON_ArrayForEach(email_item, emails) {
                            if (cJSON_IsString(email_item)) {
                                fprintf(output, "Technical Contact: %s\n", email_item->valuestring);
                            }
                        }
                    }
                }
                cJSON_Delete(json);
            } else {
                set_console_color(COLOR_RED);
                fprintf(output, "Failed to parse JSON for ASN Info.\n");
                reset_console_color();
            }
        } else {
            set_console_color(COLOR_RED);
            fprintf(output, "Failed to fetch ASN Info for ASN %s (cURL error: %s).\n", asn, curl_easy_strerror(res));
            reset_console_color();
        }
        curl_easy_cleanup(curl);
    }
    // FIX: Changed 'chunk->memory' to 'chunk.memory' in the previous step
    free(chunk.memory);
}

// Main function
int main(int argc, char **argv) {
    // Windows Console initialization
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole != INVALID_HANDLE_VALUE) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        saved_attributes = csbi.wAttributes;
    }

    // --- CRITICAL FIX 1: Initialize Winsock (required for GetAddrInfo/DNS) ---
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return 1;
    }
    // -------------------------------------------------------------------------

    char *ips = NULL; 
    char *domains = NULL; 
    FILE *output = stdout; 

    // --- CRITICAL FIX 2: Implement robust command-line argument parsing ---
    if (argc < 3) {
        set_console_color(COLOR_WHITE);
        fprintf(output, "Usage: %s -d <domain1,domain2> -i <ip1,ip2> > output.txt\n", argv[0]);
        fprintf(output, "       -d: Comma-separated list of domains to look up.\n");
        fprintf(output, "       -i: Comma-separated list of IP addresses to look up.\n");
        reset_console_color();
        // Skip WSACleanup and curl_global_cleanup, as they aren't strictly necessary if we exit here.
        // It's technically safer to clean up, but for a simple usage error exit, we can skip it.
        return 1; 
    }
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && (i + 1) < argc) {
            domains = strdup(argv[++i]);
        } else if (strcmp(argv[i], "-i") == 0 && (i + 1) < argc) {
            ips = strdup(argv[++i]);
        }
    }
    // ----------------------------------------------------------------------


    char *token;
    char *saveptr;

    // IP Lookup
    if (ips != NULL && strlen(ips) > 0) {
        token = strtok_r(ips, ",", &saveptr);
        while (token != NULL) {
            char *asn = get_asn_from_ip(token);
            if (!asn) {
                set_console_color(COLOR_RED);
                fprintf(stderr, "Failed to resolve ASN from IP: %s\n", token);
                reset_console_color();
            } else {
                set_console_color(COLOR_GREEN);
                fprintf(output, "\nResolved ASN for IP %s: %s\n", token, asn);
                reset_console_color();
                fetch_ip_ranges(asn, output);
                fetch_bgpview_info(asn, output);
                free(asn);
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
    }

    // Domain Lookup
    if (domains != NULL && strlen(domains) > 0) {
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
                    fprintf(output, "\nResolved ASN for domain %s (IP %s): %s\n", token, resolved_ip, asn);
                    reset_console_color();
                    fetch_ip_ranges(asn, output);
                    fetch_bgpview_info(asn, output);
                    free(asn);
                }
                free(resolved_ip); // Free the resolved IP
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
    }

    if (ips) free(ips);
    if (domains) free(domains);
    
    // Cleanup
    curl_global_cleanup();
    // --- CRITICAL FIX 1: Clean up Winsock ---
    WSACleanup();
    // ----------------------------------------
    
    return 0;
}