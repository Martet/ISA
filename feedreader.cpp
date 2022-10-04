#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <libxml/parser.h>
#include <getopt.h>

#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <regex>

enum protocol_t {HTTP, HTTPS};

typedef struct url {
    protocol_t protocol;
    std::string hostname;
    std::string resource;
    unsigned long port;
} url_t;

std::string to_lower(std::string str){
    for(std::size_t i = 0; i < str.length(); i++)
        str[i] = std::tolower(str[i]);
    return str;
}

//Read urls from given feedfile and save them as strings to vector urls
void read_feedfile(char *feedfile, std::vector<std::string> &urls){
    std::ifstream file(feedfile);
    if(!file.is_open()){
        std::cerr << "Failed opening feedfile " << feedfile << '\n';
        return;
    }
    std::string line;
    while(!file.eof()){
        std::getline(file, line);
        if(!line.empty() && line[0] != '#')
            urls.push_back(line);
    }
}

std::vector<url_t> parse_urls(std::vector<std::string> &urls){
    std::vector<url_t> out_urls;
    for(auto i: urls){
        url_t url;
        std::regex re(R"(^(https?)://([^/?#:]+)(:([0-9]+))?(.*)$)");
        std::smatch matches;

        if(!std::regex_match(i, matches, re)){
            std::cerr << "Failed parsing URL: " << i << '\n';
            exit(1);
        }

        url.protocol = std::string(matches[1]) == "https" ? HTTPS : HTTP;
        url.hostname = std::string(matches[2]);
        url.resource = std::string(matches[5]);

        std::string port(matches[4]);
        if(port.empty())
            url.port = url.protocol == HTTPS ? 443 : 80;
        else
            try{
                url.port = std::stoul(port);
            }
            catch(const std::exception &e){
                std::cerr << "Failed parsing URL (invalid port): " << i << '\n';
                exit(1);
            }

        out_urls.push_back(url);
    }
    return out_urls;
}

int main(int argc, char *argv[]){
    std::vector<std::string> urls;
    //Ensure correct positional argument parsing when POSIXLY_CORRECT is set
    if(argc > 1 && argv[1][0] != '-'){
        urls.push_back(std::string(argv[1]));
        argv[1] = argv[0];
        argv++;
        argc--;
    }

    std::string cert_file, cert_dir;
    bool show_time = false, show_author = false, show_url = false;
    int c;
    while((c = getopt(argc, argv, "f:c:C:Tau")) != -1){
        switch(c) {
            case 'f':
                read_feedfile(optarg, urls);
                break;
            case 'c':
                cert_file = optarg;
                break;
            case 'C':
                cert_dir = optarg;
                break;
            case 'T':
                show_time = true;
                break;
            case 'a':
                show_author = true;
                break;
            case 'u':
                show_url = true;
                break;
            default:
                std::cerr << "Invalid argument\n";
                return 1;
        }
    }
    //getopt shuffled positional arguments to end, save them as urls
    for(int i = optind; i < argc; i++)
        urls.push_back(std::string(argv[i]));

    if(urls.empty()){
        std::cerr << "No URL specified\n";
        return 1;
    }

    auto parsed_urls = parse_urls(urls);
    for(auto i: parsed_urls){
        std::cout << i.protocol << i.hostname << i.port << i.resource << '\n';
    }

    /*#define HOST_NAME "www.random.org"
    #define HOST_PORT "443"
    #define HOST_RESOURCE "/cgi-bin/randbyte?nbytes=32&format=h"

    long res = 1;

    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;

    SSL_library_init();

    SSL_load_error_strings();

    const SSL_METHOD* method = SSLv23_method();
    if(!(NULL != method)) handleFailure();

    ctx = SSL_CTX_new(method);
    if(!(ctx != NULL)) handleFailure();

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    SSL_CTX_set_verify_depth(ctx, 4);

    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, flags);

    res = SSL_CTX_load_verify_locations(ctx, "random-org-chain.pem", NULL);
    if(!(1 == res)) handleFailure();

    web = BIO_new_ssl_connect(ctx);
    if(!(web != NULL)) handleFailure();

    res = BIO_set_conn_hostname(web, HOST_NAME ":" HOST_PORT);
    if(!(1 == res)) handleFailure();

    BIO_get_ssl(web, &ssl);
    if(!(ssl != NULL)) handleFailure();

    res = SSL_set_tlsext_host_name(ssl, HOST_NAME);
    if(!(1 == res)) handleFailure();

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if(!(NULL != out)) handleFailure();

    res = BIO_do_connect(web);
    if(!(1 == res)) handleFailure();

    res = BIO_do_handshake(web);
    if(!(1 == res)) handleFailure();

    // Step 1: verify a server certificate was presented during the negotiation 
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert) { X509_free(cert); } 
    if(NULL == cert) handleFailure();

    // Step 2: verify the result of chain verification
    // Verification performed according to RFC 4158
    res = SSL_get_verify_result(ssl);
    if(!(X509_V_OK == res)) handleFailure();

    // Step 3: hostname verification
    // An exercise left to the reader

    BIO_puts(web, "GET " HOST_RESOURCE " HTTP/1.1\r\n"
                "Host: " HOST_NAME "\r\n"
                "Connection: close\r\n\r\n");
    BIO_puts(out, "\n");

    int len = 0;
    do
    {
    char buff[1536] = {};
    len = BIO_read(web, buff, sizeof(buff));
                
    if(len > 0)
        BIO_write(out, buff, len);

    } while (len > 0 || BIO_should_retry(web));

    if(out)
    BIO_free(out);

    if(web != NULL)
    BIO_free_all(web);

    if(NULL != ctx)
    SSL_CTX_free(ctx);*/

    return 0;
}
