// feedreader.cpp - a lightweight utility for getting rss and atom feeds
// Author - Martin Zmitko (xzmitk01@stud.fit.vutbr.cz)

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

#define BUF_SIZE 4096

#define SSL_ERROR(msg) do{\
    response = url.url + " - " + msg + "\n";\
    if(bio){\
        BIO_reset(bio);\
        BIO_free_all(bio);\
    }\
    if(ctx) SSL_CTX_free(ctx);\
    return false;\
} while(0)

#define XML_ERROR do{\
    xmlCleanupParser();\
    xmlFreeDoc(doc);\
    return false;\
} while(0)

typedef struct url {
    bool is_https;
    std::string hostname;
    std::string resource;
    std::string authority;
    std::string url;
    unsigned long port;
} url_t;

typedef struct args {
    bool show_time;
    bool show_author;
    bool show_url;
    char *cert_file;
    char *cert_dir;
} args_t;

void print_help(){
    std::cerr << "Pouziti: feedreader <URL | -f <feedfile>> [-c <certfile>] [-C <certdir>] [-T] [-a] [-u] [-h]\n";
    std::cerr << "-f <feedfile>\tpouzit soubor se seznamem zdroju\n";
    std::cerr << "-c <certfile>\tpouzit soubor s certifikatem\n";
    std::cerr << "-C <certdir>\tpouzit slozku s certifikaty\n";
    std::cerr << "-T\t\tvypsat cas posledni zmeny u zaznamu\n";
    std::cerr << "-a\t\tvypsat autora u zaznamu\n";
    std::cerr << "-u\t\tvypsat url u zaznamu\n";
    std::cerr << "-h\t\tvypsat tuto zpravu a zkoncit\n";
}

//Read urls from given feedfile and save them as strings to vector urls
void read_feedfile(char *feedfile, std::vector<std::string> &urls){
    std::ifstream file(feedfile);
    if(!file.is_open()){
        std::cerr << "Otevreni souboru " << feedfile << " selhalo\n";
        return;
    }
    std::string line;
    while(!file.eof()){
        std::getline(file, line);
        if(!line.empty() && line[0] != '#')
            urls.push_back(line);
    }
}

//Parse argumens and return them in args struct, save urls to vector urls
args_t parse_args(int argc, char *argv[], std::vector<std::string> &urls){
    //Ensure correct positional argument parsing when POSIXLY_CORRECT is set
    if(argc > 1 && argv[1][0] != '-'){
        urls.push_back(std::string(argv[1]));
        argv[1] = argv[0];
        argv++;
        argc--;
    }

    args_t args = {};
    int c;
    while((c = getopt(argc, argv, "f:c:C:Tauh")) != -1){
        switch(c) {
            case 'f':
                read_feedfile(optarg, urls);
                break;
            case 'c':
                args.cert_file = optarg;
                break;
            case 'C':
                args.cert_dir = optarg;
                break;
            case 'T':
                args.show_time = true;
                break;
            case 'a':
                args.show_author = true;
                break;
            case 'u':
                args.show_url = true;
                break;
            case 'h':
                std::cerr << "Feedreader - nastroj pro ziskavani informaci z rss a atom zdroju\n";
                print_help();
                exit(0);
            default:
                std::cerr << "Neplatny argument\n";
                print_help();
                exit(1);
        }
    }
    //getopt shuffled positional arguments to end, save them as urls
    for(int i = optind; i < argc; i++)
        urls.push_back(std::string(argv[i]));

    if(urls.empty()){
        std::cerr << "Zadne URL nebylo specifikovano\n";
        print_help();
        exit(1);
    }

    return args;
}

//Parse vector of urls using regex
std::vector<url_t> parse_urls(std::vector<std::string> &urls){
    std::vector<url_t> out_urls;
    for(auto i: urls){
        url_t url;
        std::regex re(R"(^\s*(https?)://([a-zA-Z.-]+)(:([0-9]+))?(.*)$)");
        std::smatch matches;

        if(!std::regex_match(i, matches, re)){
            std::cerr << "Chyba ve zpracovani URL: " << i << '\n';
            exit(1);
        }

        url.is_https = std::string(matches[1]) == "https";
        url.hostname = std::string(matches[2]);
        url.resource = std::string(matches[5]);
        url.url = i;

        std::string port(matches[4]);
        if(port.empty())
            url.port = url.is_https ? 443 : 80;
        else
            try{
                url.port = std::stoul(port);
                if(url.port < 1 || url.port > 65535)
                    throw std::exception();
            }
            catch(const std::exception &e){
                std::cerr << "Chyba ve zpracovani URL (neplatny port): " << i << '\n';
                exit(1);
            }
        url.authority = url.hostname + ":" + std::to_string(url.port);

        out_urls.push_back(url);
    }
    return out_urls;
}

//Parse the response http headers, response will contain received data on success, error message on failure
bool parse_http(std::string &response){
    std::size_t http_end = response.find("\r\n\r\n");
    std::regex re(R"(^HTTP/1.[01] (\d{3} .+))");
    std::smatch matches;
    if(!std::regex_search(response, matches, re) || http_end == std::string::npos){
        response = "Neplatna HTTP hlavicka v odpovedi";
        return false;
    }

    if(matches[1] != "200 OK"){
        response = "Neplatny kod HTTP odpovedi: " + std::string(matches[1]);
        return false;
    }

    response = response.substr(http_end + 4);
    return true;
}

//Do the HTTP request, response will contain received data on success, error message on failure
bool do_request(BIO *bio, url_t url, std::string &response){
    std::string request(
        "GET " + url.resource + " HTTP/1.0\r\n"
        "Host: " + url.authority + "\r\n"
        "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1\r\n"
        "Connection: Close\r\n\r\n"
    );

    //Send request
    int written = 0;
    do{
        written += BIO_write(bio, request.c_str(), request.size());
    } while(BIO_should_retry(bio));
    if(written != (int) request.size())
        return false;

    //Get response
    char buf[BUF_SIZE] = "";
    int res;
    do{
        res = BIO_read(bio, buf, BUF_SIZE - 1);
        if(res > 0){
            buf[res] = '\0';
            response += buf;
        }
    } while(BIO_should_retry(bio) || res != 0);
    
    return true;
}

//Find a xmlNode with a specific name in a list starting from first_node, NULL if not found
xmlNodePtr find_node(xmlNodePtr first_node, xmlChar *name){
    for(xmlNodePtr node = first_node; node != NULL; node = node->next){
        if(!xmlStrcmp(node->name, name)){
            return node;
        }
    }
    return NULL;
}

//Return a pointer to a xmlNode with a specific name in a list starting from first_node, NULL if not found
xmlChar *node_content(xmlNodePtr first_node, xmlChar *name){
    xmlNodePtr node = find_node(first_node, name);
    if(!node)
        return NULL;
    else
        return xmlNodeGetContent(node);
}

//Connect and authenticate using SSL, response will contain received data on success, error message on failure
bool do_ssl(url_t url, args_t args, std::string &response){
    BIO *bio = NULL;
    SSL_CTX *ctx = NULL;
    if(url.is_https){
        //Set up certificates
        ctx = SSL_CTX_new(SSLv23_client_method());

        int err;
        if(!args.cert_file && !args.cert_dir)
            err = SSL_CTX_set_default_verify_paths(ctx);
        else
            err = SSL_CTX_load_verify_locations(ctx, args.cert_file, args.cert_dir);
        if(err == 0)
            SSL_ERROR("Nacteni certifikatu selhalo");

        bio = BIO_new_ssl_connect(ctx);
    }
    else{
        //Insecure connection
        bio = BIO_new_connect(url.authority.c_str());
    }

    //Verify initialized connection
    if(!bio)
        SSL_ERROR("Spojeni selhalo");

    //Set secure connection parameters
    SSL *ssl = NULL;
    if(url.is_https){
        BIO_get_ssl(bio, &ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
        SSL_set_tlsext_host_name(ssl, url.hostname.c_str());
        BIO_set_conn_hostname(bio, url.authority.c_str());
    }

    //Make connection
    if(BIO_do_connect(bio) <= 0)
        SSL_ERROR("Spojeni selhalo");

    if(url.is_https){
        //Verify we've got a certificate
        X509 *cert = SSL_get_peer_certificate(ssl);
        if(!cert)
            SSL_ERROR("Protejsek neodeslal certifikat");
        X509_free(cert);

        //Verify the certificate
        long result = SSL_get_verify_result(ssl);
        if(ssl && result != X509_V_OK)
            SSL_ERROR("Spojeni selhalo (nepodarilo se overit certifikat)");
    }

    //Do the request
    if(!do_request(bio, url, response))
        SSL_ERROR("Spojeni selhalo");
    
    //Free SSL
    if(bio){
        BIO_reset(bio);
        BIO_free_all(bio);
    }
    if(ctx) SSL_CTX_free(ctx);

    return true;
}

//Parse XML and print output
bool parse_xml(std::string xml, args_t args){
    xmlDocPtr doc = xmlParseDoc((xmlChar*) xml.c_str());
    if(!doc)
        return false;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if(!root)
        XML_ERROR;

    //Decide if rss or atom
    bool is_rss;
    xmlChar *prop = NULL;
    if(!xmlStrcmp(root->name, (xmlChar *)"rss") &&
       !xmlStrcmp(prop = xmlGetProp(root, (xmlChar *)"version"), (xmlChar *)"2.0"))
        is_rss = true;
    else if(!xmlStrcmp(root->name, (xmlChar *)"feed") &&
            !xmlStrcmp(root->ns->href, (xmlChar *)"http://www.w3.org/2005/Atom"))
        is_rss = false;
    else
        XML_ERROR;
    if(prop) free(prop);

    //In RSS, all elements are one level deeper in element "channel"
    if(is_rss)
        root = root->children->next;

    //Get title
    xmlChar *title = node_content(root->children, (xmlChar *)"title");
    if(!title)
        XML_ERROR;
    std::cout << "*** " << title << " ***\n";
    free(title);

    //Parse entries
    bool first_entry = true;
    xmlChar *entry_name = (xmlChar *)(is_rss ? "item" : "entry");
    xmlNodePtr node = find_node(root->children, entry_name);
    do{
        //Print empty line between entries
        if(!first_entry && (args.show_author || args.show_time || args.show_url))
            std::cout << "\n";
        first_entry = false;

        //Print title
        xmlChar *title = node_content(node->children, (xmlChar *)"title");
        if(!title)
            XML_ERROR;
        std::cout << title << "\n";
        free(title);

        xmlNodePtr url_node, author_node, time_node;

        //Print url
        if(args.show_url && (url_node = find_node(node->children, (xmlChar *)"link"))){
            xmlChar *url = is_rss ? xmlNodeGetContent(url_node) : xmlGetProp(url_node, (xmlChar *)"href");
            std::cout << "URL: " << url << "\n";
            free(url);
        }

        //Print author
        if(args.show_author && (author_node = find_node(node->children, (xmlChar *)"author"))){
            xmlChar *author = xmlNodeGetContent(is_rss ? author_node : author_node->children->next);
            std::cout << "Autor: " << author << "\n";
            free(author);
        }

        //Print time of update
        if(args.show_time && (time_node = find_node(node->children, (xmlChar *)(is_rss ? "pubDate" : "updated")))){
            xmlChar *time = xmlNodeGetContent(time_node);
            std::cout << "Aktualizace: " << time << "\n";
            free(time);
        }
    } while((node = find_node(node->next, entry_name)));

    xmlCleanupParser();
    xmlFreeDoc(doc);
    return true;
}

int main(int argc, char *argv[]){
    //Parse arguments and urls
    std::vector<std::string> urls;
    auto args = parse_args(argc, argv, urls);
    auto parsed_urls = parse_urls(urls);

    //Set up OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    //Loop through all urls
    int success = 1;
    for(auto url : parsed_urls){
        //Print separator between feeds
        if(!success && parsed_urls.size() > 1)
            std::cout << "\n";

        std::string response;
        if(!do_ssl(url, args, response)){
            std::cerr << url.url << " - " << response << "\n";
            continue;
        }

        if(!parse_http(response)){
            std::cerr << url.url << " - " << response << "\n";
            continue;
        }

        if(!parse_xml(response, args)){
            std::cerr << url.url << " - Chyba ve zpracovani XML\n";
            continue;
        }

        success = 0;
    }

    return success;
}
