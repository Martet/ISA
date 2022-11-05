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

#define ERROR_CONTINUE(msg) if(1){\
    std::cerr << url.url << " - " << msg << "\n";\
    std::cerr << ERR_reason_error_string(ERR_get_error()) << "\n";\
    if(bio) BIO_free_all(bio);\
	if(ctx) SSL_CTX_free(ctx);\
    continue;\
}

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

void print_help(){
    std::cerr << "Usage: feedreader <URL | -f <feedfile>> [-c <certfile>] [-C <certdir>] [-T] [-a] [-u] [-h]\n";
    std::cerr << "-f <feedfile>\tspecify a file with a list of URLs to read from\n";
    std::cerr << "-c <certfile>\tspecify a certificate to use\n";
    std::cerr << "-C <certdir>\tspecify a directory with certificates to use\n";
    std::cerr << "-T\t\tprint the time of each feed entry\n";
    std::cerr << "-a\t\tprint the author of each feed entry\n";
    std::cerr << "-u\t\tprint the associated url of each feed entry\n";
    std::cerr << "-h\t\tprint this help message and exit\n";
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

//Parse vector of urls using regex
std::vector<url_t> parse_urls(std::vector<std::string> &urls){
    std::vector<url_t> out_urls;
    for(auto i: urls){
        url_t url;
        std::regex re(R"(^\s*(https?)://([^/?#:]+)(:([0-9]+))?(.*)$)");
        std::smatch matches;

        if(!std::regex_match(i, matches, re)){
            std::cerr << "Failed parsing URL: " << i << '\n';
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
                std::cerr << "Failed parsing URL (invalid port): " << i << '\n';
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
        response = "Invalid HTTP response header";
        return false;
    }

    if(matches[1] != "200 OK"){
        response = "Invalid HTTP response code: " + std::string(matches[1]);
        return false;
    }

    response = response.substr(http_end + 4);
    return true;
}

xmlNodePtr find_node(xmlNodePtr first_node, xmlChar *name){
    for(xmlNodePtr node = first_node; node != NULL; node = node->next){
        if(!xmlStrcmp(node->name, name)){
            return node;
        }
    }
    return NULL;
}

xmlChar *node_content(xmlNodePtr first_node, xmlChar *name){
    xmlNodePtr node = find_node(first_node, name);
    if(!node)
        return NULL;
    else
        return xmlNodeGetContent(node);
}

bool parse_xml(std::string xml, bool show_time, bool show_author, bool show_url){
    xmlDocPtr doc = xmlParseDoc((xmlChar*) xml.c_str());
    if(!doc)
        return false;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if(!root)
        XML_ERROR;

    bool is_rss;
    if(!xmlStrcmp(root->name, (xmlChar *)"rss") &&
       !xmlStrcmp(xmlGetProp(root, (xmlChar *)"version"), (xmlChar *)"2.0"))
        is_rss = true;
    else if(!xmlStrcmp(root->name, (xmlChar *)"feed") &&
            !xmlStrcmp(root->ns->href, (xmlChar *)"http://www.w3.org/2005/Atom"))
        is_rss = false;
    else
        XML_ERROR;

    //In RSS, all elements are one level deeper in element "channel"
    if(is_rss)
        root = root->children;

    //Get title
    xmlChar *title = node_content(root->children, (xmlChar *)"title");
    if(!title)
        XML_ERROR;
    std::cout << "*** " << title << " ***\n";

    //Parse entries
    bool first_entry = true;
    xmlChar *entry_name = (xmlChar *)(is_rss ? "item" : "entry");
    xmlNodePtr node = find_node(root->children, entry_name);
    do{
        if(!first_entry && (show_author || show_time || show_url))
            std::cout << "\n";
        first_entry = false;

        xmlChar *title = node_content(node->children, (xmlChar *)"title");
        if(!title)
            XML_ERROR;
        std::cout << title << "\n";

        xmlNodePtr url_node, author_node, time_node;
        if(show_url && (url_node = find_node(node->children, (xmlChar *)"link"))){
            xmlChar *url = is_rss ? xmlNodeGetContent(url_node) : xmlGetProp(url_node, (xmlChar *)"href");
            std::cout << "URL: " << url << "\n";
        }

        if(show_author && (author_node = find_node(node->children, (xmlChar *)"author")))
            std::cout << "Autor: " << xmlNodeGetContent(is_rss ? author_node : author_node->children) << "\n";

        if(show_time && (time_node = find_node(node->children, (xmlChar *)(is_rss ? "pubDate" : "updated"))))
            std::cout << "Aktualizace: " << xmlNodeGetContent(time_node) << "\n";
    } while((node = find_node(node->next, entry_name)));

    xmlCleanupParser();
    xmlFreeDoc(doc);
    return true;
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

    //Parse arguments
    char *cert_file = NULL, *cert_dir = NULL;
    bool show_time = false, show_author = false, show_url = false;
    int c;
    while((c = getopt(argc, argv, "f:c:C:Tauh")) != -1){
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
            case 'h':
                std::cerr << "Feedreader - an utility to get information from RSS feeds\n";
                print_help();
                return 0;
            default:
                std::cerr << "Invalid argument\n";
                print_help();
                return 1;
        }
    }
    //getopt shuffled positional arguments to end, save them as urls
    for(int i = optind; i < argc; i++)
        urls.push_back(std::string(argv[i]));

    if(urls.empty()){
        std::cerr << "No URL specified\n";
        print_help();
        return 1;
    }

    auto parsed_urls = parse_urls(urls);

    //Set up OpenSSL
    SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

    //Loop through all urls
    int success = 0;
    bool first_url = true;
	for(auto url : parsed_urls){
        if(!first_url && parsed_urls.size() > 1)
            std::cout << "\n";
        first_url = false;

		BIO *bio = NULL;
		SSL_CTX *ctx = NULL;
        if(url.is_https){
            //Set up certificates
            ctx = SSL_CTX_new(SSLv23_client_method());

            int err;
            if(!cert_file && !cert_dir)
                err = SSL_CTX_set_default_verify_paths(ctx);
            else
                err = SSL_CTX_load_verify_locations(ctx, cert_file, cert_dir);
            if(err == 0)
                ERROR_CONTINUE("Certificate verification failed");

            bio = BIO_new_ssl_connect(ctx);
        }
        else{
            //Unsecure connection
            bio = BIO_new_connect(url.authority.c_str());
        }

        //Verify initialized connection
        if(!bio)
            ERROR_CONTINUE("Connection failed");

        //Set secure connection parameters
		SSL *ssl = NULL;
		if(url.is_https){
			BIO_get_ssl(bio, &ssl);
			SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
            SSL_set_tlsext_host_name(ssl, url.authority.c_str());
			BIO_set_conn_hostname(bio, url.authority.c_str());
		}

        //Make connection
		if(BIO_do_connect(bio) <= 0)
			ERROR_CONTINUE("Connection failed");

        if(url.is_https){
            //Verify we've got a certificate
            X509 *cert = SSL_get_peer_certificate(ssl);
            if(!cert)
                ERROR_CONTINUE("Invalid host certificate");
            X509_free(cert);

            //Verify the certificate
            long result = SSL_get_verify_result(ssl);
            if(ssl && result != X509_V_OK)
                ERROR_CONTINUE("Connection failed");
        }

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
            ERROR_CONTINUE("Failed sending request");

        //Get response
		char buf[BUF_SIZE] = "";
        std::string response;
        int res;
        do{
            res = BIO_read(bio, buf, BUF_SIZE - 1);
            if(res > 0){
                buf[res] = '\0';
                response += buf;
            }
        } while(BIO_should_retry(bio) || res != 0);
        if(response.empty())
            ERROR_CONTINUE("Connection failed");
        
        if(bio) BIO_free_all(bio);
        if(ctx) SSL_CTX_free(ctx);

        if(!parse_http(response)){
            std::cerr << url.url << " - " << response << "\n";
            continue;
        }

        if(!parse_xml(response, show_time, show_author, show_url)){
            std::cerr << url.url << " - Error parsing XML\n";
            continue;
        }

        success = 1;
	}

    return success;
}
