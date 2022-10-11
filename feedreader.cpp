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
    std::string authority;
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

int main(int argc, char *argv[]){
    std::vector<std::string> urls;
    //Ensure correct positional argument parsing when POSIXLY_CORRECT is set
    if(argc > 1 && argv[1][0] != '-'){
        urls.push_back(std::string(argv[1]));
        argv[1] = argv[0];
        argv++;
        argc--;
    }

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
                return 1;
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
    for(auto i: parsed_urls){
        std::cout << i.protocol << i.hostname << i.port << i.resource << '\n';
    }

    SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	for(auto url : parsed_urls){
		BIO *bio;
		SSL_CTX *ctx;
        if(url.protocol == HTTP){
            ctx = SSL_CTX_new(SSLv23_client_method());

            int err;
            if(!cert_file && !cert_dir)
                err = SSL_CTX_set_default_verify_paths(ctx);
            else
                err = SSL_CTX_load_verify_locations(ctx, cert_file, cert_dir);
            if(err){
                std::cerr << "Certificate verification failed\n";
                return 1;
            }

            bio = BIO_new_ssl_connect(ctx);
        }
        else{
            bio = BIO_new_connect(url.authority.c_str());
        }


		/*if (!bio)
		{
			PRINTF_ERR("Connection to '%s' failed.", url.c_str());
			PROCESS_BIO_ERROR;
		}

		SSL *ssl = nullptr;
		if (urlParser.isHttps())
		{
			BIO_get_ssl(bio, &ssl);
			SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
			BIO_set_conn_hostname(bio, urlParser.getAuthority()->c_str());
		}

		if (BIO_do_connect(bio) <= 0)
		{
			PRINTF_ERR("Connection to '%s' failed.", url.c_str());
			PROCESS_BIO_ERROR;
		}

		if (ssl && SSL_get_verify_result(ssl) != X509_V_OK)
		{
			PRINTF_ERR(
				"Verification of certificates on '%s' failed.", url.c_str()
			);
			PROCESS_BIO_ERROR;
		}

		std::string request(
			"GET " + *urlParser.getPath() + " HTTP/1.0\r\n"
			"Host: " + *urlParser.getAuthority() + "\r\n"
			"Connection: Close\r\n"
			"User-Agent: Mozilla/5.0 Chrome/70.0.3538.77 Safari/537.36\r\n"
			"\r\n"
		);
		auto writeDataSize = static_cast<int>(request.size());
		bool firstWrite = true, writeDone = false;
		while (firstWrite || BIO_should_retry(bio))
		{
			firstWrite = false;
			if (BIO_write(bio, request.c_str(), writeDataSize))
			{
				writeDone = true;
				break;
			}
		}
		if (!writeDone)
		{
			PRINT_ERR("Bio write error.");
			PROCESS_BIO_ERROR;
		}

		char responseBuffer[READ_BUFFER_SIZE] = {'\0'};
		std::string response;
		int readResult = 0;
		do
		{
			bool firstRead = true, readDone = false;
			while (firstRead || BIO_should_retry(bio))
			{
				firstRead = false;
				readResult =
					BIO_read(bio, responseBuffer, READ_BUFFER_SIZE - 1);
				if (readResult >= 0)
				{
					if (readResult > 0)
					{
						responseBuffer[readResult] = '\0';
						response += responseBuffer;
					}

					readDone = true;
					break;
				}
			}
			if (!readDone)
			{
				PRINT_ERR("Bio read error.");
				PROCESS_BIO_ERROR;
			}
		}
		while (readResult != 0);

		std::string responseBody;
		if (!parseHttpResponse(response, &responseBody))
		{
			PRINTF_ERR("Invalid HTTP response from '%s'.", url.c_str());
			CLEAN_RESOURCES;
			PROCESS_ERROR;
		}

		if (!XmlParser::parseXmlFeed(responseBody, argumentProcessor, url))
		{
			CLEAN_RESOURCES;
			PROCESS_ERROR;
		}

		CLEAN_RESOURCES;*/
	}

    return 0;
}
