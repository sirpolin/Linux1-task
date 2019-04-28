#include "includes.h"
#include "base64.h"

/* YOU WILL HAVE TO CHANGE THESE TWO LINES  TO MATCH YOUR CONFIG */

#define PORT 12345 /* Port number as an integer - web server default is 80 */
#define IP_ADDRESS "192.168.1.165" /* IP Address as a string */

//char * command = "GET / HTTP/1.0 \r\n\r\nAuthorization: Basic YmFiYTpiYWJh";
char * command = "GET / HTTP/1.0 \r\n\r\n";
/* Note: spaces are delimiters and VERY important */

#define BUFSIZE 8196

void pexit(char * msg) {
    perror(msg);
    exit(1);
}

void main() {
    int i, sockfd;
    char buffer[BUFSIZE];
    static struct sockaddr_in serv_addr;

    printf("client trying to connect to %s and port %d\n", IP_ADDRESS, PORT);
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        pexit("socket() failed");

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
    serv_addr.sin_port = htons(PORT);

    /* Connect to the socket offered by the web server */
    if (connect(sockfd, (struct sockaddr * ) & serv_addr, sizeof(serv_addr)) < 0)
        pexit("connect() failed");

    char *req = malloc(65001);
    char login[65];
    char password[65];
    printf("input login\n");
    scanf("%s", login);
    printf("input password\n");
    scanf("%s", password);
    char *authdata = malloc(130);
    authdata = strcat(login, ":");
    authdata = strcat(authdata, password);
    size_t authdata_len = 0;
    authdata = base64_encode(authdata, strlen(login) + strlen(password), &authdata_len);

    int len = strlen("GET / HTTP/1.1 \r\n\r\nAuthorization: Basic ");
    memcpy(req, "GET / HTTP/1.1 \r\n\r\nAuthorization: Basic ", len);
    req += len;
    memcpy(req, authdata, authdata_len);
    req -= len;

    /* Now the sockfd can be used to communicate to the server the GET request */
    printf("Send bytes=%d %s\n", strlen(req), req);
    write(sockfd, req, strlen(req));

    /* This displays the raw HTML file (if index.html) as received by the browser */
    while ((i = read(sockfd, buffer, BUFSIZE)) > 0)
        write(1, buffer, i);

    printf("client trying to connect to %s and port %d\n", IP_ADDRESS, PORT);
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        pexit("socket() failed");

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
    serv_addr.sin_port = htons(PORT);

    /* Connect to the socket offered by the web server */
    if (connect(sockfd, (struct sockaddr * ) & serv_addr, sizeof(serv_addr)) < 0)
        pexit("connect() failed");
    free(req);
    req = malloc(65001);
    int flag;
    printf("input new word or auth (0, 1)\n");
    scanf("%d", &flag);
    if (flag == 0) {
        char *new_word = malloc(255);
        printf("input new word\n");
        scanf("%s", new_word);

        int len = strlen("GET /updatemsg/");
        memcpy(req, "GET /updatemsg/", len);
        req += len;
        memcpy(req, new_word, strlen(new_word));
        req += strlen(new_word);
        int len2 = strlen(" HTTP/1.1 \r\n\r\nAuthorization: Basic ");
        memcpy(req,  " HTTP/1.1 \r\n\r\nAuthorization: Basic ", len2);
        req += len2;
        memcpy(req, authdata, authdata_len);
        req -= (strlen(new_word) + len + len2);
    }

    /* Now the sockfd can be used to communicate to the server the GET request */
    printf("Send bytes=%d %s\n", strlen(req), req);
    write(sockfd, req, strlen(req));

    /* This displays the raw HTML file (if index.html) as received by the browser */
    while ((i = read(sockfd, buffer, BUFSIZE)) > 0)
        write(1, buffer, i);

}
