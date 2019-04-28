#include "includes.h"
#include "base64.h"

#define SERVER_PORT 12345
#define MAX_CONNECTIONS 1000
#define MAX_DIFFERENT_USERS 1024

#define LOCK_FILE_PATH "/tmp/pid.lock"
#define m_string char*

typedef enum {
    eHTTP_UNKNOWN = 0,
    eHTTP_CONNECT,
    eHTTP_DELETE,
    eHTTP_GET,
    eHTTP_HEAD,
    eHTTP_OPTIONS,
    eHTTP_PATCH,
    eHTTP_POST,
    eHTTP_PUT,
    eHTTP_TRACE
} eHTTPMethod;

typedef struct {
    eHTTPMethod type;
    char path[255];
} sHTTPHeader;

typedef struct {
    void *access_semaphore;
    char login[65];
    char password[65];
    char bound_ip[17];
    char message[2049];
} dbElem;

typedef struct {
    int sockd;
    struct sockaddr_in client_sockaddr;
    int client_sockaddr_size;
    void *database;
} clientData;

// === DAEMON BASE FUNCTIONS ===

// Starts server daemon, returns 1 on success, otherwise 0
void start_server();

// Stops server daemon, returns 1 on success, otherwise 0
void stop_server();

// Shows help and returns (is used if no parameter specified)
void show_help();

// Runs server event loop (called inside daemon)
void process_server();


// === SERVER BASE FUNCTIONS ===

// Creates socket, binds it to defined port and makes ready to listen for connections.
int create_socket();

dbElem *getDbElementByUserName(m_string username, dbElem *database);

dbElem *createNewElement(dbElem *database) {
    for (int i = 0; i < MAX_DIFFERENT_USERS; ++i) {
        if (database[i].login[0] == '\0')
            return &database[i];
    }
    return NULL;
}

dbElem *getDbElementByAssignedIP(m_string ipv4, dbElem *database);

// === WORKER BASE FUNCTIONS ===

// Checking user authentification based on bound ip address to database item or matching login and password;
// Returns 1 and pointer to user dbElem, if auth successfull
// Returns 0 if there's no user with such login
// Returns -1 if credentials are incorrect or there's a user with such login, but passwords don't match
int check_user_authorisation(m_string client_ip, dbElem *database, m_string login, m_string password, dbElem **element);

int getLoginAndPasswordFromRequest(m_string request, m_string*login, m_string*password);

// Tries to update user message. Returns 1, if successfull, or 0 - if not;
int update_user_message(dbElem *user_data, m_string msg, int len);

void send_404_not_found(int sockd);

void send_401_not_authorised(int sockd);

void send_403_forbidden(int sockd);

// Sends normal message
void send_200_message(int sockd, m_string message);


// === WORKER ADDITIONAL FUNCTIONS ===

// Returns client address depending on ipv4/ipv6 protocol
void *get_client_addr(struct sockaddr *);

// Handles request and answers
void *handle_request(void *data);

// Splits http header and returns type and path
void parse_http_request(const char *, sHTTPHeader *);

// ============================================================================================= //

int main(int argc, char **argv) {
    if (argc < 2) {
        show_help();
        return 0;
    }
    if (strcmp(argv[1], "start") == 0) {
        start_server();
        return 0;
    } else if (strcmp(argv[1], "stop") == 0) {
        stop_server();
        return 0;
    } else if (strcmp(argv[1], "help") == 0) {
        show_help();
        return 0;
    } else {
        show_help();
        return 0;
    }
}

void start_server() {
    FILE *lock_file = fopen(LOCK_FILE_PATH, "r");
    if (lock_file) {
        fprintf(stderr, "Error: seems like server is already running!\nStop it before starting the new one!\n");
        return;
    }

    pid_t pid = fork();

    if (pid == -1) {
        fprintf(stderr, "Error: cannot create server! (fork exited with error: %s)\n", strerror(errno));
        return;
    } else if (pid == 0) {
        process_server();
        return;
    } else {
        printf("Server started with pid = %d\n", pid);
        lock_file = fopen(LOCK_FILE_PATH, "w");
        fprintf(lock_file, "%d", pid);
        fclose(lock_file);
        return;
    }
}

void stop_server() {
    FILE *lock_file = fopen(LOCK_FILE_PATH, "r");
    if (!lock_file) {
        fprintf(stderr, "Error: cannot stop server (no running server found)!\n");
        return;
    }

    int pid;
    if (fscanf(lock_file, "%d", &pid) != 1) {
        fprintf(stderr, "Error: cannot stop server (pid read error)!\n");
        fclose(lock_file);
        return;
    }

    if (kill(pid, SIGTERM) != 0) {
        fprintf(stderr,
                "Warning: server pid is incorrect, server might be already stopped (exited), but lock file still exists.\n");
    }

    fclose(lock_file);
    if (remove(LOCK_FILE_PATH) != 0) {
        fprintf(stderr, "Error: cannot remove server lock file (%s), but server was stopped...\n", LOCK_FILE_PATH);
    } else {
        printf("Server stopped successfully.\n");
    }
}

void show_help() {
    printf("Using: server <COMMAND>\n"
           "\n"
           "<COMMAND> values:\n"
           "start - starts server daemon, if there's no one already started.\n"
           "\n"
           "stop - stops running server daemon if there's one.\n"
           "\n"
           "help - shows this help.\n"
           "");
}

int create_socket() {
    printf("Creating socket\n");
    int sock = socket(PF_INET, SOCK_STREAM, 0);

    int on = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    /* initialize the server's sockaddr */
    struct sockaddr_in server_sockaddr;
    memset(&server_sockaddr, 0, sizeof(server_sockaddr));
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_sockaddr.sin_port = htons(SERVER_PORT);

    printf("Binding socket %d to sockaddr %p with size %u\n", sock, (struct sockaddr *) &server_sockaddr,
           sizeof(server_sockaddr));
    int bind_result = bind(sock, (struct sockaddr *) &server_sockaddr, sizeof(server_sockaddr));
    if (bind_result < 0) {
        fprintf(stderr, "Server: Error: bind failed!");
        return -1;
    }

    listen(sock, MAX_CONNECTIONS);

    return sock;
}

dbElem *getDbElementByUserName(m_string username, dbElem *database) {
    for (int i = 0; i < MAX_DIFFERENT_USERS; ++i) {
        if (strcmp(database[i].login, username) == 0)
            return &database[i];
    }
    return NULL;
}

dbElem *getDbElementByAssignedIP(m_string ipv4, dbElem *database) {
    for (int i = 0; i < MAX_DIFFERENT_USERS; ++i) {
        if (strcmp(database[i].bound_ip, ipv4) == 0)
            return &database[i];
    }
    return NULL;
}

void *get_client_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *) sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *) sa)->sin6_addr);
}

void process_server() {
    int sock = create_socket();

    dbElem *database = malloc(sizeof(dbElem) * MAX_DIFFERENT_USERS);
    memset(database, 0, sizeof(dbElem) * MAX_DIFFERENT_USERS);

    if (sock < 0) {
        fprintf(stderr, "Server: Error, cannot create socket!\n");
        return;
    }

    printf("Server: server created and listening on port %d.\n", SERVER_PORT);

    while (1) {
        clientData *data = malloc(sizeof(clientData)); // would be freed in thread after its finishing
        data->sockd = accept(sock, (struct sockaddr *) &data->client_sockaddr, &data->client_sockaddr_size);
        data->database = database;
        pthread_t thread_id;
        pthread_attr_t attr;
        pthread_attr_init(&attr);

        printf("Server: got new connection, creating worker thread.\n");
        pthread_create(&thread_id, &attr, handle_request, data);
        printf("Server: created worker thread %u.\n", thread_id);
    }
}

int
check_user_authorisation(m_string client_ip, dbElem *database, m_string login, m_string password, dbElem **element) {
    *element = getDbElementByAssignedIP(client_ip, database);
    if (*element != NULL) {
        return 1;
    } else {
        if (!login || !password)
            return -1;
        *element = getDbElementByUserName(login, database);
        if (*element == NULL)
            return 0;

        if (strcmp((*element)->password, password) != 0)
            return -1;

        strcpy((*element)->bound_ip, login);
    }
    return 1;
}

int getLoginAndPasswordFromRequest(m_string request, m_string*login_ptr, m_string*password_ptr) {
    *login_ptr = *password_ptr = NULL;

    char *auth_ptr = strstr(request, "Authorization: Basic ");

    if (auth_ptr == NULL) {
        return 0;
    }

    char *login_data = auth_ptr + strlen("Authorization: Basic ");
    size_t decoded_login_and_pass_len = 0;

    char *data_end = strchr(login_data, '\n');
    if (data_end == NULL) {
        return 0;
    }

    char *login_and_password = base64_decode(login_data, data_end - login_data,
                                             &decoded_login_and_pass_len);

    if (!login_and_password)
        return 0;

    char *login = malloc(65);
    memset(login, 0, 65);
    char *password = malloc(65);
    memset(password, 0, 65);

    char *delimiter = strchr(login_and_password, ':');
    if (delimiter == NULL) {
        free(login_and_password);
        return 0;
    }

    if (delimiter - login_and_password > 64) {
        free(login_and_password);
        return -1; // login is too long!
    }

    if (decoded_login_and_pass_len - (delimiter + 1 - login_and_password) > 64) {
        free(login_and_password);
        return -2; // password is too long!
    }

    memcpy(login, login_and_password, delimiter - login_and_password);
    memcpy(password, delimiter + 1, decoded_login_and_pass_len);

    printf("USER LOGIN: %s, PASSWORD: %s\n", login, password);
    *login_ptr = login;
    *password_ptr = password;
    return 1; // SUCCESS
}

int update_user_message(dbElem *user_data, m_string msg, int len) {
    if (!msg || strlen(msg) == 0)
        return 0;

    if (strlen(msg) > 2048)
        return -1;
    memset(user_data->message, 0, 2049);
    memcpy(user_data->message, msg, len);
}

void *handle_request(void *data) {
    clientData *client_data = data;

    char ip[17];
    inet_ntop(AF_INET, get_client_addr((struct sockaddr *) &client_data->client_sockaddr), ip, sizeof(ip));

    printf("Worker %u: Established connection with %s beginning work.\n", pthread_self(), ip);

    const int request_buffer_size = 65536;
    char request[request_buffer_size];

    int bytes_recvd = recv(client_data->sockd, request, request_buffer_size - 1, 0);

    if (bytes_recvd < 0) {
        fprintf(stderr, "error recv: %s\n", strerror(errno));
        return NULL;
    }
    request[bytes_recvd] = '\0';

    printf("request:\n%s\n", request);


    char *login, *password;
    int result = getLoginAndPasswordFromRequest(request, &login, &password);
    printf("Worker: received login = %s; password = %s\n", login, password);
    if (result == -1 || result == -2) {
        send_200_message(client_data->sockd, "<h1>Некорректно введены данные пользователя!<br>"
                                             "Максимальная длина логина и пароля - 64 символа!");

        close(client_data->sockd);
        return NULL;
    }

    dbElem *element = NULL;
    result = check_user_authorisation(ip, client_data->database, login, password, &element);

    // This result means that there's record with such login, but password is incorrect
    if (result == -1) {
        printf("DEBUG: USER AUTH RETURNED -1\n");
        send_401_not_authorised(client_data->sockd);
        close(client_data->sockd);
        return NULL;
    }

    // This result means that there's no element in database with such credentials - so creating new one.
    if (result == 0) {
        if (!login || !password) {
            printf("DEBUG: USER AUTH RETURNED 0, but NO LOGIN OR PASSWORD\n");
            send_401_not_authorised(client_data->sockd);
            close(client_data->sockd);
            return NULL;
        }
        element = createNewElement(client_data->database);

        if (!element) {
            printf("Worker: Warning! Database is full, cannot create more users!\n");
            send_401_not_authorised(client_data->sockd);
            close(client_data->sockd);
            return NULL;
        }

        printf("Beginning creating element for new user %s with pass %s\n", login, password);
        strcpy(element->bound_ip, ip);
        strcpy(element->login, login);
        strcpy(element->password, password);
        strcpy(element->message, "Hello, ");
        strcat(element->message, login);
        printf("Created element for user %s with password %s and msg %s\n", element->login, element->password, element->message);
    }

    if (!element) {
        printf("DEBUG: NO ELEMENT!!!!\n");
        send_401_not_authorised(client_data->sockd);
        close(client_data->sockd);
        return NULL;
    }

    // Now assuming, that user is successfully logged in and has valid element

    sHTTPHeader req;
    parse_http_request(request, &req);

    if (req.type == eHTTP_GET) {
        if (strstr(req.path, "/logout/") == req.path || strstr(req.path, "/logout") == req.path) {
            memset(element->bound_ip, 0, 17);
            //send_200_message(client_data->sockd, "Successfully logged out");
            send_401_not_authorised(client_data->sockd);
            close(client_data->sockd);
            return NULL;
        }
        if (strstr(req.path, "/updatemsg/") == req.path) {
            char *msg_begin = req.path + strlen("/updatemsg/");
            char *msg_end = strchr(msg_begin, '/');
            int msg_len = strlen(msg_begin);

            if (msg_end)
                msg_len = (int) (msg_end - msg_begin);

            printf("MESSAGE (len = %d): %s", msg_len, msg_begin);
            update_user_message(element, msg_begin, msg_len);
        }

        send_200_message(client_data->sockd, element->message);
    } else {
        send_404_not_found(client_data->sockd);
    }

    close(client_data->sockd);
    printf("Worker %u: Finished.\n", pthread_self());
    return NULL;
}

void parse_http_request(const char *apstrRequest, sHTTPHeader *apHeader) {
    int type_length = 0;
    char type[255] = {0};
    int index = 0;

    apHeader->type = eHTTP_UNKNOWN;

    sscanf(&apstrRequest[index], "%s", type);

    type_length = strlen(type);
    if (!strcmp(type, "GET")) {
        apHeader->type = eHTTP_GET;
        index += type_length + 1;
        sscanf(&apstrRequest[index], "%s", apHeader->path);
    } else {
        if (!strcmp(type, "POST")) {
            apHeader->type = eHTTP_POST;
            char *pch = strstr(apstrRequest, "\r\n\r\n");
            pch += 4;
            strcpy(apHeader->path, pch);
        }
    }
}

void send_200_message(int sockd, m_string message) {
    char buffer[65536] = {0};
    strcat(buffer, "HTTP/1.1 200 OK\n\n");
    strcat(buffer, "<html><body><h1>");
    strcat(buffer, message);
    strcat(buffer, "</h1></body></html>");
    int len = strlen(buffer);
    send(sockd, buffer, len, 0);
}

void send_403_forbidden(int sockd) {
    const char *buffer = "HTTP/1.1 403 \n\n<h1>Forbidden!<br>Seems like you tried to access data without permission :/</h1>";
    int len = strlen(buffer);
    send(sockd, buffer, len, 0);
}

void send_404_not_found(int sockd) {
    const char *buffer = "HTTP/1.1 404 \n\n<h1>Sorry, nothing was found on your request :(</h1>";
    int len = strlen(buffer);
    send(sockd, buffer, len, 0);
}

void send_401_not_authorised(int sockd) {
    const char *buffer = "HTTP/1.1 401\nWWW-Authenticate: Basic realm=0JTQsNGA0L7QstCwLCDQsdC+0LXRhiEg0JfQsNC70L7Qs9C40L3RjNGB0Y8sINGH0YLQvtCx0Ysg0YPQstC40LTQtdGC0Ywg0YHQvtC+0LHRidC10L3QuNC1\n\n";
    int len = strlen(buffer);
    send(sockd, buffer, len, 0);
}