#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <dirent.h>

#define MAX_CLIENTS  10
#define MAXLEN 1024
#define BUFLEN 512

void error(char *msg)
{
    perror(msg);
    exit(1);
}

//functie care intra in directorul dir si verifica daca exista fisierul file
int printdir(char *dir, int depth, char *file)
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;
    int ok = 0;
    if((dp = opendir(dir)) == NULL) {
        return 0;
    }
    chdir(dir);
    while((entry = readdir(dp)) != NULL) {
        lstat(entry->d_name,&statbuf);
        //printf("%*s%s\n",depth,"",entry->d_name);

        if(strcmp(entry->d_name, file) == 0)
          ok = 1;      
    }

   // chdir("..");
    closedir(dp);

    return ok;
}

//functie din laborator 
ssize_t Readline(int sockd, void * vptr, size_t maxlen) {
    ssize_t n, rc;
    char c, * buffer;

    buffer = vptr;

    for (n = 1; n < maxlen; n++) {
        if ((rc = read(sockd, & c, 1)) == 1) { * buffer++ = c;
            if (c == '\n')
                break;
        } else if (rc == 0) {
            if (n == 1)
                return 0;
            else
                break;
        } else {
            if (errno == EINTR)
                continue;
            return -1;
        }
    }

    * buffer = 0;
    return n;
}

//functie din laborator in care am adaugat socketul i pentru a trimite raspunsul
//spre client 
int send_command(int sockfd, char sendbuf[], char * expected, int i) {
  char recvbuf[MAXLEN];
  int nbytes;
  char CRLF[3];

  //trimitere comanda
  CRLF[0] = 13; CRLF[1] = 10; CRLF[2] = 0;
  strcat(sendbuf, CRLF);
  printf("Trimit: %s", sendbuf);
  write(sockfd, sendbuf, strlen(sendbuf));
  nbytes = Readline(sockfd, recvbuf, MAXLEN - 1);
  recvbuf[nbytes] = 0;
  printf("Am primit: %s", recvbuf);
  send(i, recvbuf, nbytes, 0);
    
  if (strstr(recvbuf, expected) != recvbuf) {
    return 1;
  }

  return 0;
}

//extrag primul cuvant din sir si verific daca este metoda
int validare_cerere(char *buf, char mesaj[])
{
  char aux[BUFLEN], *method;
  strcpy(aux, buf);

  method = strtok(aux, " :");
  //printf(">%s< \n", method);

  if (strcmp(method, "GET") == 0)
    return 1;
  else
  if (strcmp(method, "POST") == 0)
    return 1;
  else
  if (strcmp(method, "HEAD") == 0)
    return 1;
  else
    strcpy(mesaj, "400 Bad Request\n");
  
  return 0;

}

//extrag hostul , portul si calea folosing functii strstr in principiu
//si salvez portul 80 in caz de lipseste
void parsare_url(char *buf, char host[], char port[], char cale[])
{
  char aux[BUFLEN], *aux2;
  strcpy(aux, buf);

  aux2 = strtok(aux, " :");
  aux2 = strtok(NULL, " \n");
  //printf(">%s<\n",aux2);
  if(aux2[0] == '/') // cazul in care calea se afla imediat dupa medota
    strcpy(cale, aux2);
  else { //cazul in care hostul se afla imediat dupa metoda
      strcpy(host, aux2);
      aux2 = strstr(aux2, ".");
      aux2 = strstr(aux2, "/");
      
      strcpy(cale, aux2);
      
      printf(">%ld %ld<\n",strlen(cale), strlen(host));
      host[strlen(host) - strlen(cale)] = '\0';

      if(host[0] == 'h') {
        aux2 = strstr(host, "/");
        strcpy(host, aux2 + 2);
      }


      aux2 = strstr(host, ".");
      aux2 = strstr(aux2, ":");

      if(aux2 != NULL) {
        aux2 += 1;
        strcpy(port, aux2);
        host[strlen(host) - strlen(port) - 1] = '\0';

      }
      else
         strcpy(port, "80");

      return;
  }
  strcpy(aux, buf);

  //salvez hostul daca gasesc un substring "Host: "
  aux2 = strstr(aux, "Host: ");
  aux2 = strtok(aux2, " ");
  aux2 = strtok(NULL, " ");

  aux2[strlen(aux2) - 2] = '\0';
  strcpy(host, aux2);
  
  aux2 = strstr(aux2, ".");
  aux2 = strstr(aux2, ":");

  if(aux2 != NULL){
    aux2 += 1;
    strcpy(port, aux2);
    host[strlen(host) - strlen(port) - 1] = '\0';
  }
  else
    strcpy(port, "80");

  aux2 = strstr(host, "w");
  strcpy(host, aux2);
}

//functie care construieste dintr-un string toate directoarele
// ex: "/dir1/dir2/dir3" o sa construiasca directoarele exact cum se vede
void _mkdir(char *dir) 
{
  char tmp[256];
  char *p = NULL;
  size_t len;
     
  snprintf(tmp, sizeof(tmp),"%s",dir);
  len = strlen(tmp);
  if(tmp[len - 1] == '/')
    tmp[len - 1] = 0;
      
  for(p = tmp + 1; *p; p++)
    if(*p == '/') {
      *p = 0;
      mkdir(tmp, S_IRWXU);
      *p = '/';
    }

 mkdir(tmp, S_IRWXU);
}

int main(int argc, char *argv[])
{
  int sockfd, newsockfd, portno, server_sock;
  socklen_t clilen;
  size_t nread;
  char buffer[BUFLEN], msg[20], recvbuf[MAXLEN], send_client_buff[BUFLEN];
  char host[100], nr_port[10], cale[100], file[150];
  FILE *cache_write, *cache_read; // file descriptori pentru citire / scriere din/in cache

  struct sockaddr_in serv_addr, cli_addr, next_addr;
  struct hostent *server;

  int n, i;
  fd_set read_fds;  
  fd_set tmp_fds;  
  int fdmax;    

  if (argc < 2) {
      fprintf(stderr,"Usage : %s port\n", argv[0]);
      exit(1);
  }

  //eliberarea cache'ului la pornirea programului
  system("rm -rf cache");

  FD_ZERO(&read_fds);
  FD_ZERO(&tmp_fds);

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) 
    error("ERROR opening socket");

  portno = atoi(argv[1]);

  memset((char *) &serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = PF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;  
  serv_addr.sin_port = htons(portno);

  if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr)) < 0) 
    error("ERROR on binding");

  listen(sockfd, MAX_CLIENTS);

  FD_SET(sockfd, &read_fds);
  FD_SET(0, &read_fds);
  fdmax = sockfd;

  while (1) {
    tmp_fds = read_fds; 
    
    if (select(fdmax + 1, &tmp_fds, NULL, NULL, NULL) == -1) 
      error("ERROR in select");

    for (i = 0; i <= fdmax; i++) {
      if (FD_ISSET(i, &tmp_fds)) {
          if (i == sockfd) {
            clilen = sizeof(cli_addr);

            if ((newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen)) == -1) {
              error("ERROR in accept");
            }
            else {
              FD_SET(newsockfd, &read_fds);
              
              if (newsockfd > fdmax) {
                fdmax = newsockfd;
              }
            }

            //printf("Noua conexiune de la %s, port %d, socket_client %d\n ",
              //      inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port), newsockfd);
            memset(buffer, 0, BUFLEN);
            sprintf(buffer, "S-a conectat %d\n", newsockfd);

          }
          else {
            memset(buffer, 0, BUFLEN);
            
            if ((n = recv(i, buffer, sizeof(buffer), 0)) <= 0) {
              if (n == 0) {
                printf("selectserver: socket %d hung up\n", i);
              } 
              else {
                error("ERROR in recv");
              }

              close(i);
              FD_CLR(i, &read_fds); 
            }
            else {

              printf ("Am primit de la clientul de pe socketul %d, mesajul: %s\n", i, buffer);
          
              //validez cererea si o trimit mai departe daca este buna
              //in caz contrar trimit clientului mesaj de eroare
              if (validare_cerere(buffer, msg) < 1) {
                msg[17] = '\0';
                send(i, msg, sizeof(msg), 0);
              }

              //parsez url pentru a afla hostul , portul si calea catre server
              parsare_url(buffer, host, nr_port, cale);
            
              //charul file este locul unde stochez cache'ul
              memset(file, 0 , sizeof(file));
              strcat(file, "./cache/");
              strcat(file, host);
              strcat(file, cale);
              
              if(printdir(file, 0, "file") == 0) { //daca informatia dorita nu se afla in cache
                                                   //atunci trimit cererea catre server nu inainte
                                                   //sa deschid o conexiune cu acesta

                server_sock = socket(AF_INET, SOCK_STREAM, 0);
                if (server_sock < 0) error("ERROR opening socket");


                server = gethostbyname(host);
                if (server == NULL) error("ERROR, no such host");

                memset(&next_addr,0,sizeof(next_addr));
                next_addr.sin_family = AF_INET;
                next_addr.sin_port = htons(atoi(nr_port));
                memcpy(&next_addr.sin_addr.s_addr,server->h_addr,server->h_length);

                if (connect(server_sock,(struct sockaddr *)&next_addr,sizeof(next_addr)) < 0)
                  error("ERROR connecting");

                if( send_command(server_sock, buffer, "HTTP/1.1 200 OK", i) == 0) {
                  //daca am primit OK de la server atunci incep sa scriu in cache
                  //printf("intra\n");
                  memset(file, 0 , sizeof(file));
                  strcat(file, "./cache/");
                  strcat(file, host);
                  strcat(file, cale);
                  _mkdir(file);

                  strcat(file, "file");

                  cache_write = fopen(file ,"w");
                  //printf(">%s<\n",file);

                  while((nread = Readline(server_sock, recvbuf, MAXLEN -1))>0) {
                    //cat timp primesc mesaje de la server le bag in cache 
                    // si le trimit in acelasi timp catre client
                    fprintf(cache_write, "%s", recvbuf);
                    //printf("%s",recvbuf);
                    send(i, recvbuf, nread, 0);
                    memset(recvbuf, 0, sizeof(recvbuf));
                   }

                  fclose(cache_write);
                  FD_CLR(i, &read_fds);
                  close(i);

                }

              }
              else {//cazul in care informatia se afla in cache 
                    //deschid fisierul si incep sa trimit catre client
                cache_read = fopen("file", "r");
         
                if(cache_read)
                  while(fgets(send_client_buff, BUFLEN, cache_read) != NULL)
                    send(i, send_client_buff, sizeof(send_client_buff), 0);
                    //printf("%s",send_client_buff);

                fclose(cache_read);
                FD_CLR(i, &read_fds);
                close(i);
              }
            }
          }
      }
    }
}

close(sockfd);
return 0;
}

