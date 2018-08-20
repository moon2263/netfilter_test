#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <regex.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define IPPROTO_TCP 0x06
#define ETHERHEADER_SIZE 14
#pragma pack(push,1)
struct ip
{
	unsigned char ip_header_len:4;
	unsigned char ip_version:4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_frag_offset:5;
	unsigned char ip_more_fragment:1;
	unsigned char ip_dont_fragment:1;
	unsigned char ip_reserved_zero:1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
};


struct tcp
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns:1;
	unsigned char reserved_part1:3;
	unsigned char data_offset:4;
	unsigned char fin:1;
	unsigned char syn:1;
	unsigned char rst:1;
	unsigned char psh:1;
	unsigned char ack:1;
	unsigned char urg:1;
	unsigned char ecn:1;
	unsigned char cwr:1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};

#pragma pack(pop)

int isBlock(char * domain)
{
	char check[100];
	FILE * fp = fopen("list.txt","r");
	if(fp==NULL)
	{
		printf("no list.txt");
		exit(-1);
	}
	
	fscanf(fp,"%100s\n",check);
	if(!strcmp(domain,check))
		return 1;
	return 0;	

}

int inspect(u_char * buf, int size) {
	int i,err;	
	int match;
	regex_t preg;
	regmatch_t pmatch[2]; 
	size_t nmatch = 2;
	const char *str_request = (char *)buf;
	const char * str_regex = "Host:\\s*\\([a-z0-9]\\+[a-z0-9.-]*.[a-z]\\{2,\\}\\)";

	err = regcomp(&preg, str_regex,0);
	if(err!=0)
	{
		char error_message[0x1000];
		regerror(err,&preg,error_message,0x1000);
		printf("Regex error compiling %s : %s\n", str_regex,error_message);
		return 1;

	}
	if (err == 0)
	{
		char domain[100];
		match = regexec(&preg, str_request, nmatch, pmatch, 0);
		nmatch = preg.re_nsub;
		regfree(&preg);
		if (match == 0)
		{
		//	printf("\"%.*s\"\n", pmatch[1].rm_eo - pmatch[1].rm_so, &str_request[pmatch[1].rm_so]);
			strncpy(domain, &str_request[pmatch[1].rm_so], pmatch[1].rm_eo - pmatch[1].rm_so);
			if(isBlock(domain))
			{
				printf("%s\n",domain);
				return 1;
			}
			else
				return 0;
		}
		else if (match == REG_NOMATCH)
		{
			printf("unmatch\n");
		}
	}
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int ret;
	struct ip * ip_header;
	struct tcp * tcp_header;
	int ip_tcp_off=0, total_len=0;
	int tcp_data_off=0, data_len=0;
	u_char *data;

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
	{
		ip_header = (struct ip*)data;
		ip_tcp_off = ip_header->ip_header_len * 4;
		if(ip_header->ip_protocol == IPPROTO_TCP)
		{
			tcp_header = (struct tcp*)(data+ip_tcp_off);
			tcp_data_off = tcp_header->data_offset * 4;
			if((ntohs(tcp_header->dest_port) == 80 || ntohs(tcp_header->dest_port) == 8080) && 
					tcp_header->psh==1 && tcp_header->ack==1)
			{
				data_len = ret-ip_tcp_off-tcp_data_off;
				if(inspect((u_char*)tcp_header+tcp_data_off,data_len))
					return 1;
				else
					return 0;

			}
		}
	}
	return 0;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
	struct nfqnl_msg_packet_hdr *ph;
	int id;
	ph = nfq_get_msg_packet_hdr(nfa);
	if(ph)
	{
		id=ntohl(ph->packet_id);
	}
	if(print_pkt(nfa))
	{
		printf("DROP!!\n");
		return nfq_set_verdict(qh,id,NF_DROP,0,NULL);
	}
	else
	{
		printf("ACCEPT!!\n");
		return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);
	}
}


int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 *      * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

