
#include <iostream>
#include <pcap.h>
#include <libnet.h>
#include "ethernet.cpp"
//int turnout_pcap(struct pcap_pkthdr *e_hdr ,unsigned short port);
using namespace std;
//reperence :http://www.tcpdump.org/pcap.html
int ethernet(struct libnet_ethernet_hdr *e_hdr);
int ipv4(struct libnet_ipv4_hdr *ip_hdr);
int tcp(struct libnet_tcp_hdr *tcp_hdr);

int main(void)
{
    char *dev,error_buf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    pcap_t *handle;
    struct pcap_pkthdr *header; //actual packet

    dev=pcap_lookupdev(error_buf);//search device
    
    if(dev==NULL)
    {
        fprintf(stderr,"No such device:%s\n",error_buf);
        return 2;
    }


    bpf_u_int32 net;
    bpf_u_int32 mask;
    if (pcap_lookupnet(dev, &net, &mask, error_buf) == -1)
        return 2;

    handle=pcap_open_live(dev,10000,1,0,error_buf); //dev open

    char filter[]="port 80";
    struct bpf_program ft;

    if(pcap_compile(handle,&ft,filter,0,net)==-1)
        return 2;
    if(pcap_setfilter(handle,&ft)==-1)
        return 2;

    if(handle==NULL)
    {
        fprintf(stderr,"Couldn't open device:%s",error_buf);
        return 2;
    }

    struct libnet_ethernet_hdr *e_hdr;
    struct libnet_ipv4_hdr *ip_hdr;
    struct libnet_tcp_hdr *tcp_hdr;

    while(true)
    {
        pcap_next_ex(handle,&header,&packet);
        e_hdr=(struct libnet_ethernet_hdr *)packet;

        if(ethernet(e_hdr))
        {
            ip_hdr=(struct libnet_ipv4_hdr *) (packet+sizeof(struct libnet_ethernet_hdr));
            tcp_hdr=(struct libnet_tcp_hdr *)(packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));
            if(ipv4(ip_hdr)==0&&tcp(tcp_hdr)==0)
                break;
        }

    }

    pcap_close(handle);//end

    return 0;
}


int ethernet(struct libnet_ethernet_hdr *e_hdr)
{
    if(ntohs(e_hdr->ether_type)==ETHERTYPE_IP)
    {

        printf("D_MAC:%02x-%02x-%02x-%02x-%02x-%02x\n",e_hdr->ether_dhost[0],e_hdr->ether_dhost[1],e_hdr->ether_dhost[2],e_hdr->ether_dhost[3],e_hdr->ether_dhost[4],e_hdr->ether_dhost[5]);
        printf("S_MAC:%02x-%02x-%02x-%02x-%02x-%02x\n",e_hdr->ether_shost[0],e_hdr->ether_shost[1],e_hdr->ether_shost[2],e_hdr->ether_shost[3],e_hdr->ether_shost[4],e_hdr->ether_shost[5]);
        return 1;
    }
    return 0;
}

int ipv4(struct libnet_ipv4_hdr *ip_hdr)
{
 //   printf("D_IP:%s\n",inet_ntoa(ip_hdr->ip_dst));
 printf("D_IP:%s\n",inet_ntop(ip_hdr->ip_dst));
 //inet_ntoa is weak for multiple threads
//so it doesn't fit. instead inet_ntoa to inet_ntop
    printf("S_IP:%s\n",inet_ntop(ip_hdr->ip_src));
    return 0;
}

int tcp(struct libnet_tcp_hdr *tcp_hdr)
{
    printf("D_port:%u\n",tcp_hdr->th_dport);
    printf("S_port:%u\n",tcp_hdr->th_sport);
    return 0;
}


