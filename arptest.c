#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>



#define ARP_PACKET_LEN (8 + 6 + 4 + 6 + 4)
#define ARP_PACKET_HW_TYPE 0
#define ARP_PACKET_IP_TYPE 2
#define ARP_PACKET_HW_LEN 4
#define ARP_PACKET_IP_LEN 5
#define ARP_PACKET_OPCODE 6
#define ARP_PACKET_SRC_HW 8
#define ARP_PACKET_SRC_IP 14

#define ARP_HW_TYPE_ETHERNET 1
#define ARP_IP_TYPE_IPV4 0x0800
#define ARP_OPCODE_REQ 1
#define ARP_OPCODE_REP 2

#define MACLEN 6
typedef unsigned char macaddr[MACLEN];



static int arp_loop(const char *ifname);
static int find_if(int socket, const char *name, macaddr mac);
static void print_arp(const char *data, int len);


int main(int argc, const char *argv[])
{
  printf("ARP Test\n");

  arp_loop("eth0");

  return 0;
}



static int arp_loop(const char *ifname)
{
  int ret = 0;
  int s = 0;
  
  s = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));

  if(s <= 0)
  {
    printf("Could not create socket %d\n", errno);
    ret = 0;
    goto end;
  }

  

  {
    macaddr ifmac = {0, 0, 0, 0, 0, 0};
    int ifindex = find_if(s, ifname, ifmac);
    if(ifindex <= 0)
    {
      printf("Could not find interface %s\n", ifname);
      ret = 0;
      goto end;
    }

    struct sockaddr_ll ba;
    memset(&ba, 0, sizeof(ba));
    ba.sll_family = AF_PACKET;
    ba.sll_protocol = htons(ETH_P_ARP);
    ba.sll_ifindex = ifindex;

    if(bind(s, (const struct sockaddr *)&ba, sizeof(ba)) != 0)
    {
      printf("Could not bind to interface %s\n", ifname);
      ret = 0;
      goto end;
    }

    printf("Bound to %d %02x:%02x:%02x:%02x:%02x:%02x\n",
            ifindex,
            ifmac[0], ifmac[1], ifmac[2], ifmac[3], ifmac[4], ifmac[5]);
  }

  unsigned int yes = 1;
  setsockopt(s, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));

  struct sockaddr_ll raddr;
  int raddr_size = 0;
  unsigned char data[2000];
  
  for(;;)
  {
    memset(&raddr, 0, sizeof(raddr));
    raddr_size = sizeof(raddr);
    memset(&data, 0, sizeof(data));

    int r = recvfrom(s, data, sizeof(data), 0, (struct sockaddr *)&raddr, &raddr_size);


    if(r <= 0 || raddr_size < sizeof(struct sockaddr_ll) || raddr.sll_halen != 6)
    {
      printf("recv error %d %d\n", errno, r);
      break;
    }

    printf("r %d %d %02x:%02x:%02x:%02x:%02x:%02x\n", r, raddr.sll_halen,
            raddr.sll_addr[0],raddr.sll_addr[1],raddr.sll_addr[2],
            raddr.sll_addr[3],raddr.sll_addr[4],raddr.sll_addr[5]);
    
    print_arp(data, r);
  }



end:

  if(s > 0)
    close(s);
  
  return ret;
}


static int find_if(int socket, const char *name, macaddr mac)
{
  int ret = 0;
  struct ifreq ifs;

  memset(&ifs, 0, sizeof(ifs));
  strncpy(ifs.ifr_name, name, IFNAMSIZ-1);

  if(ioctl(socket, SIOCGIFINDEX, &ifs) == 0)
    ret = ifs.ifr_ifindex;
  
  if(ret && mac)
  {
    memset(&ifs, 0, sizeof(ifs));
    strncpy(ifs.ifr_name, name, IFNAMSIZ-1);

    if(ioctl(socket, SIOCGIFHWADDR, &ifs) == 0)
      memcpy(mac, ifs.ifr_hwaddr.sa_data, MACLEN);
    else
      ret = 0;
  }

  return ret;
}



static void print_arp(const char *data, int len)
{
  if(len < ARP_PACKET_LEN)
    goto invalid;
  
  int hw_type = (data[ARP_PACKET_HW_TYPE] << 8) + data[ARP_PACKET_HW_TYPE+1];
  int ip_type = (data[ARP_PACKET_IP_TYPE] << 8) + data[ARP_PACKET_IP_TYPE+1];
  if(hw_type != ARP_HW_TYPE_ETHERNET || ip_type != ARP_IP_TYPE_IPV4)
    goto invalid;
  
  if(data[ARP_PACKET_HW_LEN] != 6 || data[ARP_PACKET_IP_LEN] != 4)
    goto invalid;
  
  int opcode = (data[ARP_PACKET_OPCODE] << 8) + data[ARP_PACKET_OPCODE+1];
  if(opcode != ARP_OPCODE_REQ && opcode != ARP_OPCODE_REP)
    goto invalid;
  
  printf("ARP: %s %d.%d.%d.%d -> %02x:%02x:%02x:%02x:%02x:%02x\n",
          opcode == ARP_OPCODE_REQ ? "REQ" : "RES",
          data[ARP_PACKET_SRC_IP], data[ARP_PACKET_SRC_IP+1], data[ARP_PACKET_SRC_IP+2], data[ARP_PACKET_SRC_IP+3],
          data[ARP_PACKET_SRC_HW], data[ARP_PACKET_SRC_HW+1], data[ARP_PACKET_SRC_HW+2],
          data[ARP_PACKET_SRC_HW+3], data[ARP_PACKET_SRC_HW+4], data[ARP_PACKET_SRC_HW+5]);

  return;

invalid:
  printf("ARP: Invalid\n");
}



