#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>



#define ARP_PACKET_LEN (8 + 6 + 4 + 6 + 4)
enum {
  ARP_PACKET_HW_TYPE = 0,
  ARP_PACKET_IP_TYPE = 2,
  ARP_PACKET_HW_LEN  = 4,
  ARP_PACKET_IP_LEN  = 5,
  ARP_PACKET_OPCODE  = 6,
  ARP_PACKET_SRC_HW  = 8,
  ARP_PACKET_SRC_IP  = 14,
  ARP_PACKET_TGT_HW  = 18,
  ARP_PACKET_TGT_IP  = 24
};

#define ARP_HW_TYPE_ETHERNET 1
#define ARP_IP_TYPE_IPV4 0x0800
#define ARP_OPCODE_REQ 1
#define ARP_OPCODE_REP 2

const uint8_t ARP_HEADER[] = {
  0x00, 0x01, // Hardware type
  0x08, 0x00, // Protocol type
  0x06,       // HW address length
  0x04,       // IP address length
  0x00        // Opcode high byte

  // 1 byte   // Opcode low byte
  // 6 bytes  // Sender HW address
  // 4 bytes  // Sender IP address
  // 6 bytes  // Should be 0
  // 4 bytes  // Target IP address
};

#define MACLEN 6
typedef uint8_t macaddr[MACLEN];
typedef uint32_t ip4addr;


struct arp_state {
  int sock;
  int ifindex;
  macaddr ifmac;
};



static int arp_loop(const char *ifname);
static int find_if(int socket, const char *name, macaddr mac);
static void print_arp(const char *data, int len);
static void send_arp_req(struct arp_state state, ip4addr src, ip4addr target);


int main(int argc, const char *argv[])
{
  printf("ARP Test\n");

  arp_loop("eth0");

  return 0;
}



static int arp_loop(const char *ifname)
{
  int ret = 0;
  struct arp_state state;
  memset(&state, 0, sizeof(state));
  
  state.sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));

  if(state.sock <= 0)
  {
    printf("Could not create socket %d\n", errno);
    goto end;
  }

  {
    state.ifindex = find_if(state.sock, ifname, state.ifmac);
    if(state.ifindex <= 0)
    {
      printf("Could not find interface %s\n", ifname);
      goto end;
    }

    struct sockaddr_ll ba;
    memset(&ba, 0, sizeof(ba));
    ba.sll_family = AF_PACKET;
    ba.sll_protocol = htons(ETH_P_ARP);
    ba.sll_ifindex = state.ifindex;

    if(bind(state.sock, (const struct sockaddr *)&ba, sizeof(ba)) != 0)
    {
      printf("Could not bind to interface %s\n", ifname);
      goto end;
    }

    printf("Bound to %d %02x:%02x:%02x:%02x:%02x:%02x\n",
            state.ifindex,
            state.ifmac[0], state.ifmac[1], state.ifmac[2],
            state.ifmac[3], state.ifmac[4], state.ifmac[5]);
  }

  {
    // This doesn't appear to be needed
    //const unsigned int yes = 1;
    //setsockopt(state.sock, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));

    ip4addr target = 0;
    if(inet_pton(AF_INET, "172.25.25.10", &target) == 1)
      send_arp_req(state, target, target);
  }

  struct sockaddr_ll raddr;
  int raddr_size = 0;
  unsigned char data[2000];
  
  for(;;)
  {
    memset(&raddr, 0, sizeof(raddr));
    raddr_size = sizeof(raddr);
    memset(&data, 0, sizeof(data));

    errno = 0;
    int r = recvfrom(state.sock, data, sizeof(data), 0, (struct sockaddr *)&raddr, &raddr_size);

    if(r <= 0 || raddr_size < sizeof(struct sockaddr_ll) || raddr.sll_halen != 6)
    {
      printf("recv error %d %d\n", errno, r);
      goto end;
    }

    printf("r %d %d %02x:%02x:%02x:%02x:%02x:%02x\n", r, raddr.sll_halen,
            raddr.sll_addr[0],raddr.sll_addr[1],raddr.sll_addr[2],
            raddr.sll_addr[3],raddr.sll_addr[4],raddr.sll_addr[5]);
    
    print_arp(data, r);
  }

  ret = 1;

end:

  if(state.sock > 0)
    close(state.sock);
  
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
  
  if(memcmp(data, ARP_HEADER, sizeof(ARP_HEADER)))
    goto invalid;
  
  int opcode = data[ARP_PACKET_OPCODE+1];
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


static void send_arp_req(struct arp_state state, ip4addr src, ip4addr target)
{
  uint8_t data[ARP_PACKET_LEN];

  memset(data, 0, sizeof(data));
  memcpy(data, ARP_HEADER, sizeof(ARP_HEADER));
  data[ARP_PACKET_OPCODE+1] = ARP_OPCODE_REQ;

  memcpy(&(data[ARP_PACKET_SRC_IP]), &src, 4);
  memcpy(&(data[ARP_PACKET_SRC_HW]), &state.ifmac, 6);
  memcpy(&(data[ARP_PACKET_TGT_IP]), &target, 4);

  struct sockaddr_ll to;
  memset(&to, 0, sizeof(to));
  to.sll_family = AF_PACKET;
  to.sll_protocol = htons(ETH_P_ARP);
  to.sll_ifindex = state.ifindex;
  to.sll_halen = 6;
  memset(to.sll_addr, 0xFF, 6);

  int r = sendto(state.sock, data, ARP_PACKET_LEN, 0, (const struct sockaddr *)&to, sizeof(to));

  if(r != ARP_PACKET_LEN)
    printf("Send error %d %d\n", r, errno);
}


