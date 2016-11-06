/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */

/* TODO: Add helper functions here... */

/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
  /* TODO: Fill this in */
  time_t currtime = time(NULL);
  if(difftime(currtime, req->sent)>1.0){
    if(req->times_sent>=5){

    }
    else{
      uint8_t *newpacket = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
      sr_ethernet_hdr_t newetheader[1];
      int i;
      for(i=0;i<6;i++){
        newetheader[0].ether_dhost[i]=255;
      }
      struct sr_if* ainterface =  sr_get_interface(sr, req->packets->iface);
      unsigned char macaddr[ETHER_ADDR_LEN];
      memcpy(macaddr, ainterface->addr, ETHER_ADDR_LEN);
      uint32_t newip = ainterface->ip;

      memcpy(newetheader[0].ether_shost, macaddr, ETHER_ADDR_LEN);
      newetheader[0].ether_type=htons(0x0806);
      memcpy(newpacket, newetheader, sizeof(sr_ethernet_hdr_t));
      
      sr_arp_hdr_t newarpheader[1];

      memcpy(newarpheader[0].ar_sha, macaddr, ETHER_ADDR_LEN);
      newarpheader[0].ar_sip = newip;
      
      for(i=0;i<6;i++){
        newarpheader[0].ar_tha[i]=255;
      }
      newarpheader[0].ar_tip =  htonl(req->ip);
      newarpheader[0].ar_hrd = htons(arp_hrd_ethernet);
      newarpheader[0].ar_pln = sizeof(uint32_t);
      newarpheader[0].ar_pro = htons(2048);
      newarpheader[0].ar_hln = ETHER_ADDR_LEN;
      newarpheader[0].ar_op = htons(arp_op_request);
      memcpy(newpacket+sizeof(sr_ethernet_hdr_t), newarpheader, sizeof(sr_arp_hdr_t));
      sr_send_packet(sr , newpacket , sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) , req->packets->iface);      
      req->sent = currtime;
      req->times_sent++;
    }
  }  
}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* TODO: (opt) Add initialization code here */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d\n",len);

  /* TODO: Add forwarding logic here */
  sr_ethernet_hdr_t *etheader = (sr_ethernet_hdr_t *)packet;
  
  if(ntohs(etheader->ether_type) ==0x800){
    printf("HI FUck off\n");
    sr_ip_hdr_t *ipheader = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    struct sr_rt* temp1 = sr->routing_table;
    struct sr_rt* rt = sr->routing_table;
    uint32_t destip = ntohl(ipheader->ip_dst);
    
    uint32_t lmatch;
    
    /*print_hdrs(packet,len);*/
    if(ipheader->ip_ttl!=0)ipheader->ip_ttl--;
    ipheader->ip_sum = 0;
    ipheader->ip_sum = cksum(ipheader, sizeof(sr_ip_hdr_t));

    if(ipheader->ip_ttl==0){
      printf("JOHN\n");
      uint8_t *icmppacket = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
      sr_ethernet_hdr_t newetheader[1];
      struct sr_if* ppinterface =  sr_get_interface(sr, interface);
      
      memcpy(newetheader[0].ether_dhost,etheader->ether_shost, ETHER_ADDR_LEN);
      memcpy(newetheader[0].ether_shost,etheader->ether_dhost, ETHER_ADDR_LEN);
      newetheader[0].ether_type = htons(ethertype_ip);
      
      sr_ip_hdr_t newipheader[1];

      memcpy(icmppacket, newetheader, sizeof(sr_ethernet_hdr_t));
      memcpy(newipheader, ipheader , sizeof(sr_ip_hdr_t));

      newipheader[0].ip_ttl = 64;
      newipheader[0].ip_p = ip_protocol_icmp;
      newipheader[0].ip_dst = ipheader->ip_src;
      newipheader[0].ip_src = (ppinterface->ip);
      newipheader[0].ip_len = ntohs(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
      newipheader[0].ip_sum=0;
      newipheader[0].ip_sum = cksum(newipheader, sizeof(sr_ip_hdr_t));
      memcpy(icmppacket+sizeof(sr_ethernet_hdr_t), newipheader, sizeof(sr_ip_hdr_t));

      sr_icmp_t3_hdr_t newicmpheader[1];
      newicmpheader[0].icmp_type=11;
      newicmpheader[0].icmp_code=0;
      newicmpheader[0].unused = 0;
      memcpy(newicmpheader[0].data, ipheader, ICMP_DATA_SIZE);

      newicmpheader[0].icmp_sum=0;
      newicmpheader[0].icmp_sum=cksum(newicmpheader, sizeof(sr_icmp_t3_hdr_t));

      memcpy(icmppacket+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t), newicmpheader, sizeof(sr_icmp_t3_hdr_t));
      print_hdrs(packet, len);
      sr_send_packet(sr , icmppacket , sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t)+sizeof(sr_icmp_t3_hdr_t) , interface);      
      printf("icmp sent\n");
      print_hdrs(icmppacket, sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
      return;
    }
    int check = 0;
    while(temp1 != NULL)
    {
      uint32_t a = htonl(temp1->dest.s_addr) & htonl(temp1->mask.s_addr);
      uint32_t b = htonl(temp1->mask.s_addr) & destip; 
      struct sr_if* ppinterface =  sr_get_interface(sr, temp1->interface);
      if(destip==ntohl(ppinterface->ip)){
        check=1;
        break;
        sr_icmp_hdr_t *icmpheader = (sr_icmp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
        icmpheader->icmp_type = 0;
        icmpheader->icmp_code =0;
        icmpheader->icmp_sum = 0;
        icmpheader->icmp_sum = cksum(icmpheader, sizeof(icmpheader));

        ipheader->ip_dst = (ipheader->ip_src);
        ipheader->ip_src = (ppinterface->ip);
        ipheader->ip_sum =0;
        ipheader->ip_sum =cksum(ipheader, sizeof(sr_ip_hdr_t));
        memcpy(etheader->ether_dhost,etheader->ether_shost, ETHER_ADDR_LEN);
        memcpy(etheader->ether_shost, sr_get_interface(sr,interface)->addr, ETHER_ADDR_LEN);
        /*print_hdrs(packet,len);*/
        sr_send_packet(sr , packet , len , interface);
        return;
      }
      if((a==b)){
        if((lmatch <= htonl(temp1->mask.s_addr))){
          lmatch = htonl(temp1->mask.s_addr);
          rt = temp1;  
        }
      }
      temp1 = temp1->next;
    }

    struct sr_if* pinterface =  sr_get_interface(sr, rt->interface);
    char iface[sr_IFACE_NAMELEN];
    memcpy(iface, pinterface->name, sr_IFACE_NAMELEN);
    unsigned char *curmacaddr = (unsigned char *)malloc(ETHER_ADDR_LEN);
    memcpy(curmacaddr, pinterface->addr, ETHER_ADDR_LEN);

    struct sr_arpentry *arp = sr_arpcache_lookup(&(sr->cache), ntohl((rt->dest).s_addr ));
    if(arp!=NULL){
      char destmacaddr[6];
      memcpy(destmacaddr, arp->mac, 6);
      printf("sent packet\n");
      memcpy(etheader->ether_shost, curmacaddr, ETHER_ADDR_LEN);
      memcpy(etheader->ether_dhost, destmacaddr, ETHER_ADDR_LEN);
      print_hdrs(packet, len);
      sr_send_packet(sr , packet , len , iface);

      }
    else if(arp==NULL){
      struct sr_arpreq* request = sr_arpcache_queuereq(&(sr->cache), destip, packet, len, iface);
      handle_arpreq(sr, request);
    }
    if(check&& (len>sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t))){
      uint8_t *icmppacket = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
      sr_ethernet_hdr_t newetheader[1];
      struct sr_if* ppinterface =  sr_get_interface(sr, interface);
      
      memcpy(newetheader[0].ether_dhost,etheader->ether_shost, ETHER_ADDR_LEN);
      memcpy(newetheader[0].ether_shost,etheader->ether_dhost, ETHER_ADDR_LEN);
      newetheader[0].ether_type = htons(ethertype_ip);
      
      sr_ip_hdr_t newipheader[1];

      memcpy(icmppacket, newetheader, sizeof(sr_ethernet_hdr_t));
      memcpy(newipheader, ipheader , sizeof(sr_ip_hdr_t));

      newipheader[0].ip_ttl = 64;
      newipheader[0].ip_p = ip_protocol_icmp;
      newipheader[0].ip_dst = ipheader->ip_src;
      newipheader[0].ip_src = (ppinterface->ip);
      newipheader[0].ip_len = ntohs(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
      newipheader[0].ip_sum=0;
      newipheader[0].ip_sum = cksum(newipheader, sizeof(sr_ip_hdr_t));
      memcpy(icmppacket+sizeof(sr_ethernet_hdr_t), newipheader, sizeof(sr_ip_hdr_t));

      sr_icmp_t3_hdr_t newicmpheader[1];
      newicmpheader[0].icmp_type=3;
      newicmpheader[0].icmp_code=3;
      newicmpheader[0].unused = 0;
      memcpy(newicmpheader[0].data, ipheader, ICMP_DATA_SIZE);

      newicmpheader[0].icmp_sum=0;
      newicmpheader[0].icmp_sum=cksum(newicmpheader, sizeof(sr_icmp_t3_hdr_t));

      memcpy(icmppacket+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t), newicmpheader, sizeof(sr_icmp_t3_hdr_t));
      print_hdrs(packet, len);
      sr_send_packet(sr , icmppacket , sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t)+sizeof(sr_icmp_t3_hdr_t) , interface);      
      printf("icmp sent\n");
      print_hdrs(icmppacket, sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
      return;
    }
  }

  if(ntohs(etheader->ether_type) ==0x806){
    /*print_hdrs(packet, len);*/
    sr_arp_hdr_t *arpheader = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    struct sr_if* ainterface =  sr_get_interface(sr, interface);
    struct sr_rt* temp = sr->routing_table;
    unsigned char nmacaddr[ETHER_ADDR_LEN];
    

    if(ntohs(arpheader->ar_op)==0x0001){
      uint32_t sourceip=0;
      /*print_hdrs(packet, len);*/
      while(temp!=NULL){
        struct sr_if* tempinterface =  sr_get_interface(sr, temp->interface);
        
        if(ntohl(arpheader->ar_tip)==ntohl(tempinterface->ip)){
          sourceip = ntohl(tempinterface->ip);
          memcpy(nmacaddr, tempinterface->addr, ETHER_ADDR_LEN);
          break;
        }
      }

      /* print_addr_ip_int(sourceip); */

      if(sourceip!=0){
        arpheader->ar_tip=arpheader->ar_sip;
        arpheader->ar_sip = htonl(sourceip);
        memcpy(arpheader->ar_tha, arpheader->ar_sha, ETHER_ADDR_LEN);
        memcpy(arpheader->ar_sha, nmacaddr, ETHER_ADDR_LEN);
        arpheader->ar_op = htons(0x0002);
        
        memcpy(etheader->ether_dhost, etheader->ether_shost, ETHER_ADDR_LEN);
        memcpy(etheader->ether_shost, nmacaddr, ETHER_ADDR_LEN);
        sr_send_packet(sr , packet , len , interface); 
        return;     
      }
      else
        return;

    }
    if(ntohs(arpheader->ar_op)==0x0002){
      
      struct sr_arpreq *newrequest = sr_arpcache_insert(&(sr->cache), arpheader->ar_sha, ntohl(arpheader->ar_sip));
      struct sr_arpreq *temp2= newrequest;
      while(temp2->packets!=NULL){
        sr_ethernet_hdr_t *newetheader = (sr_ethernet_hdr_t *)temp2->packets->buf;  
        struct sr_if* ninterface =  sr_get_interface(sr, temp2->packets->iface);
        memcpy(newetheader->ether_shost, ninterface->addr, ETHER_ADDR_LEN);
        memcpy(newetheader->ether_dhost, arpheader->ar_sha, ETHER_ADDR_LEN);
        
        /*printf("sent packet\n");
        print_hdrs(temp2->packets->buf,temp2->packets->len);*/
        sr_send_packet(sr , temp2->packets->buf , temp2->packets->len , temp2->packets->iface);
        temp2->packets = temp2->packets->next;
        sr_arpreq_destroy(&(sr->cache), newrequest);
      }
      
    }  
    
    
  }
  

}/* -- sr_handlepacket -- */

