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
  if diffttime(currtime, req->sent)>1.0{
    if(req->times_sent>=5){

    }
    else{
      uint8_t *newpacket = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
      sr_ethernet_hdr_t newetheader[1];
      for(int i=0;i<6;i++){
        newetheader[0].ether_dhost[i]=255;
      }
      struct sr_if* ainterface =  sr_get_interface(sr, req->packets->iface);
      unsigned char macaddr[ETHER_ADDR_LEN];
      memcpy(macaddr, ainterface->addr, ETHER_ADDR_LEN);
      uint32_t newip = ainterface->ip;

      memcpy(newetheader[0].ether_shost, macaddr, ETHER_ADDR_LEN);
      newetheader[0].ether_type=0x0806;
      memcpy(newpacket, newheader, sizeof(sr_ethernet_hdr_t));
      
      sr_arp_hdr_t newarpheader[1];

      memcpy(newarpheader[0].ar_sha, macaddr, ETHER_ADDR_LEN);
      newarpheader.ar_sip = newip;
      for(int i=0;i<6;i++){
        newarpeader[0].ar_tha[i]=255;
      }
      newarpheader[0].ar_tip =  req->ip;
      newarpheader[0].ar_hrd = htons(arp_hrd_ethernet);
      newarpheader[0].ar_pln = sizeof(uint32_t);
      newarpheader[0].ar_pro = htons(2048);
      newarpheader[0].ar_hln = ETHER_ADDR_LEN;
      newarpheader[0].ar_op = 0x0001;

      memcpy(newpacket+sizeof(sr_ethernet_hdr_t), newarpheader, sizeof(sr_arp_hdr_t));
      sr_send_packet(sr , newpacket , sizeof(newpacket) , req->packets->iface);      
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
  

  if(etheader->ether_type==0x800){
    sr_ip_hdr_t *ipheader = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    struct sr_rt* temp1 = sr->routing_table;
    struct sr_rt* rt = sr->routing_table;
    uint32_t destip = ipheader->ip_dst;
    uint32_t lmatch;
    /*prefix-match*/
    while(rt != NULL)
    {
      uint32_t a = htonl(temp1->dest.s_addr) & htonl(temp1->mask.s_addr);
      uint32_t b = htonl(temp1->mask.s_addr) & destip; 
      
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

    struct sr_arpentry *arp = sr_arpcache_lookup(&(sr->cache), (rt->dest).s_addr);
    if(arp!=NULL){
      char destmacaddr[6];
      memcpy(destmacaddr, arp->mac, 6);

      memcpy(etheader->ether_shost, curmacaddr, ETHER_ADDR_LEN);
      memcpy(etheader->ether_dhost, destmacaddr, ETHER_ADDR_LEN);

      sr_send_packet(sr , packet , len , iface);

      }
    else{
      struct sr_arpreq* request = sr_arpcache_queuereq(&(sr->cache), destip, packet, len, iface);
      handle_arpreq(sr, request);
    }
  }

  if(etheader->ether_type==0x806){
    sr_arp_hdr_t *arpheader = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    struct sr_if* ainterface =  sr_get_interface(sr, interface);
    struct sr_rt* temp = sr->routing_table;
    unsigned char nmacaddr[ETHER_ADDR_LEN];

    if(arpheader->ar_op==0x0001){
      uint32_t sourceip=0;
      while(temp!=NULL){
        struct sr_if* tempinterface =  sr_get_interface(sr, temp->interface);
        if(arpheader->ar_tip==tempinterface->ip){
          sourceip = tempinterface->ip;
          memcpy(nmacaddr, tempinterface->addr, ETHER_ADDR_LEN);
        }
      }

      if(sip!=0){
        arpheader->ar_tip=arpheader->ar_sip;
        arpheader->ar_sip = sourceip;
        memcpy(arpheader->ar_tha, arpheader->ar_sha, ETHER_ADDR_LEN);
        memcpy(arpheader->ar_sha, nmacaddr, ETHER_ADDR_LEN);
        arpheader->ar_op = 0x0002;
        
        memcpy(etheader->ether_dhost, etheader->ether_shost, ETHER_ADDR_LEN);
        memcpy(etheader->ether_shost, nmacaddr, ETHER_ADDR_LEN);
        sr_send_packet(sr , packet , len , interface);      
      }

    }
    if(arpheader->ar_op==0x0002){
      struct sr_arpreq *newrequest = sr_arpcache_insert(&(sr->cache), arpheader->ar_sha, arpheader->ar_sip);
      struct sr_arpreq *temp2= newrequest;
      while(temp2->packets!=NULL){
        sr_ethernet_hdr_t *newetheader = (sr_ethernet_hdr_t *)temp2->packets;  
        struct sr_if* ninterface =  sr_get_interface(sr, temp2->packets->iface);
        memcpy(newetheader->ether_shost, ninterface->addr, ETHER_ADDR_LEN);
        memcpy(newetheader->ether_dhost, arpheader->ar_sha, ETHER_ADDR_LEN);

        sr_send_packet(sr , temp2->packets , sizeof(temp2->packets) , temp2->packets->iface);
        temp2->packets = temp2->packets->next;
        sr_arpreq_destroy(&(sr->cache), newrequest);


      }
      
    }  
    
    
  }
  

}/* -- sr_handlepacket -- */

