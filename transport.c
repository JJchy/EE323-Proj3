/*
 * transport.c 
 *
 * CS244a HW#3 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"


enum { CSTATE_ESTABLISHED, CSTATE_CLOSED, CSTATE_LISTEN, CSTATE_SYN_SENT,
       CSTATE_SYN_RCVD, CSTATE_FIN_WAIT_1, CSTATE_FIN_WAIT_2, 
       CSTATE_CLOSE_WAIT, CSTATE_LAST_ACK, CSTATE_CLOSING };    /* obviously you should have more states */

typedef enum packet_type { NORMAL, SYN, ACK, SYNACK, FIN } packet_type; 

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    tcp_seq present_sequence_num;

    /* any other connection-wide global variables go here */
} context_t;

typedef struct
{
  STCPHeader STCPhead;
  char STCPdata[STCP_MSS];
} STCPPacket;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
void our_dprintf(const char *format,...);
void send_packet (mysocket_t sd, tcp_seq seq_num, tcp_seq ack_num, \
                  packet_type type);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */
    if (is_active)
    {
      send_packet (sd, ctx->initial_sequence_num, 0, SYN);
      ctx->connection_state = CSTATE_SYN_SENT;
    }
    else ctx->connection_state = CSTATE_LISTEN;
   
    /* 여기서 부터 다시 시작, Document 읽어보기*/
    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    ctx->initial_sequence_num = rand() % 256;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    ssize_t success;
    STCPPacket packet;
    assert(ctx);

    while (!ctx->done)
    {
        our_dprintf ("state : %d\n", ctx->connection_state);
        unsigned int event;
        memset (&packet, 0, sizeof (STCPPacket));

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, 0, NULL);
        our_dprintf ("afddf\n");

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
        }

        else if (event & NETWORK_DATA)
        {
          our_dprintf ("QWER\n");
          success = stcp_network_recv (sd, &packet, sizeof (STCPPacket));
          if (success == -1) our_dprintf ("Error : stcp_network_recv\n");

          if (packet.STCPhead.th_flags & TH_SYN) 
          {
            if (packet.STCPhead.th_flags & TH_ACK)
            {
              send_packet (sd, ntohl (packet.STCPhead.th_ack), \
                           ntohl (packet.STCPhead.th_seq) + 1, ACK);
              ctx->present_sequence_num = ntohl (packet.STCPhead.th_ack);
              ctx->connection_state = CSTATE_ESTABLISHED;
              stcp_unblock_application(sd);
              our_dprintf ("ASDF\n");
            }
                
            else
            {
              if (ctx->connection_state == CSTATE_LISTEN)
              {
                generate_initial_seq_num (ctx);
                send_packet (sd, ctx->initial_sequence_num, \
                             ntohl (packet.STCPhead.th_seq) + 1, SYNACK);
                ctx->connection_state = CSTATE_SYN_RCVD;
              }

              else if (ctx->connection_state == CSTATE_SYN_SENT)
              {
                send_packet (sd, ctx->initial_sequence_num,\
                             ntohl (packet.STCPhead.th_seq) + 1, SYNACK);
                ctx->connection_state = CSTATE_SYN_RCVD;
              }

              else our_dprintf ("NO WAY! 1\n");
            }
          }

          if (packet.STCPhead.th_flags & TH_ACK)
          {
            if (ctx->connection_state == CSTATE_SYN_RCVD)
            {
              ctx->present_sequence_num = ntohl (packet.STCPhead.th_ack);
              ctx->connection_state = CSTATE_ESTABLISHED;
              stcp_unblock_application(sd);
              our_dprintf ("ASDF\n");
            }
          }
        }

        /* etc. */
    }
}

void send_packet (mysocket_t sd, tcp_seq seq_num, tcp_seq ack_num, \
                  packet_type type)
{
  our_dprintf ("AAAA\n");
  STCPPacket packet;
  STCPHeader header;
  ssize_t success;
  memset (&packet, 0, sizeof (STCPPacket));
  memset (&header, 0, sizeof (STCPHeader));

  if (type == SYN)
  {
    header.th_seq = htonl (seq_num); 
    header.th_off = 5;
    header.th_flags = TH_SYN;
  }

  else if (type == ACK) /* ACK에 메세지 없다고 가정.*/
  {
    header.th_seq = htonl (seq_num);
    header.th_ack = htonl (ack_num);
    header.th_off = 5;
    header.th_flags = TH_ACK;
  }

  else if (type == SYNACK)
  {
    header.th_seq = htonl (seq_num);
    header.th_ack = htonl (ack_num);
    header.th_off = 5;
    header.th_flags = TH_ACK | TH_SYN;
  }

  
  if (type == SYN || type == ACK || type == SYNACK)
  {
    our_dprintf ("%s\n", &header);
    success = stcp_network_send (sd, &header, sizeof (STCPHeader), NULL);
    if (success != sizeof (STCPHeader)) our_dprintf ("Error : send_packet\n");
  }
}




/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}
