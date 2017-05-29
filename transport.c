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

#define WINDOWS_SIZE 3072
#define FULLOPTION 44

enum { CSTATE_ESTABLISHED, CSTATE_CLOSED, CSTATE_LISTEN, CSTATE_SYN_SENT,\
       CSTATE_SYN_RCVD, CSTATE_FIN_WAIT_1, CSTATE_FIN_WAIT_2, \
       CSTATE_CLOSE_WAIT, CSTATE_LAST_ACK, CSTATE_CLOSING};    /* obviously you should have more states */

typedef enum { NORMAL, SYN, SYNACK, ACK, FIN } packet_type;

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    tcp_seq present_sequence_num; /* GBN */
    tcp_seq present_ack_num;
    int window;
    int iserror;

    /* any other connection-wide global variables go here */
} context_t;

typedef struct
{
  STCPHeader header;
  int data_size;
  char data[STCP_MSS];
} STCPPacket;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
void our_dprintf(const char *format,...);
int send_packet (mysocket_t sd, tcp_seq seq_num, tcp_seq ack_num, \
                 packet_type type, char *data, int size);
int rcvd_packet (mysocket_t sd, tcp_seq *seq_num, tcp_seq *ack_num, \
                 packet_type *type, char *data, int *data_size);

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
      ctx->connection_state = CSTATE_SYN_SENT;
      send_packet (sd, ctx->initial_sequence_num, 0, SYN, NULL, 0);
    }
    else ctx->connection_state = CSTATE_LISTEN;

    control_loop(sd, ctx);

    /* iserror == 1 -> error */
    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
    srand (time (NULL));

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    ctx->initial_sequence_num = rand () % 256;
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
    assert(ctx);
    tcp_seq seq_num, ack_num;
    packet_type type;
    int is_full = 0;

    while (!ctx->done)
    {
        unsigned int event;
        
        our_dprintf ("\nEVENT! ");
        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */

        if (is_full == 0) event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
        else if (is_full == 1)
          event = stcp_wait_for_event (sd, NETWORK_DATA, NULL);

        our_dprintf ("%d, %d\n", event, ctx->connection_state);
        

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
          int packet_size = STCP_MSS;
          our_dprintf ("APP_DATA\n");
          if (ctx->connection_state == CSTATE_ESTABLISHED)
          {
            void *data = calloc (1, STCP_MSS);
            if (ctx->window <= STCP_MSS) packet_size = ctx->window;
            if (packet_size == 0)
            {
              is_full = 1;
              continue;
            }

            int data_size = stcp_app_recv (sd, data, packet_size);
            send_packet (sd, ctx->present_sequence_num, \
                         ctx->present_ack_num, NORMAL, data, data_size);
            ctx->present_sequence_num += data_size;
            ctx->window -= data_size;
            our_dprintf ("ctx->window = %d\n", ctx->window);
            free (data);
          }

            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
        }

        else if (event & NETWORK_DATA)
        {
          if (ctx->connection_state == CSTATE_LISTEN)
          {
            our_dprintf ("LISTEN\n");
            rcvd_packet (sd, &seq_num, &ack_num, &type, NULL, NULL);
            if (type == SYN)
            {
              ctx->connection_state = CSTATE_SYN_RCVD;
              send_packet (sd, ctx->initial_sequence_num, seq_num + 1, SYNACK,\
                           NULL, 0);
            }
          }

          else if (ctx->connection_state == CSTATE_SYN_SENT)
          {
            rcvd_packet (sd, &seq_num, &ack_num, &type, NULL, NULL);
            if (type == SYNACK)
            {
              send_packet (sd, ack_num, seq_num + 1, ACK, NULL, 0);
              ctx->present_sequence_num = ack_num;
              ctx->present_ack_num = seq_num + 1;
              ctx->window = WINDOWS_SIZE;
              ctx->connection_state = CSTATE_ESTABLISHED;
              stcp_unblock_application (sd);
            }
          }
          /* if error? */

          else if (ctx->connection_state == CSTATE_SYN_RCVD)
          {
            rcvd_packet (sd, &seq_num, &ack_num, &type, NULL, NULL);
            if (type == ACK)
            {
              ctx->present_sequence_num = ack_num;
              ctx->present_ack_num = seq_num + 1;
              ctx->window = WINDOWS_SIZE;
              ctx->connection_state = CSTATE_ESTABLISHED;
              stcp_unblock_application (sd);
            }
          }

          else if (ctx->connection_state == CSTATE_ESTABLISHED)
          {  
            void *data = calloc (1, STCP_MSS);
            int size;
            rcvd_packet (sd, &seq_num, &ack_num, &type, data, &size);
            if (type == NORMAL)
            {
              send_packet (sd, ctx->present_sequence_num, \
                           seq_num + size, ACK, NULL, 0);
              ctx->present_ack_num = seq_num + size;

              our_dprintf ("data transmission : %s\n", data);
              stcp_app_send (sd, data, size);
            }

            else if (type == ACK)
            {
              ctx->window = WINDOWS_SIZE - (ctx->present_sequence_num - ack_num);
              our_dprintf ("ctx->window = %d\n", ctx->window);
              assert (ctx->window <= WINDOWS_SIZE);
              our_dprintf ("ACK\n");
              is_full = 0;
            } /* ack 처리 */

            else if (type == FIN)
            {
              send_packet (sd, ack_num, seq_num + 1, ACK, NULL, 0);
              ctx->present_ack_num = seq_num + 1;
              ctx->connection_state = CSTATE_CLOSE_WAIT;
              if (size != 0) stcp_app_send (sd, data, size);
              stcp_fin_received (sd);
            }

            free (data);
          }

          else if (ctx->connection_state == CSTATE_FIN_WAIT_1)
          {
            rcvd_packet (sd, &seq_num, &ack_num, &type, NULL, NULL);
            
            if (type == ACK) ctx->connection_state = CSTATE_FIN_WAIT_2;
            else if (type == FIN)
            {
              send_packet (sd, ack_num, seq_num + 1, ACK, NULL, 0);
              ctx->present_ack_num = seq_num + 1;
              ctx->connection_state = CSTATE_CLOSING;
            }
          }

          else if (ctx->connection_state == CSTATE_FIN_WAIT_2)
          {
            rcvd_packet (sd, &seq_num, &ack_num, &type, NULL, NULL);
            if (type == FIN)
            {
              send_packet (sd, ack_num, seq_num + 1, ACK, NULL, 0);
              ctx->done = TRUE;
            }
          }

          else if (ctx->connection_state == CSTATE_CLOSING)
          {
            rcvd_packet (sd, &seq_num, &ack_num, &type, NULL, NULL);
            if (type == ACK) ctx->done = TRUE;
          }

          else if (ctx->connection_state == CSTATE_LAST_ACK)
          {
            rcvd_packet (sd, &seq_num, &ack_num, &type, NULL, NULL);
            if (type == ACK) ctx->done = TRUE;
          }
        }
           

        if (event & APP_CLOSE_REQUESTED)
        {
          if (ctx->connection_state == CSTATE_ESTABLISHED)
          {
            send_packet (sd, ctx->present_sequence_num, ctx->present_ack_num,\
                         FIN, NULL, 0);
            ctx->connection_state = CSTATE_FIN_WAIT_1;
          }

          if (ctx->connection_state == CSTATE_CLOSE_WAIT)
          {
            send_packet (sd, ctx->present_sequence_num, ctx->present_ack_num,\
                         FIN, NULL, 0);
            ctx->connection_state = CSTATE_LAST_ACK;
          }
        }
                                    
        /* etc. */
    }
}

int send_packet (mysocket_t sd, tcp_seq seq_num, tcp_seq ack_num, \
                 packet_type type, char *data, int size)
{
  our_dprintf ("send : %d, %d, %d\n", seq_num, ack_num, type);
  int success;
  STCPPacket *packet = (STCPPacket *) calloc (1, sizeof (STCPPacket));
  packet->header.th_seq = htonl (seq_num);
  packet->header.th_ack = htonl (ack_num);
  packet->header.th_off = 5;
  if (type == SYN) packet->header.th_flags = TH_SYN;
  else if (type == SYNACK) packet->header.th_flags = (TH_SYN | TH_ACK);
  else if (type == ACK) packet->header.th_flags = TH_ACK;
  else if (type == FIN) packet->header.th_flags = TH_FIN;
  packet->header.th_win = htonl (WINDOWS_SIZE);
  
  if (data != NULL) 
  {
    packet->data_size = size;
    memcpy (packet->data, data, size);
    success = stcp_network_send (sd, packet, sizeof (STCPPacket), NULL);
  }

  else success = stcp_network_send (sd, packet, sizeof (STCPPacket), NULL);
  free (packet);

  return success;
}






int rcvd_packet (mysocket_t sd, tcp_seq *seq_num, tcp_seq *ack_num, \
                 packet_type *type, char *data, int *data_size)
{
  our_dprintf ("RCVD\n");
  int size;
  int option;
  void *temp = calloc (1, sizeof (STCPPacket) + FULLOPTION);
  STCPPacket *packet = (STCPPacket *) calloc (1, sizeof (STCPPacket));
  size = stcp_network_recv (sd, temp, sizeof (STCPPacket) + FULLOPTION);

  option = ((STCPPacket *) temp)->header.th_off;
  if (option != 5)
  {
    memcpy (packet, temp, sizeof (STCPHeader));
    memcpy (&packet->data_size, temp + (option * sizeof (int)), sizeof (int));
    memcpy (&packet->data, temp + ((option + 1) * sizeof (int)), STCP_MSS);
  }
  else memcpy (packet, temp, sizeof (STCPPacket));
  
  /* error checking */

  our_dprintf ("RCVD_PACKET\n");
  *seq_num = ntohl (packet->header.th_seq);
  *ack_num = ntohl (packet->header.th_ack);
  if (packet->header.th_flags == TH_SYN) *type = SYN;
  else if (packet->header.th_flags == (TH_SYN | TH_ACK)) *type = SYNACK;
  else if (packet->header.th_flags == TH_ACK) *type = ACK;
  else if (packet->header.th_flags == TH_FIN) *type = FIN;
  else *type = NORMAL;

  if (packet->data_size != 0)
  {
    memcpy (data, packet->data, STCP_MSS);
    *data_size = packet->data_size;
  }
  else data = NULL;
  
  free (packet);
  free (temp);

  return size;
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



