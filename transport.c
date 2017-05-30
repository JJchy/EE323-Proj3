/*-----------------------------------------------------------------------------
 * Name : Choi ho yong
 * Student ID : 20130672
 * File name : proxy.c
 *
 * Project 3. STCP: Implementing a Reliable Transport Layer
 *---------------------------------------------------------------------------*/

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
#include <time.h>
#include <sys/time.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

#define WINDOWS_SIZE 3072 /* receiver window size */
#define FULLOPTION 44  /* TCP Header : 20byte -> 64byte (full option) */

#define SEC 1000000000 /* You need some nanosecond calculation */
#define MSEC 1000000   
#define USEC 1000

enum { CSTATE_ESTABLISHED, CSTATE_CLOSED, CSTATE_LISTEN, CSTATE_SYN_SENT,\
       CSTATE_SYN_RCVD, CSTATE_FIN_WAIT_1, CSTATE_FIN_WAIT_2, \
       CSTATE_CLOSE_WAIT, CSTATE_LAST_ACK, CSTATE_CLOSING};    /* obviously you should have more states */

typedef enum { NORMAL, SYN, SYNACK, ACK, FIN } packet_type;

/* for buffer, save the some data out of order  */ 
typedef struct save_packet save_packet;
typedef struct save_packet
{
  int start;
  int end;
  char data[STCP_MSS];

  save_packet *next;
} save_packet;

/* for retransmission, save the packet sending */
typedef struct preack_packet preack_packet;
typedef struct preack_packet
{
  tcp_seq sequence_num;
  int size;
  char data[STCP_MSS];
  
  preack_packet *next;
} preack_packet;

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;                  /* TRUE once connection is closed */

    int connection_state;         /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num; /* initialization of sequence number */
    tcp_seq present_sequence_num; /* next unsent sequence number */
    tcp_seq present_ack_num;      /* next unacked sequence number */
    int window;                   /* present window size */ 
    int ERTT_ms;                  /* estimate RTT (millisecond) */
    int ERTT_s;                   /* estimate RTT (second) */

    int iserror;                  /* error detecting when connection */

    save_packet *save;            /* linked list for buffer */
    preack_packet *preack;        /* linked list for retransmission */

    struct timespec *timer;       /* for timeout    */
    /* any other connection-wide global variables go here */
} context_t;

/* STCP packet structure */
typedef struct
{
  STCPHeader header;      /* header */
  int data_size;          /* data size (for easy implementation) */
  char data[STCP_MSS];    /* data */
} STCPPacket;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
void our_dprintf(const char *format,...);
int send_packet (mysocket_t sd, tcp_seq seq_num, tcp_seq ack_num, \
                 packet_type type, char *data, int size);
int rcvd_packet (mysocket_t sd, tcp_seq *seq_num, tcp_seq *ack_num, \
                 packet_type *type, char *data, int *data_size);
void cal_timer (mysocket_t sd, context_t *ctx);
void set_timer (mysocket_t sd, context_t *ctx);

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

    if (is_active)  /* client */
    { 
      struct timeval *now;
      struct timespec *timer;
      now = (struct timeval *) calloc (1, sizeof (struct timeval));
      timer = (struct timespec *) calloc (1, sizeof (struct timespec));
      ctx->timer = timer;

      gettimeofday (now, NULL);
      
      /* start timer : 1sec */
      ctx->timer->tv_sec = now->tv_sec + 1;
      ctx->timer->tv_nsec = now->tv_usec * USEC;
      free (now);

      ctx->connection_state = CSTATE_SYN_SENT;
      send_packet (sd, ctx->initial_sequence_num, 0, SYN, NULL, 0);
    }
    else ctx->connection_state = CSTATE_LISTEN; /* server */

    control_loop(sd, ctx);

    if (ctx->iserror == 1)    /* connection is bad */
      errno = ECONNREFUSED;

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
    save_packet *save, *save_temp;
    preack_packet *preack, *preack_temp;

    int is_full = 0;    /* If window is full, is_full = 1 */
    int timeout = 0;    /* number of timeout. timeout > 5 -> terminate */

    while (!ctx->done)
    {
        unsigned int event;
        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */

        if (is_full == 0) event = stcp_wait_for_event(sd, ANY_EVENT, ctx->timer); 
        else if (is_full == 1)
          event = stcp_wait_for_event (sd, NETWORK_DATA, ctx->timer);
        


        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)       
        {
          int packet_size = STCP_MSS;
          if (ctx->connection_state == CSTATE_ESTABLISHED)
          {
            void *data = calloc (1, STCP_MSS);

            if (ctx->window == WINDOWS_SIZE) set_timer (sd, ctx);  
            else if (ctx->window <= STCP_MSS) packet_size = ctx->window;
            
            if (packet_size == 0)
            {
              is_full = 1;
              free (data);
              continue;
            }

            int data_size = stcp_app_recv (sd, data, packet_size);
            preack = (preack_packet *) calloc (1, sizeof (preack_packet));
            preack->sequence_num = ctx->present_sequence_num;
            preack->size = data_size;

            memcpy (preack->data, data, data_size);
            if (ctx->preack == NULL) ctx->preack = preack;
            else 
            {
              preack_temp = ctx->preack;
              while (preack_temp->next != NULL) preack_temp = preack_temp->next;
              preack_temp->next = preack;
            }

            send_packet (sd, ctx->present_sequence_num, \
                         ctx->present_ack_num, NORMAL, data, data_size);
            ctx->present_sequence_num += data_size;
            ctx->window -= data_size;
            free (data);
          }
        }




        else if (event & NETWORK_DATA)
        {
          if (ctx->connection_state == CSTATE_LISTEN)
          {
            rcvd_packet (sd, &seq_num, &ack_num, &type, NULL, NULL);
            if (type == SYN)
            {
              ctx->connection_state = CSTATE_SYN_RCVD;
              ctx->present_ack_num = seq_num + 1;
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
              ctx->ERTT_ms = 500;
              ctx->connection_state = CSTATE_ESTABLISHED;
              free (ctx->timer);
              ctx->timer = NULL;
              stcp_unblock_application (sd);
            }
          }


          else if (ctx->connection_state == CSTATE_SYN_RCVD)
          {
            rcvd_packet (sd, &seq_num, &ack_num, &type, NULL, NULL);
            if (type == ACK)
            {
              ctx->present_sequence_num = ack_num;
              ctx->present_ack_num = seq_num;
              ctx->window = WINDOWS_SIZE;
              ctx->ERTT_ms = 500;
              ctx->connection_state = CSTATE_ESTABLISHED;
              free (ctx->timer);
              ctx->timer = NULL;
              stcp_unblock_application (sd);
            }
          }


          else if (ctx->connection_state == CSTATE_ESTABLISHED)
          {  
            void *data = calloc (1, STCP_MSS);
            int size;
            rcvd_packet (sd, &seq_num, &ack_num, &type, data, &size);

            if (type == SYNACK)    /* delay ACK of SYNACK */
              send_packet (sd, ctx->present_sequence_num, \
                           ctx->present_ack_num, ACK, NULL, 0);

            else if (type == NORMAL) /* Data Receive */
            {
              if (seq_num < ctx->present_ack_num)  /* Duplicate Data */
                send_packet (sd, ctx->present_sequence_num,\
                             ctx->present_ack_num, ACK, NULL, 0);
              
              else if (seq_num > ctx->present_ack_num) /* Buffer out of order */
              {
                send_packet (sd, ctx->present_sequence_num,\
                             ctx->present_ack_num, ACK, NULL, 0);

                save_temp = ctx->save;
                while (save_temp != NULL)
                {
                  if (save_temp->start == \
                      (int)(seq_num - ctx->present_ack_num))
                    break;
                  save_temp = save_temp->next;
                }
                if (save_temp != NULL) 
                {
                  free (data);
                  continue;
                }

                save = (save_packet *) calloc (1, sizeof (save_packet));
                save->start = seq_num - ctx->present_ack_num;
                if (save->start >= WINDOWS_SIZE)
                {
                  free (save);
                  free (data);
                  continue;
                }
                save->end = save->start + size;
                if (save->end > WINDOWS_SIZE)
                  save->end = WINDOWS_SIZE;
                memcpy (save->data, data, save->end - save->start);

                if (ctx->save == NULL) ctx->save = save;
                else
                {
                  save_temp = ctx->save;
                  while (save_temp->next != NULL) save_temp = save_temp->next;
                  save_temp->next = save;
                }
              }

              else /* Naturally Data arrive */ 
              {
                int size_temp = size;
                
                save_temp = ctx->save;
                while (save_temp != NULL) /* Search that out of order data */
                {
                  if (save_temp->start == size_temp)
                  {
                    size_temp += save_temp->end - save_temp->start;
                    save_temp = save_temp->next;
                  }
                  else break;
                }

                send_packet (sd, ctx->present_sequence_num, \
                             seq_num + size_temp, ACK, NULL, 0);
                
                void *data_merge = calloc (1, WINDOWS_SIZE);
                memcpy (data_merge, data, size);
                
                save_temp = ctx->save;   /* if out of buffer data exists, merge that */
                while (save_temp != NULL)
                {
                  if (save_temp->start == size)
                  {
                    memcpy (data_merge + size, save_temp->data,\
                            save_temp->end - save_temp->start);
                    size += save_temp->end - save_temp->start;
                    save = save_temp;
                    save_temp = save_temp->next;
                    ctx->save = save_temp;
                    free (save);
                  }
                  else
                  {
                    while (save_temp != NULL)
                    {
                      save_temp->start -= size;
                      save_temp->end -= size;
                      save_temp = save_temp->next;
                    }
                  }
                }

                ctx->present_ack_num = seq_num + size;

                stcp_app_send (sd, data_merge, size);
                free (data_merge);
              }
            }

            else if (type == ACK)  /* ACK arrive */
            {
              /* move the window */
              if (ctx->preack != NULL && ack_num > ctx->preack->sequence_num)
              {
                cal_timer (sd, ctx);
                preack_temp = ctx->preack;
                while (preack_temp != NULL)
                {
                  if (preack_temp->sequence_num < ack_num)
                  {
                    preack = preack_temp;
                    preack_temp = preack_temp->next;
                    ctx->preack = preack_temp;
                    free (preack);
                  }
                  else break;
                }
                is_full = 0;
              }

              if (ctx->preack == NULL) ctx->window = WINDOWS_SIZE;
              else
              {
                ctx->window = WINDOWS_SIZE -\
                              (ctx->present_sequence_num -\
                               ctx->preack->sequence_num);
                set_timer (sd, ctx);
              }
              our_dprintf ("ctx->window = %d\n", ctx->window);
              assert (ctx->window <= WINDOWS_SIZE);

              /* Our code can handling data with ack 
               * (Actually almost same as receive data) */
              if (size != 0)
              { 
                if (seq_num < ctx->present_ack_num)
                  send_packet (sd, ctx->present_sequence_num,\
                               ctx->present_ack_num, ACK, NULL, 0);
                else if (seq_num > ctx->present_ack_num)
                {
                  send_packet (sd, ctx->present_sequence_num,\
                               ctx->present_ack_num, ACK, NULL, 0);

                  save_temp = ctx->save;
                  while (save_temp != NULL)
                  {
                    if (save_temp->start == \
                        (int)(seq_num - ctx->present_ack_num))
                      break;
                    save_temp = save_temp->next;
                  }

                  if (save_temp != NULL) 
                  {
                    free (data);
                    continue;
                  }

                  save = (save_packet *) calloc (1, sizeof (save_packet));
                  save->start = seq_num - ctx->present_ack_num;
                  if (save->start >= WINDOWS_SIZE)
                  {
                    free (save);
                    free (data);
                    continue;
                  }
                  save->end = save->start + size;
                  if (save->end > WINDOWS_SIZE)
                    save->end = WINDOWS_SIZE;
                  memcpy (save->data, data, save->end - save->start);

                  if (ctx->save == NULL) ctx->save = save;
                  else
                  {
                    save_temp = ctx->save;
                    while (save_temp->next != NULL) save_temp = save_temp->next;
                    save_temp->next = save;
                  }
                }

                else
                {
                  int size_temp = size;
                  save_temp = ctx->save;
                  while (save_temp != NULL)
                  {
                    if (save_temp->start == size_temp)
                    {
                      size_temp += save_temp->end - save_temp->start;
                      save_temp = save_temp->next;
                    }
                    else break;
                  }
                  send_packet (sd, ctx->present_sequence_num, \
                               seq_num + size_temp, ACK, NULL, 0);
                
                  void *data_merge = calloc (1, WINDOWS_SIZE);
                  memcpy (data_merge, data, size);
                
                  save_temp = ctx->save;
                  while (save_temp != NULL)
                  {
                    if (save_temp->start == size)
                    {
                      memcpy (data_merge + size, save_temp->data,\
                              save_temp->end - save_temp->start);
                      size += save_temp->end - save_temp->start;
                      save = save_temp;
                      save_temp = save_temp->next;
                      ctx->save = save_temp;
                      free (save);
                    }
                    else
                    {
                      while (save_temp != NULL)
                      {
                        save_temp->start -= size;
                        save_temp->end -= size;
                        save_temp = save_temp->next;
                      }
                    }
                  }

                  ctx->present_ack_num = seq_num + size;

                  our_dprintf ("data transmission : %s\n", data_merge);
                  stcp_app_send (sd, data_merge, size);
                  free (data_merge);
                } 
              }
            }

            else if (type == FIN) /* ready to terminate */
            {
              send_packet (sd, ack_num, seq_num + 1, ACK, NULL, 0);
              ctx->present_ack_num = seq_num + 1;
              ctx->connection_state = CSTATE_CLOSE_WAIT;

              /* Our code can handling data with fin 
               * (Actually almost same as receive data) */
              if (size != 0)
              { 
                if (seq_num < ctx->present_ack_num)
                  send_packet (sd, ctx->present_sequence_num,\
                               ctx->present_ack_num, ACK, NULL, 0);
                else if (seq_num > ctx->present_ack_num)
                {
                  send_packet (sd, ctx->present_sequence_num,\
                               ctx->present_ack_num, ACK, NULL, 0);
                  
                  save_temp = ctx->save;
                  while (save_temp != NULL)
                  {
                    if (save_temp->start == \
                        (int)(seq_num - ctx->present_ack_num))
                      break;
                    save_temp = save_temp->next;
                  }

                  if (save_temp != NULL) 
                  {
                    free (data);
                    continue;
                  }

                  save = (save_packet *) calloc (1, sizeof (save_packet));
                  save->start = seq_num - ctx->present_ack_num;
                  if (save->start >= WINDOWS_SIZE)
                  {
                    free (save);
                    free (data);
                    continue;
                  }
                  save->end = save->start + size;
                  if (save->end > WINDOWS_SIZE)
                    save->end = WINDOWS_SIZE;
                  memcpy (save->data, data, save->end - save->start);

                  if (ctx->save == NULL) ctx->save = save;
                  else
                  {
                    save_temp = ctx->save;
                    while (save_temp->next != NULL) save_temp = save_temp->next;
                    save_temp->next = save;
                  }
                }

                else
                {
                  int size_temp = size;
                  save_temp = ctx->save;
                  while (save_temp != NULL)
                  {
                    if (save_temp->start == size_temp)
                    {
                      size_temp += save_temp->end - save_temp->start;
                      save_temp = save_temp->next;
                    }
                    else break;
                  }
                  send_packet (sd, ctx->present_sequence_num, \
                               seq_num + size_temp, ACK, NULL, 0);
                
                  void *data_merge = calloc (1, WINDOWS_SIZE);
                  memcpy (data_merge, data, size);
                
                  save_temp = ctx->save;
                  while (save_temp != NULL)
                  {
                    if (save_temp->start == size)
                    {
                      memcpy (data_merge + size, save_temp->data,\
                              save_temp->end - save_temp->start);
                      size += save_temp->end - save_temp->start;
                      save = save_temp;
                      save_temp = save_temp->next;
                      ctx->save = save_temp;
                      free (save);
                    }
                    else
                    {
                      while (save_temp != NULL)
                      {
                        save_temp->start -= size;
                        save_temp->end -= size;
                        save_temp = save_temp->next;
                      }
                    }
                  }

                  ctx->present_ack_num = seq_num + size;

                  our_dprintf ("data transmission : %s\n", data_merge);
                  stcp_app_send (sd, data_merge, size);
                  free (data_merge);
                } 
              }

              /* request to application to close connection */
              stcp_fin_received (sd); 
            }

            free (data);
          }


          else if (ctx->connection_state == CSTATE_FIN_WAIT_1)
          {
            void *data = calloc (1, STCP_MSS);
            int size;
            rcvd_packet (sd, &seq_num, &ack_num, &type, data, &size);
            
            if (type == FIN)
            {
              send_packet (sd, ack_num, seq_num + 1, ACK, NULL, 0);
              ctx->present_ack_num = seq_num + 1;
              ctx->connection_state = CSTATE_CLOSING;
            }

            /* Before the ack packet arrive, Our code can receive data
             * (Actually almost same as receive data) */
            else if (type == NORMAL)
            {
              if (seq_num < ctx->present_ack_num)
              {
                our_dprintf ("BEFORE!\n");
                send_packet (sd, ctx->present_sequence_num,\
                             ctx->present_ack_num, ACK, NULL, 0);
              }
              else if (seq_num > ctx->present_ack_num)
              {
                our_dprintf ("AFTER!\n");
                send_packet (sd, ctx->present_sequence_num,\
                             ctx->present_ack_num, ACK, NULL, 0);
                save_temp = ctx->save;
                while (save_temp != NULL)
                {
                  if (save_temp->start == \
                      (int)(seq_num - ctx->present_ack_num))
                    break;
                  save_temp = save_temp->next;
                }

                if (save_temp != NULL) 
                {
                  free (data);
                  continue;
                }

                save = (save_packet *) calloc (1, sizeof (save_packet));
                save->start = seq_num - ctx->present_ack_num;
                if (save->start >= WINDOWS_SIZE)
                {
                  free (save);
                  free (data);
                  continue;
                }
                save->end = save->start + size;
                if (save->end > WINDOWS_SIZE)
                  save->end = WINDOWS_SIZE;
                memcpy (save->data, data, save->end - save->start);

                if (ctx->save == NULL) ctx->save = save;
                else
                {
                  save_temp = ctx->save;
                  while (save_temp->next != NULL) save_temp = save_temp->next;
                  save_temp->next = save;
                }
              }

              else
              {
                our_dprintf ("PRINT!\n");
                int size_temp = size;
                save_temp = ctx->save;
                while (save_temp != NULL)
                {
                  if (save_temp->start == size_temp)
                  {
                    size_temp += save_temp->end - save_temp->start;
                    save_temp = save_temp->next;
                  }
                  else break;
                }
                send_packet (sd, ctx->present_sequence_num, \
                             seq_num + size_temp, ACK, NULL, 0);
                
                void *data_merge = calloc (1, WINDOWS_SIZE);
                memcpy (data_merge, data, size);
                
                save_temp = ctx->save;
                while (save_temp != NULL)
                {
                  if (save_temp->start == size)
                  {
                    memcpy (data_merge + size, save_temp->data,\
                            save_temp->end - save_temp->start);
                    size += save_temp->end - save_temp->start;
                    save = save_temp;
                    save_temp = save_temp->next;
                    ctx->save = save_temp;
                    free (save);
                  }
                  else
                  {
                    while (save_temp != NULL)
                    {
                      save_temp->start -= size;
                      save_temp->end -= size;
                      save_temp = save_temp->next;
                    }
                  }
                }

                ctx->present_ack_num = seq_num + size;

                our_dprintf ("data transmission : %s\n", data_merge);
                stcp_app_send (sd, data_merge, size);
                free (data_merge);
              }
            }

            /* Our code can handling data with ack 
             * (Actually almost same as receive data) */
            else if (type == ACK)
            {
              if (ctx->preack != NULL && ack_num > ctx->preack->sequence_num)
              {
                cal_timer (sd, ctx);
                preack_temp = ctx->preack;
                while (preack_temp != NULL)
                {
                  if (preack_temp->sequence_num < ack_num)
                  {
                    preack = preack_temp;
                    preack_temp = preack_temp->next;
                    ctx->preack = preack_temp;
                    free (preack);
                  }
                  else break;
                }
                is_full = 0;
              }

              if (ctx->preack == NULL) ctx->window = WINDOWS_SIZE;
              else
              {
                ctx->window = WINDOWS_SIZE -\
                              (ctx->present_sequence_num -\
                               ctx->preack->sequence_num);
                set_timer (sd, ctx);
              }
              our_dprintf ("ctx->window = %d\n", ctx->window);
              assert (ctx->window <= WINDOWS_SIZE);
              our_dprintf ("ACK\n");

              printf ("size : %d\n", size);
              if (size != 0)
              { 
              our_dprintf ("Here?\n");
                if (seq_num < ctx->present_ack_num)
                  send_packet (sd, ctx->present_sequence_num,\
                               ctx->present_ack_num, ACK, NULL, 0);
                else if (seq_num > ctx->present_ack_num)
                {
                  send_packet (sd, ctx->present_sequence_num,\
                               ctx->present_ack_num, ACK, NULL, 0);

                  save_temp = ctx->save;
                  while (save_temp != NULL)
                  {
                    if (save_temp->start == \
                        (int)(seq_num - ctx->present_ack_num))
                      break;
                    save_temp = save_temp->next;
                  }

                  if (save_temp != NULL) 
                  {
                    free (data);
                    continue;
                  }

                  save = (save_packet *) calloc (1, sizeof (save_packet));
                  save->start = seq_num - ctx->present_ack_num;
                  if (save->start >= WINDOWS_SIZE)
                  {
                    free (save);
                    free (data);
                    continue;
                  }
                  save->end = save->start + size;
                  if (save->end > WINDOWS_SIZE)
                    save->end = WINDOWS_SIZE;
                  memcpy (save->data, data, save->end - save->start);

                  if (ctx->save == NULL) ctx->save = save;
                  else
                  {
                    save_temp = ctx->save;
                    while (save_temp->next != NULL) save_temp = save_temp->next;
                    save_temp->next = save;
                  }
                }

                else
                {
                  int size_temp = size;
                  save_temp = ctx->save;
                  while (save_temp != NULL)
                  {
                    if (save_temp->start == size_temp)
                    {
                      size_temp += save_temp->end - save_temp->start;
                      save_temp = save_temp->next;
                    }
                    else break;
                  }
                  send_packet (sd, ctx->present_sequence_num, \
                               seq_num + size_temp, ACK, NULL, 0);
                
                  void *data_merge = calloc (1, WINDOWS_SIZE);
                  memcpy (data_merge, data, size);
                
                  save_temp = ctx->save;
                  while (save_temp != NULL)
                  {
                    if (save_temp->start == size)
                    {
                      memcpy (data_merge + size, save_temp->data,\
                              save_temp->end - save_temp->start);
                      size += save_temp->end - save_temp->start;
                      save = save_temp;
                      save_temp = save_temp->next;
                      ctx->save = save_temp;
                      free (save);
                    }
                    else
                    {
                      while (save_temp != NULL)
                      {
                        save_temp->start -= size;
                        save_temp->end -= size;
                        save_temp = save_temp->next;
                      }
                    }
                  }

                  ctx->present_ack_num = seq_num + size;

                  our_dprintf ("data transmission : %s\n", data_merge);
                  stcp_app_send (sd, data_merge, size);
                  free (data_merge);
                } 
              
              }
              
              ctx->connection_state = CSTATE_FIN_WAIT_2;
            }

            free (data);
          }


          else if (ctx->connection_state == CSTATE_FIN_WAIT_2)
          {
            rcvd_packet (sd, &seq_num, &ack_num, &type, NULL, NULL);
            if (type == FIN)
            {
              send_packet (sd, ack_num, seq_num + 1, ACK, NULL, 0);
              cal_timer (sd, ctx);
              ctx->done = TRUE;
            }
          }


          else if (ctx->connection_state == CSTATE_CLOSING)
          {
            rcvd_packet (sd, &seq_num, &ack_num, &type, NULL, NULL);
            if (type == ACK)
            {
              cal_timer (sd, ctx);
              ctx->done = TRUE;
            }
          }


          else if (ctx->connection_state == CSTATE_LAST_ACK)
          {
            rcvd_packet (sd, &seq_num, &ack_num, &type, NULL, NULL);
            if (type == ACK) 
            {
              cal_timer (sd, ctx);
              ctx->done = TRUE;
            }
          }
        }
          


        else if (event & APP_CLOSE_REQUESTED)
        {
          if (ctx->connection_state == CSTATE_ESTABLISHED)
          {
            send_packet (sd, ctx->present_sequence_num, ctx->present_ack_num,\
                         FIN, NULL, 0);
            if (ctx->timer == NULL) set_timer (sd, ctx);
            ctx->connection_state = CSTATE_FIN_WAIT_1;
          }


          if (ctx->connection_state == CSTATE_CLOSE_WAIT)
          {
            send_packet (sd, ctx->present_sequence_num, ctx->present_ack_num,\
                         FIN, NULL, 0);
            if (ctx->timer == NULL) set_timer (sd, ctx);
            ctx->connection_state = CSTATE_LAST_ACK;
          }
        }
  


        else if (event == TIMEOUT)
        {
          if (timeout++ > 5)
          {
            if (ctx->connection_state == CSTATE_SYN_SENT ||\
                ctx->connection_state == CSTATE_SYN_RCVD)
            {
              stcp_unblock_application (sd);
              ctx->iserror = 1;
            }
            return;
          }

          if (ctx->connection_state == CSTATE_SYN_SENT)
          {
            send_packet (sd, ctx->initial_sequence_num, 0, SYN, NULL, 0);
            ctx->timer->tv_sec++;
          }

          else if (ctx->connection_state == CSTATE_SYN_RCVD)
          {
            send_packet (sd, ctx->initial_sequence_num, ctx->present_ack_num,\
                         SYNACK, NULL, 0);
            ctx->timer->tv_sec++;
          }

          else if (ctx->connection_state == CSTATE_ESTABLISHED)
          {
            assert (ctx->preack != NULL);

            /* If timeout occurs when data exchange, 
             * timeout value will be one and a half */
            free (ctx->timer);
            ctx->timer = NULL;
            int RTT = ctx->ERTT_s * SEC + ctx->ERTT_ms * MSEC;
            RTT = RTT * 3 / 2;
            ctx->ERTT_s = RTT / SEC;
            ctx->ERTT_ms = (RTT / MSEC) % 1000;

            set_timer (sd, ctx);
            
            /* retransmission */
            preack_temp = ctx->preack;
            while (preack_temp != NULL)
            {
              send_packet (sd, preack_temp->sequence_num, \
                           ctx->present_ack_num, NORMAL, \
                           preack_temp->data, preack_temp->size);
              preack_temp = preack_temp->next;
            }
          }

          else if (ctx->connection_state == CSTATE_FIN_WAIT_1)
          {
            send_packet (sd, ctx->present_sequence_num, ctx->present_ack_num,\
                         FIN, NULL, 0);
            free (ctx->timer);
            ctx->timer = NULL;
            set_timer (sd, ctx);
          }

          else if (ctx->connection_state == CSTATE_LAST_ACK)
          {
            send_packet (sd, ctx->present_sequence_num, ctx->present_ack_num,\
                         FIN, NULL, 0);
            free (ctx->timer);
            ctx->timer = NULL;
            set_timer (sd, ctx);
          }

          else
          {
            free (ctx->timer);
            ctx->timer = NULL;
            set_timer (sd, ctx); 
          }
        }
        /* etc. */
    }
}

/* send_packet : send a packet with lots of parameter */
int send_packet (mysocket_t sd, tcp_seq seq_num, tcp_seq ack_num, \
                 packet_type type, char *data, int size)
{
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
  packet->data_size = size;

  if (data != NULL) 
  {
    memcpy (packet->data, data, size);
    success = stcp_network_send (sd, packet, sizeof (STCPPacket), NULL);
  }

  else success = stcp_network_send (sd, packet, sizeof (STCPPacket), NULL);
  free (packet);

  return success;
}

/* rcvd_packet : receive a packet and parsing the data in packet */
int rcvd_packet (mysocket_t sd, tcp_seq *seq_num, tcp_seq *ack_num, \
                 packet_type *type, char *data, int *data_size)
{
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
  
  *seq_num = ntohl (packet->header.th_seq);
  *ack_num = ntohl (packet->header.th_ack);
  if (packet->header.th_flags == TH_SYN) *type = SYN;
  else if (packet->header.th_flags == (TH_SYN | TH_ACK)) *type = SYNACK;
  else if (packet->header.th_flags == TH_ACK) *type = ACK;
  else if (packet->header.th_flags == TH_FIN) *type = FIN;
  else *type = NORMAL;

  if (data_size != NULL) *data_size = packet->data_size;

  if (packet->data_size != 0)
    memcpy (data, packet->data, STCP_MSS);

  else data = NULL;
  
  free (packet);
  free (temp);

  return size;
}

/* cal_timer : calculate the RTT and change timeout value */
/* (stop the timer) */
void cal_timer (mysocket_t sd, context_t *ctx)
{
  struct timeval *now;
  time_t RTT, new_RTT;
  now = (struct timeval *) calloc (1, sizeof (struct timeval));
  gettimeofday (now, NULL);
 
  RTT = ((2 * ctx->ERTT_s * SEC + 2 * ctx->ERTT_ms * MSEC) - \
         ((ctx->timer->tv_sec - now->tv_sec) * SEC + \
          (ctx->timer->tv_nsec - now->tv_usec * USEC))) / 1000;
  RTT += 100 * USEC; /* prevent unnecessary timeout */
  our_dprintf ("RTT = %d\n", RTT);
  
  new_RTT = (7 * ((ctx->ERTT_s * SEC + ctx->ERTT_ms * MSEC) / 1000) + RTT) / 8;
  our_dprintf ("new_RTT : %d\n", new_RTT);

  ctx->ERTT_s = new_RTT / (SEC / 1000) ;
  ctx->ERTT_ms = (new_RTT / (MSEC / 1000)) % 1000; 
  free (now);
  free (ctx->timer);
  ctx->timer = NULL;
}

/* set_timer : set the timer on 2 * RTT value */
void set_timer (mysocket_t sd, context_t *ctx)
{
  struct timeval *now;
  struct timespec *timer;
  now = (struct timeval *) calloc (1, sizeof (struct timeval));
  timer = (struct timespec *) calloc (1, sizeof (struct timespec));
  
  ctx->timer = timer;
  gettimeofday (now, NULL);

  if ((now->tv_usec * USEC + 2 * ctx->ERTT_ms * MSEC) >= 2 * SEC)
  {
    ctx->timer->tv_sec = now->tv_sec + 2 * ctx->ERTT_s + 2;
    ctx->timer->tv_nsec = (now->tv_usec * USEC + 2 * ctx->ERTT_ms * MSEC) % SEC;
  }
  else if ((now->tv_usec * USEC + 2 * ctx->ERTT_ms * MSEC) >= SEC)
  {
    ctx->timer->tv_sec = now->tv_sec + 2 * ctx->ERTT_s + 1;
    ctx->timer->tv_nsec = (now->tv_usec * USEC + 2 * ctx->ERTT_ms * MSEC) % SEC;
  }
  else
  {
    ctx->timer->tv_sec = now->tv_sec + 2 * ctx->ERTT_s;
    ctx->timer->tv_nsec = now->tv_usec * USEC + 2 * ctx->ERTT_ms * MSEC;
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



