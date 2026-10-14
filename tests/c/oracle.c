/*
    C reference oracle for the netcode.rs receive-drain differential test.

    Build (see tests/c_differential.rs):

        cc -O2 -ffp-contract=off -finstrument-functions \
           -I$NETCODE_C_DIR -I$NETCODE_C_DIR/sodium \
           tests/c/oracle.c $NETCODE_C_DIR/sodium/sodium.c -lm -o oracle

    netcode.c is #included rather than compiled separately so the file-local
    receive classifier stays reachable.

    Queues are scripted behind receive_packet_override. One update is the
    reference's netcode_server_receive_packets / netcode_client_receive_packets,
    with the override transport and a time passed to create. No socket is
    opened. consumed is the number of override calls that update made.
    processed is the number of times that update entered the packet processor
    (netcode_server_read_and_process_packet / netcode_client_process_packet),
    counted by the compiler's function-entry hook, so a skip of -1 that the
    loop handed to the processor shows up here.

    The program prints one line per input, of the form

        <queue> <server|client|classifier> consumed <n> processed <m>

    for the scripted receive queues the card names, plus one line per
    classifier row.
*/

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "netcode.c"

#define SERVER_CAP ( 64 * NETCODE_MAX_CLIENTS )
#define CLIENT_CAP 64

/* A scripted override queue. The override returns the classified result the
   reference receive loop consumes: a positive count is a junk datagram, -1 is
   a datagram to skip (a zero-length datagram, or any other non-would-block
   receive), and 0 is would-block (the socket is drained). */
enum { ENTRY_BYTES = 0, ENTRY_EMPTY = 1, ENTRY_WOULD_BLOCK = 2 };

struct entry
{
    int kind;
    int bytes;
};

static struct entry queue[SERVER_CAP + 16];
static int queue_length;
static int queue_index;
static int override_calls;

static int counting;
static int processor_entries;

void __attribute__((no_instrument_function)) __cyg_profile_func_enter( void * this_fn, void * call_site )
{
    (void) call_site;
    if ( !counting )
        return;
    if ( this_fn == (void *) netcode_server_read_and_process_packet || this_fn == (void *) netcode_client_process_packet )
        processor_entries++;
}

void __attribute__((no_instrument_function)) __cyg_profile_func_exit( void * this_fn, void * call_site )
{
    (void) this_fn;
    (void) call_site;
}

static void queue_push( int kind, int bytes )
{
    queue[queue_length].kind = kind;
    queue[queue_length].bytes = bytes;
    queue_length++;
}

static void reset_queue( void )
{
    queue_length = 0;
    queue_index = 0;
    override_calls = 0;
    memset( queue, 0, sizeof( queue ) );
}

static void rewind_queue( void )
{
    queue_index = 0;
    override_calls = 0;
}

static int receive_override( void * context, struct netcode_address_t * from, uint8_t * packet_data, int max_packet_bytes )
{
    (void) context;
    override_calls++;

    if ( queue_index >= queue_length )
        return 0;

    struct entry e = queue[queue_index++];
    if ( e.kind == ENTRY_EMPTY || e.kind == ENTRY_WOULD_BLOCK )
        return e.kind == ENTRY_WOULD_BLOCK ? 0 : -1;

    if ( e.bytes > max_packet_bytes )
        return -1;

    memset( packet_data, 0xFF, (size_t) e.bytes );
    memset( from, 0, sizeof( *from ) );
    from->type = NETCODE_ADDRESS_IPV4;
    from->data.ipv4[0] = 127;
    from->data.ipv4[3] = 1;
    from->port = 50000;
    return e.bytes;
}

static void send_override( void * context, struct netcode_address_t * to, NETCODE_CONST uint8_t * packet_data, int packet_bytes )
{
    (void) context;
    (void) to;
    (void) packet_data;
    (void) packet_bytes;
}

static void print_classifier( const char * name, int raw, int error, int would_block )
{
    int result = netcode_classify_receive_result( raw, error, would_block );
    printf( "%s classifier consumed 1 processed %d\n", name, result > 0 ? 1 : 0 );
}

static void print_run( const char * name, const char * side, int consumed, int processed )
{
    printf( "%s %s consumed %d processed %d\n", name, side, consumed, processed );
}

int main( void )
{
    if ( netcode_init() != NETCODE_OK )
        return 1;

    /* The classifier rows. (0, no error) skips, would-block drains, any other
       error skips, a positive count is the byte count. */
    print_classifier( "classifier-0-0", 0, 0, 0 );
    print_classifier( "classifier-1-would-block", -1, EAGAIN, 1 );
    print_classifier( "classifier-1-other", -1, ECONNREFUSED, 0 );
    print_classifier( "classifier-5-0", 5, 0, 0 );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.protocol_id = 0x1122334455667788ULL;
    server_config.override_send_and_receive = 1;
    server_config.send_packet_override = send_override;
    server_config.receive_packet_override = receive_override;

    struct netcode_server_t * server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );
    if ( !server )
        return 1;
    netcode_server_start( server, 1 );

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.override_send_and_receive = 1;
    client_config.send_packet_override = send_override;
    client_config.receive_packet_override = receive_override;

    struct netcode_client_t * client = netcode_client_create( "127.0.0.1:50000", &client_config, 0.0 );
    if ( !client )
        return 1;

    /* [junk, empty, junk, junk] */
    reset_queue();
    queue_push( ENTRY_BYTES, 12 );
    queue_push( ENTRY_EMPTY, 0 );
    queue_push( ENTRY_BYTES, 12 );
    queue_push( ENTRY_BYTES, 12 );

    counting = 1;
    processor_entries = 0;
    netcode_server_receive_packets( server );
    counting = 0;
    print_run( "junk-empty-junk-junk", "server", override_calls, processor_entries );

    rewind_queue();
    counting = 1;
    processor_entries = 0;
    netcode_client_receive_packets( client );
    counting = 0;
    print_run( "junk-empty-junk-junk", "client", override_calls, processor_entries );

    /* [empty, empty, empty, junk] */
    reset_queue();
    queue_push( ENTRY_EMPTY, 0 );
    queue_push( ENTRY_EMPTY, 0 );
    queue_push( ENTRY_EMPTY, 0 );
    queue_push( ENTRY_BYTES, 12 );

    counting = 1;
    processor_entries = 0;
    netcode_server_receive_packets( server );
    counting = 0;
    print_run( "empty-empty-empty-junk", "server", override_calls, processor_entries );

    rewind_queue();
    counting = 1;
    processor_entries = 0;
    netcode_client_receive_packets( client );
    counting = 0;
    print_run( "empty-empty-empty-junk", "client", override_calls, processor_entries );

    /* MAX_RECEIVE_PACKETS + 10 junk datagrams. The server cap and the client
       cap differ, so each side stops on its own constant. */
    reset_queue();
    for ( int i = 0; i < SERVER_CAP + 10; ++i )
        queue_push( ENTRY_BYTES, 12 );

    counting = 1;
    processor_entries = 0;
    netcode_server_receive_packets( server );
    counting = 0;
    print_run( "flood", "server", override_calls, processor_entries );

    rewind_queue();
    counting = 1;
    processor_entries = 0;
    netcode_client_receive_packets( client );
    counting = 0;
    print_run( "flood", "client", override_calls, processor_entries );

    /* a queue that ends with a would-block */
    reset_queue();
    queue_push( ENTRY_BYTES, 12 );
    queue_push( ENTRY_EMPTY, 0 );
    queue_push( ENTRY_WOULD_BLOCK, 0 );

    counting = 1;
    processor_entries = 0;
    netcode_server_receive_packets( server );
    counting = 0;
    print_run( "ends-with-drain", "server", override_calls, processor_entries );

    rewind_queue();
    counting = 1;
    processor_entries = 0;
    netcode_client_receive_packets( client );
    counting = 0;
    print_run( "ends-with-drain", "client", override_calls, processor_entries );

    netcode_client_destroy( client );
    netcode_server_destroy( server );
    netcode_term();
    return 0;
}
