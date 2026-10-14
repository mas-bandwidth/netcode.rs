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

/* ----------------------------------------------------------------------------
   Challenge-token binding scenario (mode "challenge").

   Runs the C reference's server handshake for the scripted scenario the card
   names, then prints one line per step in the form

       <step> connected <sorted client ids> userdata <first byte of each>

   so the port's netcode::challenge_token_transcript() can be compared byte for
   byte. The scenario: tokens A (client id 0x1111, user data first byte 0xa1)
   and B (0x2222, 0xb2) minted for one server, X presenting A, Y presenting B,
   Y answering under B's keys with A's challenge (refused), then with its own
   (connected as B), then X moving to token C (0x3333, 0xc3) twice with two
   challenges in flight, A's challenge under C's keys refused, and the older C
   challenge admitting X as C.

   The challenge token encrypt/decrypt take the connect token's 16-byte MAC as
   AEAD associated data, so a challenge minted under one token's MAC decrypts
   only under that same token's mapping. No socket is opened: requests and
   responses are fed straight to the file-local process functions with an
   override transport and explicit timestamps.

   NOTE: written against the reference API names from memory and never compiled
   against the C checkout (no C checkout is reachable from this job). Expect to
   adjust file-local signatures and struct field names on first run against
   mas-bandwidth/netcode (branch sprint/netcode-audit-fixes at or after
   5cc4798d).
---------------------------------------------------------------------------- */

static void print_connected_challenge( struct netcode_server_t * server, const char * step )
{
    uint64_t ids[NETCODE_MAX_CLIENTS];
    uint8_t first[NETCODE_MAX_CLIENTS];
    int count = 0;
    int i, j;
    for ( i = 0; i < server->max_clients; ++i )
    {
        if ( server->client_slots[i].connected )
        {
            ids[count] = server->client_slots[i].client_id;
            first[count] = server->client_slots[i].user_data[0];
            count++;
        }
    }
    for ( i = 0; i < count; ++i )
        for ( j = i + 1; j < count; ++j )
            if ( ids[j] < ids[i] )
            {
                uint64_t tid = ids[i];
                ids[i] = ids[j];
                ids[j] = tid;
                uint8_t tb = first[i];
                first[i] = first[j];
                first[j] = tb;
            }
    printf( "%s connected", step );
    for ( i = 0; i < count; ++i )
        printf( " 0x%llx", (unsigned long long) ids[i] );
    printf( " userdata" );
    for ( i = 0; i < count; ++i )
        printf( " %02x", first[i] );
    printf( "\n" );
}

/* The connect token buffer layout is byte-identical to the port (STANDARD.md
   "Connect Token"): 13 version + 8 protocol + 8 create + 8 expire + 24 nonce,
   then 1024 bytes of encrypted private data. The private data's trailing 16
   bytes are its AEAD tag, which is exactly the MAC the challenge token binds to
   and the bytes the connect-token history entry keeps. */
#define CONNECT_TOKEN_PRIVATE_OFFSET ( 13 + 8 + 8 + 8 + 24 )
#define CONNECT_TOKEN_MAC_OFFSET ( CONNECT_TOKEN_PRIVATE_OFFSET + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES )

static void mint_challenge_c( uint8_t * challenge, uint64_t client_id, uint8_t first_byte, uint64_t sequence, uint8_t * challenge_key, uint8_t * mac )
{
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    uint8_t plain[NETCODE_CHALLENGE_TOKEN_BYTES];
    memset( user_data, 0, sizeof( user_data ) );
    user_data[0] = first_byte;
    memset( plain, 0, sizeof( plain ) );
    /* challenge token: 8-byte client id then 256-byte user data */
    memcpy( plain, &client_id, 8 );
    memcpy( plain + 8, user_data, NETCODE_USER_DATA_BYTES );
    memcpy( challenge, plain, sizeof( plain ) );
    netcode_encrypt_challenge_token( challenge, challenge_key, sequence, mac );
}

static int run_challenge_scenario( void )
{
    uint8_t private_key[NETCODE_KEY_BYTES];
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    char * server_addresses[1];
    uint8_t * connect_token_a;
    uint8_t * connect_token_b;
    uint8_t * connect_token_c;
    struct netcode_address_t x_addr;
    struct netcode_address_t y_addr;
    uint8_t challenge_a[NETCODE_CHALLENGE_TOKEN_BYTES];
    uint8_t challenge_b[NETCODE_CHALLENGE_TOKEN_BYTES];
    uint8_t challenge_c[NETCODE_CHALLENGE_TOKEN_BYTES];

    server_addresses[0] = "127.0.0.1:40000";
    memset( private_key, 0, NETCODE_KEY_BYTES );
    memset( &x_addr, 0, sizeof( x_addr ) );
    x_addr.type = NETCODE_ADDRESS_IPV4;
    x_addr.data.ipv4[0] = 127;
    x_addr.data.ipv4[3] = 1;
    x_addr.port = 41000;
    memset( &y_addr, 0, sizeof( y_addr ) );
    y_addr.type = NETCODE_ADDRESS_IPV4;
    y_addr.data.ipv4[0] = 127;
    y_addr.data.ipv4[3] = 1;
    y_addr.port = 41001;

    /* tokens A (0x1111, 0xa1), B (0x2222, 0xb2), C (0x3333, 0xc3) */
    memset( user_data, 0, sizeof( user_data ) );
    user_data[0] = 0xa1;
    connect_token_a = netcode_generate_connect_token( private_key, 0x1122334455667788ULL, 1000000, 5, 0x1111, 1, server_addresses, 1, server_addresses, user_data );

    memset( user_data, 0, sizeof( user_data ) );
    user_data[0] = 0xb2;
    connect_token_b = netcode_generate_connect_token( private_key, 0x1122334455667788ULL, 1000000, 5, 0x2222, 1, server_addresses, 1, server_addresses, user_data );

    memset( user_data, 0, sizeof( user_data ) );
    user_data[0] = 0xc3;
    connect_token_c = netcode_generate_connect_token( private_key, 0x1122334455667788ULL, 1000000, 5, 0x3333, 1, server_addresses, 1, server_addresses, user_data );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.protocol_id = 0x1122334455667788ULL;
    memcpy( server_config.private_key, private_key, NETCODE_KEY_BYTES );
    server_config.override_send_and_receive = 1;
    server_config.send_packet_override = send_override;
    server_config.receive_packet_override = receive_override;

    struct netcode_server_t * server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );
    if ( !server )
        return 1;
    netcode_server_start( server, 2 );

    /* X presents token A, then Y presents token B. The request processor is fed
       the token's decrypted private data (with the MAC in its trailing 16
       bytes); it mints one challenge per request, sequence 0 then 1. */
    netcode_server_process_connection_request( server, &x_addr, connect_token_a + CONNECT_TOKEN_PRIVATE_OFFSET, 1000000, 0 );
    print_connected_challenge( server, "present-a" );

    netcode_server_process_connection_request( server, &y_addr, connect_token_b + CONNECT_TOKEN_PRIVATE_OFFSET, 1000000, 0 );
    print_connected_challenge( server, "present-b" );

    /* Re-mint the challenges the server just issued, bound to each token's MAC,
       exactly as the server did. */
    mint_challenge_c( challenge_a, 0x1111, 0xa1, 0, server->challenge_key, connect_token_a + CONNECT_TOKEN_MAC_OFFSET );
    mint_challenge_c( challenge_b, 0x2222, 0xb2, 1, server->challenge_key, connect_token_b + CONNECT_TOKEN_MAC_OFFSET );

    /* Y answers under B's keys with A's challenge: refused. */
    netcode_server_process_connection_response( server, &y_addr, challenge_a, 0 );
    print_connected_challenge( server, "answer-cross" );

    /* Y answers with its own challenge: connected as B. */
    netcode_server_process_connection_response( server, &y_addr, challenge_b, 1 );
    print_connected_challenge( server, "answer-own" );

    /* X moves to token C twice: two challenges in flight, sequences 2 and 3. */
    netcode_server_process_connection_request( server, &x_addr, connect_token_c + CONNECT_TOKEN_PRIVATE_OFFSET, 1000000, 0 );
    print_connected_challenge( server, "present-c" );

    netcode_server_process_connection_request( server, &x_addr, connect_token_c + CONNECT_TOKEN_PRIVATE_OFFSET, 1000000, 0 );
    print_connected_challenge( server, "present-c-again" );

    mint_challenge_c( challenge_c, 0x3333, 0xc3, 2, server->challenge_key, connect_token_c + CONNECT_TOKEN_MAC_OFFSET );

    /* X answers under C's keys with A's challenge: refused. */
    netcode_server_process_connection_response( server, &x_addr, challenge_a, 0 );
    print_connected_challenge( server, "answer-stale" );

    /* X answers with the older C challenge (sequence 2): connected as C. */
    netcode_server_process_connection_response( server, &x_addr, challenge_c, 2 );
    print_connected_challenge( server, "answer-c" );

    netcode_server_destroy( server );
    return 0;
}

int main( int argc, char ** argv )
{
    if ( netcode_init() != NETCODE_OK )
        return 1;

    if ( argc > 1 && strcmp( argv[1], "challenge" ) == 0 )
        return run_challenge_scenario();

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
