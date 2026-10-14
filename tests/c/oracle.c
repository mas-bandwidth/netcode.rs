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

/* ----------------------------------------------------------------------------
   Disconnect callback re-entry scenario (mode "disconnect").

   The reference fix (netcode PR 196) makes the disconnect callback unable to
   re-enter the internal disconnect that is clearing the slot. This scenario
   drives the three paths that fix covers over one server with one admitted
   client (installed directly, no handshake) and prints one line per path in
   the shared form:

       <case> callbacks <n> saw <reason> <id> <user data first byte> connected <n> mappings <n> slot <connected|clear>

   The callback re-enters the way the C test does: the "disconnect" case calls
   netcode_server_disconnect_client on the same slot from inside the callback,
   and the "stop" and "timeout" cases call netcode_server_stop from inside it.
   With the fix each callback runs exactly once, observes the slot's reason,
   id and user data, and the server is left consistent; without it the inner
   call cleared the slot, the outer frame then read and wrote
   encryption_manager.client_index[-1] and drove num_connected_clients to -1.
   The port half, netcode::differential_disconnect_transcript, has no
   application callback at all (its queue semantics cannot re-enter) and prints
   the same three lines.

   No socket is opened (override transports) and time is passed in explicitly.

   NOTE: written against the reference API names from memory and never compiled
   against the C checkout (no C checkout is reachable from this job). Expect to
   adjust file-local struct field names and the disconnect callback's exact
   config field and signature on first run against mas-bandwidth/netcode
   (branch sprint/netcode-audit-fixes at or after bbf9805a).
---------------------------------------------------------------------------- */

enum { DISCO_ACTION_NONE = 0, DISCO_ACTION_DISCONNECT = 1, DISCO_ACTION_STOP = 2 };

static int disco_callbacks;
static uint64_t disco_id;
static unsigned disco_user_first;
static int disco_action;

static void disco_callback( void * context, int client_index )
{
    struct netcode_server_t * server = (struct netcode_server_t *) context;
    disco_callbacks++;
    disco_id = server->client_slots[client_index].client_id;
    disco_user_first = server->client_slots[client_index].user_data[0];
    if ( disco_action == DISCO_ACTION_DISCONNECT )
        netcode_server_disconnect_client( server, client_index );
    else if ( disco_action == DISCO_ACTION_STOP )
        netcode_server_stop( server );
}

static int disco_any_connected( struct netcode_server_t * server )
{
    for ( int i = 0; i < server->max_clients; ++i )
        if ( server->client_slots[i].connected )
            return 1;
    return 0;
}

static int disco_mapping_count( struct netcode_server_t * server )
{
    int count = 0;
    for ( int i = 0; i < server->encryption_manager.num_entries; ++i )
        if ( server->encryption_manager.address[i].port != 0 )
            count++;
    return count;
}

static void disco_print( const char * name, const char * reason, struct netcode_server_t * server )
{
    printf( "%s callbacks %d saw %s %llu %u connected %d mappings %d slot %s\n",
            name,
            disco_callbacks,
            reason,
            (unsigned long long) disco_id,
            disco_user_first,
            netcode_server_num_connected_clients( server ),
            disco_mapping_count( server ),
            disco_any_connected( server ) ? "connected" : "clear" );
}

static void disco_install_client( struct netcode_server_t * server )
{
    uint8_t send_key[NETCODE_KEY_BYTES];
    uint8_t receive_key[NETCODE_KEY_BYTES];
    for ( int i = 0; i < NETCODE_KEY_BYTES; ++i )
    {
        send_key[i] = (uint8_t) ( i + 1 );
        receive_key[i] = (uint8_t) ( i + 101 );
    }

    struct netcode_address_t address;
    memset( &address, 0, sizeof( address ) );
    address.type = NETCODE_ADDRESS_IPV4;
    address.data.ipv4[0] = 127;
    address.data.ipv4[3] = 1;
    address.port = 50000;

    netcode_encryption_manager_add_encryption_mapping( &server->encryption_manager, &address, send_key, receive_key, 0.0, -1.0, 5 );

    int encryption_index = netcode_encryption_manager_find_encryption_mapping( &server->encryption_manager, &address, 0.0 );
    netcode_encryption_manager_set_client_index( &server->encryption_manager, encryption_index, 0 );

    struct netcode_server_client_t * client = &server->client_slots[0];
    client->connected = 1;
    client->confirmed = 1;
    client->client_id = 0x1234ULL;
    client->timeout_seconds = 5;
    client->encryption_index = encryption_index;
    netcode_address_copy( &client->address, &address );
    client->last_packet_send_time = 0.0;
    client->last_packet_receive_time = 0.0;
    memset( client->user_data, 0, sizeof( client->user_data ) );
    client->user_data[0] = 0xAB;

    server->num_connected_clients = 1;
}

static struct netcode_server_t * disco_create_server( struct netcode_server_config_t * config )
{
    uint8_t private_key[NETCODE_KEY_BYTES];
    memset( private_key, 0, sizeof( private_key ) );

    netcode_default_server_config( config );
    config->protocol_id = 0x1122334455667788ULL;
    memcpy( config->private_key, private_key, NETCODE_KEY_BYTES );
    config->override_send_and_receive = 1;
    config->send_packet_override = send_override;
    config->receive_packet_override = receive_override;
    config->callback_context = NULL;
    config->disconnect_callback = disco_callback;

    struct netcode_server_t * server = netcode_server_create( "127.0.0.1:40000", config, 0.0 );
    if ( !server )
        return NULL;
    /* the callback needs the server, which does not exist until create returns */
    server->config.callback_context = server;
    netcode_server_start( server, 1 );
    disco_install_client( server );
    return server;
}

static void disco_reset_observations( void )
{
    disco_callbacks = 0;
    disco_id = 0;
    disco_user_first = 0;
}

static int disco_run( void )
{
    struct netcode_server_config_t config;
    struct netcode_server_t * server;

    /* A: the callback disconnects the same client. */
    disco_action = DISCO_ACTION_DISCONNECT;
    server = disco_create_server( &config );
    if ( !server )
        return 1;
    disco_reset_observations();
    netcode_server_disconnect_client( server, 0 );
    disco_print( "disconnect", "server-disconnect", server );
    netcode_server_destroy( server );

    /* B: the callback stops the server; a restart finds every slot empty. */
    disco_action = DISCO_ACTION_STOP;
    server = disco_create_server( &config );
    if ( !server )
        return 1;
    disco_reset_observations();
    netcode_server_disconnect_client( server, 0 );
    netcode_server_start( server, 1 );
    disco_print( "stop", "server-disconnect", server );
    netcode_server_destroy( server );

    /* C: a timeout inside update whose callback stops the server. */
    disco_action = DISCO_ACTION_STOP;
    server = disco_create_server( &config );
    if ( !server )
        return 1;
    disco_reset_observations();
    netcode_server_update( server, 6.0 );
    disco_print( "timeout", "timed-out", server );
    netcode_server_destroy( server );

    disco_action = DISCO_ACTION_NONE;
    return 0;
}

/* ----------------------------------------------------------------------------
   Replay top-sequence and restart-floor scenario (mode "replay").

   Prints one line per input, of the form

       <op> <sequence or expire> -> <0|1|accepted|refused>

   in three groups: the sequence list the card names, with a probe before the
   advance and a re-probe of every sequence advanced so far after it; a
   keep-alive whose prefix byte says eight sequence bytes, all 0xFF, read after
   the window is already at u64::MAX; and connection request bytes with expire
   F-1, F and F+1 against a floor F and a current time below F. The replay
   protection and the packet reads are driven by hand with explicit timestamps;
   no socket is opened.

   NOTE: written against the reference API names from memory and never compiled
   against the C checkout (no C checkout is reachable from this job). Expect to
   adjust file-local signatures and struct field names on first run against
   mas-bandwidth/netcode (branch sprint/netcode-audit-fixes at or after
   406e8d28).
---------------------------------------------------------------------------- */

static void replay_print_flag( const char * op, uint64_t value, int flag )
{
    printf( "%s %llu -> %d\n", op, (unsigned long long) value, flag ? 1 : 0 );
}

static void replay_print_verdict( const char * op, uint64_t value, int accepted )
{
    printf( "%s %llu -> %s\n", op, (unsigned long long) value, accepted ? "accepted" : "refused" );
}

/* Builds a connection request packet whose private data decrypts, in place, for
   the given expiry timestamp: [0][version 13][protocol 8][expire 8][nonce 24]
   [encrypted private 1024]. Returns the packet length. */
static int replay_build_request( uint8_t * packet, uint8_t * private_key, uint64_t protocol_id, uint64_t expire_timestamp )
{
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    char * server_addresses[1];
    uint8_t * token;
    int p = 0;

    server_addresses[0] = "127.0.0.1:40000";
    memset( user_data, 0, sizeof( user_data ) );
    token = netcode_generate_connect_token( private_key, protocol_id, expire_timestamp - 5, 5,
                                            0x1234, 10, server_addresses, 1, server_addresses, 1, user_data );
    if ( !token )
        return 0;

    packet[p++] = 0;
    memcpy( packet + p, token, 13 );
    p += 13;
    memcpy( packet + p, token + 13, 8 );
    p += 8;
    packet[p++] = (uint8_t) ( expire_timestamp & 0xFF );
    packet[p++] = (uint8_t) ( ( expire_timestamp >> 8 ) & 0xFF );
    packet[p++] = (uint8_t) ( ( expire_timestamp >> 16 ) & 0xFF );
    packet[p++] = (uint8_t) ( ( expire_timestamp >> 24 ) & 0xFF );
    packet[p++] = (uint8_t) ( ( expire_timestamp >> 32 ) & 0xFF );
    packet[p++] = (uint8_t) ( ( expire_timestamp >> 40 ) & 0xFF );
    packet[p++] = (uint8_t) ( ( expire_timestamp >> 48 ) & 0xFF );
    packet[p++] = (uint8_t) ( ( expire_timestamp >> 56 ) & 0xFF );
    memcpy( packet + p, token + 29, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    p += NETCODE_CONNECT_TOKEN_NONCE_BYTES;
    memcpy( packet + p, token + 29 + NETCODE_CONNECT_TOKEN_NONCE_BYTES, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    p += NETCODE_CONNECT_TOKEN_PRIVATE_BYTES;

    free( token );
    return p;
}

static int replay_run( void )
{
    static const uint64_t sequences[10] = {
        0, 1, 255, 256, 257,
        UINT64_MAX - 257, UINT64_MAX - 256, UINT64_MAX - 255, UINT64_MAX - 1, UINT64_MAX
    };
    const uint64_t protocol_id = 0x1122334455667788ULL;
    uint64_t floor = 1000030ULL;
    uint64_t current_timestamp = floor - 30;
    uint8_t private_key[NETCODE_KEY_BYTES];
    struct netcode_replay_protection_t replay_protection;
    int i, j;

    /* group 1: the sequence list, probed before and re-probed after each advance */
    netcode_replay_protection_reset( &replay_protection );
    for ( i = 0; i < 10; ++i )
    {
        uint64_t sequence = sequences[i];
        replay_print_flag( "probe", sequence,
                           netcode_replay_protection_already_received( &replay_protection, sequence ) );
        netcode_replay_protection_advance_sequence( &replay_protection, sequence );
        for ( j = 0; j <= i; ++j )
            replay_print_flag( "recheck", sequences[j],
                               netcode_replay_protection_already_received( &replay_protection, sequences[j] ) );
    }

    /* group 2: a keep-alive at the top of the sequence space read after the window
       is there. The packet is written with a key and read back with the window
       already advanced to u64::MAX; the read is skipped when the window already
       holds that sequence, mirroring the port's check before the decrypt. */
    {
        uint8_t write_key[NETCODE_KEY_BYTES];
        uint8_t read_packet_key[NETCODE_KEY_BYTES];
        uint8_t packet[NETCODE_MAX_PACKET_BYTES];
        uint8_t additional_data[13 + 8 + 1];
        uint8_t nonce[NETCODE_NONCE_BYTES];
        struct netcode_replay_protection_t keep_protection;
        uint64_t sequence = UINT64_MAX;
        uint8_t packet_type = 0;
        int p = 0, written, accepted = 0;

        memset( write_key, 0x42, sizeof( write_key ) );
        memset( read_packet_key, 0x42, sizeof( read_packet_key ) );
        memset( packet, 0, sizeof( packet ) );

        packet[p++] = (uint8_t) ( NETCODE_CONNECTION_KEEP_ALIVE_PACKET | ( 8 << 4 ) );
        for ( i = 0; i < 8; ++i )
            packet[p++] = 0xFF;
        packet[p++] = 7;
        packet[p++] = 0;
        packet[p++] = 0;
        packet[p++] = 0;
        packet[p++] = 16;
        packet[p++] = 0;
        packet[p++] = 0;
        packet[p++] = 0;

        memcpy( additional_data, NETCODE_VERSION_INFO, 13 );
        netcode_write_uint64( additional_data + 13, protocol_id );
        additional_data[13 + 8] = packet[0];
        netcode_sequence_nonce( nonce, sequence );
        netcode_encrypt_aead( packet + 1 + 8, 8, additional_data, sizeof( additional_data ), nonce, write_key );
        p += NETCODE_MAC_BYTES;
        written = p;

        netcode_replay_protection_reset( &keep_protection );
        netcode_replay_protection_advance_sequence( &keep_protection, sequence );
        if ( !netcode_replay_protection_already_received( &keep_protection, sequence ) )
        {
            if ( netcode_read_packet( packet, written, protocol_id, 0, 0, read_packet_key, NULL, 1 << NETCODE_CONNECTION_KEEP_ALIVE_PACKET, &packet_type, &sequence ) == NETCODE_OK )
                accepted = 1;
        }
        replay_print_verdict( "keepalive", UINT64_MAX, accepted );
    }

    /* group 3: connection request bytes with expire F-1, F and F+1 against floor F
       and a current time below F. The bytes decrypt, so a refusal here is the floor,
       not the decrypt. */
    memset( private_key, 0x60, sizeof( private_key ) );
    for ( i = -1; i <= 1; ++i )
    {
        uint64_t expire_timestamp = floor + (uint64_t) i;
        uint8_t packet[NETCODE_MAX_PACKET_BYTES];
        uint8_t packet_type = 0;
        uint64_t sequence = 0;
        int length, accepted = 0;

        length = replay_build_request( packet, private_key, protocol_id, expire_timestamp );
        if ( length > 0 &&
             netcode_read_packet( packet, length, protocol_id, current_timestamp, floor, NULL, private_key,
                                 1 << NETCODE_CONNECTION_REQUEST_PACKET, &packet_type, &sequence ) == NETCODE_OK )
            accepted = 1;
        replay_print_verdict( "request", expire_timestamp, accepted );
    }

    return 0;
}

/* ----------------------------------------------------------------------------
   Pre-connect mapping lifetime and bounded token lifetime scenario (mode
   "lifetime").

   Prints one line per input, of the form

       preconnect <timeout> -> <offset|never>
       preconnect-response <timeout> -> <connects|refused>
       request <expire> -> <accepted|refused>

   for the token timeouts {-1, 0, 1, 5, 30} and the expiries UINT64_MAX,
   current + 2 * max lifetime, current + max lifetime + 1, current + max
   lifetime, current + 1 and current. The pre-connect mapping and the packet
   read are driven by hand with explicit timestamps; no socket is opened.

   NOTE: written against the reference API names from memory and never compiled
   against the C checkout (no C checkout is reachable from this job). Expect to
   adjust file-local signatures and struct field names on first run against
   mas-bandwidth/netcode (branch sprint/netcode-audit-fixes at or after the
   commit that lands
   netfix-never-expiring-tokens-are-refused-or-documented-against-the-restart-floor).
---------------------------------------------------------------------------- */

#define LIFETIME_BASE 100.0
#define LIFETIME_MAX 30

/* The mapping's expiry as the reference stores it: -1 means never. */
static int lifetime_mapping_expire( struct netcode_server_t * server, struct netcode_address_t * addr, double * expire_time )
{
    int i;
    for ( i = 0; i < NETCODE_MAX_ENCRYPTION_MAPPINGS; ++i )
    {
        struct netcode_encryption_manager_entry_t * entry = &server->encryption_manager.entry[i];
        if ( entry->address && netcode_address_equal( &entry->address, addr ) )
        {
            *expire_time = entry->expire_time;
            return 1;
        }
    }
    return 0;
}

static int lifetime_run( void )
{
    const uint64_t protocol_id = 0x1122334455667788ULL;
    const int timeouts[5] = { -1, 0, 1, 5, 30 };
    uint8_t private_key[NETCODE_KEY_BYTES];
    struct netcode_address_t addr;
    int i;

    memset( private_key, 0x60, sizeof( private_key ) );
    memset( &addr, 0, sizeof( addr ) );
    addr.type = NETCODE_ADDRESS_IPV4;
    addr.data.ipv4[0] = 127;
    addr.data.ipv4[3] = 1;
    addr.port = 41000;

    /* group 1: the pre-connect mapping for each token timeout. The mapping is
       added by the reference's process_connection_request; the offset is the
       first whole second after the request at which it is gone. */
    for ( i = 0; i < 5; ++i )
    {
        char * server_addresses[1];
        uint8_t * token;
        struct netcode_server_config_t server_config;
        struct netcode_server_t * server;
        int offset, k;

        server_addresses[0] = "127.0.0.1:40000";
        token = netcode_generate_connect_token( private_key, protocol_id, 1000000, timeouts[i],
                                                0x1234, 10, server_addresses, 1, server_addresses, 1, NULL );

        netcode_default_server_config( &server_config );
        server_config.protocol_id = protocol_id;
        memcpy( server_config.private_key, private_key, NETCODE_KEY_BYTES );
        server_config.override_send_and_receive = 1;
        server_config.send_packet_override = send_override;
        server_config.receive_packet_override = receive_override;

        server = netcode_server_create( "127.0.0.1:40000", &server_config, LIFETIME_BASE );
        netcode_server_start( server, 2 );
        server->min_connect_token_expire_timestamp = 0;
        server->time = LIFETIME_BASE;

        netcode_server_process_connection_request( server, &addr, token + CONNECT_TOKEN_PRIVATE_OFFSET, 1000000, 0 );

        offset = -1;
        for ( k = 1; k <= 40; ++k )
        {
            double e;
            if ( !lifetime_mapping_expire( server, &addr, &e ) || e < 0.0 || e < LIFETIME_BASE + k )
            {
                offset = k;
                break;
            }
        }
        if ( offset < 0 )
            printf( "preconnect %d -> never\n", timeouts[i] );
        else
            printf( "preconnect %d -> %d\n", timeouts[i], offset );

        /* a response one update (0.1 s) after the request: the mapping must still
           hold for the response to be accepted */
        {
            double e;
            int present = lifetime_mapping_expire( server, &addr, &e ) && ( e < 0.0 || e >= LIFETIME_BASE + 0.1 );
            printf( "preconnect-response %d -> %s\n", timeouts[i], present ? "connects" : "refused" );
        }

        netcode_server_destroy( server );
        free( token );
    }

    /* group 2: connection request bytes whose expiry is UINT64_MAX or beyond the
       maximum lifetime, refused by the lifetime check rather than the decrypt.
       The bytes decrypt, so an accept here is the missing bound. */
    {
        uint64_t current_timestamp = 1000000ULL;
        uint64_t max_expire = current_timestamp + LIFETIME_MAX;
        uint64_t expiries[6];
        expiries[0] = UINT64_MAX;
        expiries[1] = current_timestamp + 2 * LIFETIME_MAX;
        expiries[2] = max_expire + 1;
        expiries[3] = max_expire;
        expiries[4] = current_timestamp + 1;
        expiries[5] = current_timestamp;

        for ( i = 0; i < 6; ++i )
        {
            uint8_t packet[NETCODE_MAX_PACKET_BYTES];
            uint8_t packet_type = 0;
            uint64_t sequence = 0;
            uint64_t expire_timestamp = expiries[i];
            int length, accepted = 0;

            length = replay_build_request( packet, private_key, protocol_id, expire_timestamp );
            if ( length > 0 &&
                 netcode_read_packet( packet, length, protocol_id, current_timestamp, 0, max_expire,
                                      private_key, 1 << NETCODE_CONNECTION_REQUEST_PACKET,
                                      &packet_type, &sequence ) == NETCODE_OK )
                accepted = 1;
            replay_print_verdict( "request", expire_timestamp, accepted );
        }
    }

    return 0;
}

/* ----------------------------------------------------------------------------
   Client address-family refusal scenario (mode "connect_family").

   Prints one line per input, of the form

       <label> state <state> address <index|none>

   for tokens whose server address lists are [[::1]:40000],
   [[::1]:40000, 127.0.0.1:40000] and [127.0.0.1:40000], fed to a client with
   only an IPv4 socket. The client is created with the override transport and an
   explicit time; no socket is opened. The IPv6 socket is cleared so the client
   has no socket for the [::1] family, the way the C test does; the reference's
   socket handle assert stays a programmer-error check and this scenario never
   trips it.

   NOTE: written against the reference API names from memory and never compiled
   against the C checkout (no C checkout is reachable from this job). Expect to
   adjust file-local signatures and struct field names on first run against
   mas-bandwidth/netcode (branch sprint/netcode-audit-fixes at or after the
   commit that lands
   netfix-client-refuses-a-server-address-it-has-no-socket-for).
---------------------------------------------------------------------------- */

static const char * connect_family_state_name( int state )
{
    switch ( state )
    {
        case NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN:      return "invalid_connect_token";
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST: return "sending_connection_request";
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:return "sending_connection_response";
        case NETCODE_CLIENT_STATE_CONNECTED:                  return "connected";
        case NETCODE_CLIENT_STATE_DISCONNECTED:               return "disconnected";
        default:                                              return "unknown";
    }
}

static int connect_family_run( void )
{
    const uint64_t protocol_id = 0x1122334455667788ULL;
    const char * labels[3] = { "ipv6-only", "ipv6-then-ipv4", "ipv4-only" };
    char * addresses[3][2];
    int counts[3] = { 1, 2, 1 };
    uint8_t private_key[NETCODE_KEY_BYTES];
    int t;

    memset( private_key, 0x60, sizeof( private_key ) );

    addresses[0][0] = "[::1]:40000";
    addresses[1][0] = "[::1]:40000";
    addresses[1][1] = "127.0.0.1:40000";
    addresses[2][0] = "127.0.0.1:40000";

    for ( t = 0; t < 3; ++t )
    {
        struct netcode_client_config_t client_config;
        struct netcode_client_t * client;
        uint8_t * token;
        int index;

        netcode_default_client_config( &client_config );
        client_config.protocol_id = protocol_id;
        memcpy( client_config.private_key, private_key, NETCODE_KEY_BYTES );
        client_config.override_send_and_receive = 1;
        client_config.send_packet_override = send_override;
        client_config.receive_packet_override = receive_override;

        client = netcode_client_create( "127.0.0.1:0", &client_config, 100.0 );

        /* the client is IPv4-only: clear the IPv6 socket so the [::1] family has
           no open handle */
        memset( &client->socket_ipv6, 0, sizeof( client->socket_ipv6 ) );

        token = netcode_generate_connect_token( private_key, protocol_id, 1000000, 10,
                                                0x1234, NETCODE_MAX_SERVERS_PER_CONNECT,
                                                addresses[t], counts[t], addresses[t], counts[t] );

        netcode_client_connect( client, token );

        index = ( client->state == NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN )
              ? -1 : client->server_address_index;

        printf( "%s state %s address ", labels[t], connect_family_state_name( client->state ) );
        if ( index < 0 )
            printf( "none\n" );
        else
            printf( "%d\n", index );

        netcode_client_destroy( client );
        free( token );
    }

    return 0;
}

int main( int argc, char ** argv )
{
    if ( netcode_init() != NETCODE_OK )
        return 1;

    if ( argc > 1 && strcmp( argv[1], "connect_family" ) == 0 )
    {
        int result = connect_family_run();
        netcode_term();
        return result;
    }

    if ( argc > 1 && strcmp( argv[1], "lifetime" ) == 0 )
    {
        int result = lifetime_run();
        netcode_term();
        return result;
    }

    if ( argc > 1 && strcmp( argv[1], "challenge" ) == 0 )
        return run_challenge_scenario();

    if ( argc > 1 && strcmp( argv[1], "disconnect" ) == 0 )
    {
        int result = disco_run();
        netcode_term();
        return result;
    }

    if ( argc > 1 && strcmp( argv[1], "replay" ) == 0 )
    {
        int result = replay_run();
        netcode_term();
        return result;
    }

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
