/*
    C reference oracle for the netcode.rs receive-drain differential test.

    Build (see tests/c_differential.rs):

        cc -O2 -ffp-contract=off \
           -I$NETCODE_C_DIR -I$NETCODE_C_DIR/sodium \
           tests/c/oracle.c $NETCODE_C_DIR/sodium/sodium.c -lm -o oracle

    netcode.c is #included rather than compiled separately so the file-local
    receive classifier stays reachable; if a checkout exposes it non-static,
    compile netcode.c on the command line instead.

    The program prints one line per input, of the form

        <queue> <server|client|classifier> consumed <n> processed <m>

    for the scripted receive queues the card names, plus one line per
    classifier row. It uses no socket and no wall clock: the queue is scripted
    and every timestamp is passed in.
*/

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "netcode.c"

#define SERVER_CAP ( 64 * NETCODE_MAX_CLIENTS )
#define CLIENT_CAP 64

/* A scripted receive queue. Each entry is a raw recvfrom result plus the errno
   that accompanies a negative result:
       > 0   a datagram of that many bytes (no error)
         0   a zero-length datagram (no error)
        -1   a receive error; the accompanying errno selects would-block vs
             any other error */
enum { ENTRY_BYTES = 0, ENTRY_EMPTY = 1, ENTRY_WOULD_BLOCK = 2, ENTRY_ERROR = 3 };

struct entry
{
    int kind;
    int bytes;
};

static struct entry queue[SERVER_CAP + 16];
static int queue_length;
static int queue_index;

static void queue_push( int kind, int bytes )
{
    queue[queue_length].kind = kind;
    queue[queue_length].bytes = bytes;
    queue_length++;
}

/* Pulls the next raw result. A queue is drained (would-block) once exhausted. */
static int next_receive( int * error, int * would_block )
{
    if ( queue_index >= queue_length )
    {
        *error = EAGAIN;
        *would_block = 1;
        return -1;
    }
    struct entry e = queue[queue_index++];
    if ( e.kind == ENTRY_BYTES )
    {
        *error = 0;
        *would_block = 0;
        return e.bytes;
    }
    if ( e.kind == ENTRY_EMPTY )
    {
        *error = 0;
        *would_block = 0;
        return 0;
    }
    if ( e.kind == ENTRY_WOULD_BLOCK )
    {
        *error = EAGAIN;
        *would_block = 1;
        return -1;
    }
    *error = ECONNREFUSED;
    *would_block = 0;
    return -1;
}

/* The C receive loop, classified and capped exactly as the reference does it. */
static void run_queue( const char * name, const char * side, int cap )
{
    int consumed = 0;
    int processed = 0;
    while ( 1 )
    {
        int error;
        int would_block;
        int raw = next_receive( &error, &would_block );
        int packet_bytes = netcode_classify_receive_result( raw, error, would_block );
        consumed++;
        if ( packet_bytes == 0 )
            break;
        if ( packet_bytes < 0 )
        {
            if ( consumed >= cap )
                break;
            continue;
        }
        processed++;
        if ( consumed >= cap )
            break;
    }
    printf( "%s %s consumed %d processed %d\n", name, side, consumed, processed );
}

static void reset_queue( void )
{
    queue_length = 0;
    queue_index = 0;
    memset( queue, 0, sizeof( queue ) );
}

static void print_classifier( const char * name, int raw, int error, int would_block )
{
    int result = netcode_classify_receive_result( raw, error, would_block );
    printf( "%s classifier consumed 1 processed %d\n", name, result > 0 ? 1 : 0 );
}

int main( void )
{
    /* The classifier rows. */
    print_classifier( "classifier-0-0", 0, 0, 0 );
    print_classifier( "classifier-1-would-block", -1, EAGAIN, 1 );
    print_classifier( "classifier-1-other", -1, ECONNREFUSED, 0 );
    print_classifier( "classifier-5-0", 5, 0, 0 );

    /* [junk, empty, junk, junk] */
    reset_queue();
    queue_push( ENTRY_BYTES, 12 );
    queue_push( ENTRY_EMPTY, 0 );
    queue_push( ENTRY_BYTES, 12 );
    queue_push( ENTRY_BYTES, 12 );
    run_queue( "junk-empty-junk-junk", "server", SERVER_CAP );
    queue_index = 0;
    run_queue( "junk-empty-junk-junk", "client", CLIENT_CAP );

    /* [empty, empty, empty, junk] */
    reset_queue();
    queue_push( ENTRY_EMPTY, 0 );
    queue_push( ENTRY_EMPTY, 0 );
    queue_push( ENTRY_EMPTY, 0 );
    queue_push( ENTRY_BYTES, 12 );
    run_queue( "empty-empty-empty-junk", "server", SERVER_CAP );
    queue_index = 0;
    run_queue( "empty-empty-empty-junk", "client", CLIENT_CAP );

    /* MAX_RECEIVE_PACKETS + 10 junk datagrams */
    reset_queue();
    for ( int i = 0; i < SERVER_CAP + 10; ++i )
        queue_push( ENTRY_BYTES, 12 );
    run_queue( "flood", "server", SERVER_CAP );
    queue_index = 0;
    run_queue( "flood", "client", CLIENT_CAP );

    /* a queue that ends with a would-block */
    reset_queue();
    queue_push( ENTRY_BYTES, 12 );
    queue_push( ENTRY_EMPTY, 0 );
    queue_push( ENTRY_WOULD_BLOCK, -1 );
    run_queue( "ends-with-drain", "server", SERVER_CAP );
    queue_index = 0;
    run_queue( "ends-with-drain", "client", CLIENT_CAP );

    return 0;
}
