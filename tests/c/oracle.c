/*
    C reference oracle for the netcode.rs differential test.

    Build (see tests/c_differential.rs):

        cc -O2 -ffp-contract=off \
           -I$NETCODE_C_DIR -I$NETCODE_C_DIR/sodium \
           tests/c/oracle.c $NETCODE_C_DIR/netcode.c $NETCODE_C_DIR/sodium/sodium.c -lm \
           -o oracle

    netcode.c is compiled separately rather than #included so the file-local
    symbols stay reachable only through the public entry points this oracle
    uses; if a checkout exposes the packet readers as static, include
    netcode.c here instead.

    The program prints one line per input, in the card's form:

        <n> <packet type or refused> <sequence> <length>

    It uses no socket and no wall clock: every input is a fixed byte buffer and
    every timestamp is passed in.
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "netcode.h"

#define TEST_PROTOCOL_ID 0x1122334455667788ULL
#define TEST_CURRENT_TIMESTAMP 1720000000ULL

static uint8_t private_key[NETCODE_KEY_BYTES];
static uint8_t write_key[NETCODE_KEY_BYTES];
static uint8_t read_key[NETCODE_KEY_BYTES];

static void fill_keys( void )
{
    for ( int i = 0; i < NETCODE_KEY_BYTES; ++i )
    {
        private_key[i] = (uint8_t) ( 0x60 + i );
        write_key[i] = (uint8_t) ( i + 17 );
        read_key[i] = (uint8_t) ( i + 17 );
    }
}

/* Decode the prefix byte the way the standard specifies, so the oracle can print
   the type and sequence of an input without asking the packet struct. */
static void decode_prefix( const uint8_t * buffer, int length, int * type, uint64_t * sequence )
{
    *type = -1;
    *sequence = 0;
    if ( length < 1 )
        return;
    if ( buffer[0] == 0 )
    {
        *type = 0;
        return;
    }
    *type = buffer[0] & 0xF;
    int sequence_bytes = ( buffer[0] >> 4 ) & 0xF;
    if ( sequence_bytes < 1 || sequence_bytes > 8 )
        return;
    uint64_t value = 0;
    for ( int i = 0; i < sequence_bytes && 1 + i < length; ++i )
        value |= ( (uint64_t) buffer[1 + i] ) << ( 8 * i );
    *sequence = value;
}

static void print_result( int n, const uint8_t * buffer, int length, int result )
{
    int type;
    uint64_t sequence;
    decode_prefix( buffer, length, &type, &sequence );
    if ( result )
        printf( "%d %d %llu %d\n", n, type, (unsigned long long) sequence, length );
    else
        printf( "%d refused 0 %d\n", n, length );
}

int main( void )
{
    fill_keys();

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];
    uint8_t packet_data[NETCODE_MAX_PACKET_BYTES];
    int written;

    /* 1. a valid keep-alive packet written and read back */
    memset( packet_data, 0, sizeof( packet_data ) );
    struct netcode_connection_keep_alive_packet keep_alive;
    keep_alive.client_index = 7;
    keep_alive.max_clients = 32;
    written = netcode_write_packet( &keep_alive, packet_data, sizeof( packet_data ), 1000, write_key, TEST_PROTOCOL_ID );
    memcpy( buffer, packet_data, (size_t) written );
    {
        int result = netcode_read_packet( packet_data, buffer, written, read_key, TEST_PROTOCOL_ID, TEST_CURRENT_TIMESTAMP, NULL );
        print_result( 1, buffer, written, result );
    }

    /* 2. bad prefix byte: the low four bits are 7, an invalid packet type */
    memcpy( buffer, packet_data, (size_t) written );
    buffer[0] = (uint8_t) ( ( buffer[0] & 0xF0 ) | 7 );
    {
        int result = netcode_read_packet( packet_data, buffer, written, read_key, TEST_PROTOCOL_ID, TEST_CURRENT_TIMESTAMP, NULL );
        print_result( 2, buffer, written, result );
    }

    /* 3. truncated packet: fewer than 1 + sequence bytes + MAC */
    memcpy( buffer, packet_data, (size_t) written );
    {
        int result = netcode_read_packet( packet_data, buffer, 10, read_key, TEST_PROTOCOL_ID, TEST_CURRENT_TIMESTAMP, NULL );
        print_result( 3, buffer, 10, result );
    }

    /* 4. wrong packet size: a payload packet with its encrypted body's last byte cut */
    memset( packet_data, 0, sizeof( packet_data ) );
    struct netcode_connection_payload_packet payload;
    payload.payload_data_length = 3;
    payload.payload_data[0] = 1;
    payload.payload_data[1] = 2;
    payload.payload_data[2] = 3;
    written = netcode_write_packet( &payload, packet_data, sizeof( packet_data ), 42, write_key, TEST_PROTOCOL_ID );
    memcpy( buffer, packet_data, (size_t) written );
    {
        int result = netcode_read_packet( packet_data, buffer, written - 1, read_key, TEST_PROTOCOL_ID, TEST_CURRENT_TIMESTAMP, NULL );
        print_result( 4, buffer, written - 1, result );
    }

    /* 5. replayed sequence: the same payload packet read twice */
    memset( packet_data, 0, sizeof( packet_data ) );
    written = netcode_write_packet( &payload, packet_data, sizeof( packet_data ), 42, write_key, TEST_PROTOCOL_ID );
    memcpy( buffer, packet_data, (size_t) written );
    {
        uint64_t most_recent = 0;
        uint64_t received[NETCODE_REPLAY_PROTECTION_BUFFER_SIZE];
        memset( received, 0xFF, sizeof( received ) );
        int first = netcode_read_packet( packet_data, buffer, written, read_key, TEST_PROTOCOL_ID, TEST_CURRENT_TIMESTAMP, NULL );
        if ( first )
        {
            most_recent = 42;
            received[42 % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE] = 42;
        }
        /* the second read's replay state rejects it before decryption; model the
           state the first read would have produced */
        int already = ( most_recent >= NETCODE_REPLAY_PROTECTION_BUFFER_SIZE &&
                        42 <= most_recent - NETCODE_REPLAY_PROTECTION_BUFFER_SIZE ) ||
                      ( received[42 % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE] != UINT64_MAX &&
                        received[42 % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE] >= 42 );
        print_result( 5, buffer, written, already ? 0 : first );
    }

    /* 6. wrong version info in a connection request */
    struct netcode_connection_request_packet request;
    memset( &request, 0, sizeof( request ) );
    for ( int i = 0; i < NETCODE_VERSION_INFO_BYTES; ++i )
        request.version_info[i] = netcode_version_info[i];
    request.protocol_id = TEST_PROTOCOL_ID;
    request.expire_timestamp = TEST_CURRENT_TIMESTAMP + 30;
    memset( buffer, 0, sizeof( buffer ) );
    written = netcode_write_packet( &request, buffer, sizeof( buffer ), 0, NULL, TEST_PROTOCOL_ID );
    {
        int result = netcode_read_packet( packet_data, buffer, written, NULL, TEST_PROTOCOL_ID, TEST_CURRENT_TIMESTAMP, private_key );
        print_result( 6, buffer, written, result );
    }

    /* 7. wrong protocol id in a connection request */
    buffer[1 + NETCODE_VERSION_INFO_BYTES] ^= 0x01;
    {
        int result = netcode_read_packet( packet_data, buffer, written, NULL, TEST_PROTOCOL_ID, TEST_CURRENT_TIMESTAMP, private_key );
        print_result( 7, buffer, written, result );
    }

    return 0;
}
