// SQLight, tiny MySQL C++11 client. Based on code by Ladislav Nevery.
// - rlyeh, 2013. zlib/libpng licensed

#include <string.h>
#include <stdlib.h>
#include <cstdint>
#include <cassert>
#include <errno.h>

#include <algorithm>
#include <map>
// #include <mutex>
#include <string>
#include <vector>

// (DCMMC) from include/linux/socket.h
#define MSG_PEEK    2
#define MSG_DONTWAIT    0x40    /* Nonblocking io        */
#define MSG_NOSIGNAL    0x4000  /* Do not generate SIGPIPE */

// (DCMMC debug)
#include "../log.h"
#include "../debug.h"

#   define INIT()                    {}
#   define $welse(...) __VA_ARGS__
#   define $windows(...)

#include "../Enclave_t.h"
#include "sqlight.hpp"

namespace {
    // knot c&p in the future we must do it right
    enum
    {
        TCP_OK = 0,
        TCP_ERROR = -1,
        TCP_TIMEOUT = -2
            //      TCP_DISCONNECTED = -3,
    };

    // We must complete socket functions, timeout socket receptions.
    // This is just a fix and it will block if count bytes are
    // never received
    int recvfixed(int sockfd, void *buffer, size_t count, int flags) {
        char *_buffer = (char*)buffer;
        while (count) {
            int ret = 0;
            ocall_select(&ret, &sockfd, 1);
            if (ret != TCP_OK)
                return -1;
            ssize_t total = 0;
            ocall_recv((ssize_t *)&total, sockfd, _buffer, count, flags);
            // Sometimes when the socket is closed it has unexpected behavior
            if (total<=0)
                return -1;

            _buffer+=total;
            count-=total;
        }
        return 1;
    }

    typedef uint32_t basetype;
    typedef std::vector<basetype> hash;

    // Mostly based on Paul E. Jones' sha1 implementation
    static hash SHA1( const void *pMem, basetype iLen, hash &my_hash )
    {
        // if( pMem == 0 || iLen == 0 ) return my_hash;

        struct Process
        {
            static basetype CircularShift(int bits, basetype word)
            {
                return ((word << bits) & 0xFFFFFFFF) | ((word & 0xFFFFFFFF) >> (32-bits));
            }

            static void MessageBlock( hash &H, unsigned char *Message_Block, int &Message_Block_Index )
            {
                const basetype K[] = {                  // Constants defined for SHA-1
                    0x5A827999,
                    0x6ED9EBA1,
                    0x8F1BBCDC,
                    0xCA62C1D6
                };
                int     t;                          // Loop counter
                basetype    temp;                       // Temporary word value
                basetype    W[80];                      // Word sequence
                basetype    A, B, C, D, E;              // Word buffers

                /*
                 *  Initialize the first 16 words in the array W
                 */
                for(t = 0; t < 16; t++)
                {
                    W[t] = ((basetype) Message_Block[t * 4]) << 24;
                    W[t] |= ((basetype) Message_Block[t * 4 + 1]) << 16;
                    W[t] |= ((basetype) Message_Block[t * 4 + 2]) << 8;
                    W[t] |= ((basetype) Message_Block[t * 4 + 3]);
                }

                for(t = 16; t < 80; t++)
                {
                    W[t] = CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
                }

                A = H[0];
                B = H[1];
                C = H[2];
                D = H[3];
                E = H[4];

                for(t = 0; t < 20; t++)
                {
                    temp = CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0]; //D^(B&(C^D))
                    temp &= 0xFFFFFFFF;
                    E = D;
                    D = C;
                    C = CircularShift(30,B);
                    B = A;
                    A = temp;
                }

                for(t = 20; t < 40; t++)
                {
                    temp = CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
                    temp &= 0xFFFFFFFF;
                    E = D;
                    D = C;
                    C = CircularShift(30,B);
                    B = A;
                    A = temp;
                }

                for(t = 40; t < 60; t++)
                {
                    temp = CircularShift(5,A) +
                        ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];         //(B & C) | (D & (B | C))
                    temp &= 0xFFFFFFFF;
                    E = D;
                    D = C;
                    C = CircularShift(30,B);
                    B = A;
                    A = temp;
                }

                for(t = 60; t < 80; t++)
                {
                    temp = CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
                    temp &= 0xFFFFFFFF;
                    E = D;
                    D = C;
                    C = CircularShift(30,B);
                    B = A;
                    A = temp;
                }

                H[0] = (H[0] + A) & 0xFFFFFFFF;
                H[1] = (H[1] + B) & 0xFFFFFFFF;
                H[2] = (H[2] + C) & 0xFFFFFFFF;
                H[3] = (H[3] + D) & 0xFFFFFFFF;
                H[4] = (H[4] + E) & 0xFFFFFFFF;

                Message_Block_Index = 0;
            }
        };

        // 512-bit message blocks
        unsigned char Message_Block[64];
        // Index into message block array
        int Message_Block_Index = 0;
        // Message length in bits
        basetype Length_Low = 0, Length_High = 0;

        if( iLen > 0 )
        {
            // Is the message digest corrupted?
            bool Corrupted = false;

            // Input()

            unsigned char *message_array = (unsigned char *)pMem;

            while(iLen-- && !Corrupted)
            {
                Message_Block[Message_Block_Index++] = (*message_array & 0xFF);

                Length_Low += 8;
                Length_Low &= 0xFFFFFFFF;               // Force it to 32 bits
                if (Length_Low == 0)
                {
                    Length_High++;
                    Length_High &= 0xFFFFFFFF;          // Force it to 32 bits
                    if (Length_High == 0)
                    {
                        Corrupted = true;               // Message is too long
                    }
                }

                if (Message_Block_Index == 64)
                {
                    Process::MessageBlock( my_hash, Message_Block, Message_Block_Index );
                }

                message_array++;
            }

            assert( !Corrupted );
        }

        // Result() and PadMessage()

        /*
         *  Check to see if the current message block is too small to hold
         *  the initial padding bits and length.  If so, we will pad the
         *  block, process it, and then continue padding into a second block.
         */
        if (Message_Block_Index > 55)
        {
            Message_Block[Message_Block_Index++] = 0x80;

            while(Message_Block_Index < 64)
            {
                Message_Block[Message_Block_Index++] = 0;
            }

            Process::MessageBlock( my_hash, Message_Block, Message_Block_Index );

            while(Message_Block_Index < 56)
            {
                Message_Block[Message_Block_Index++] = 0;
            }
        }
        else
        {
            Message_Block[Message_Block_Index++] = 0x80;

            while(Message_Block_Index < 56)
            {
                Message_Block[Message_Block_Index++] = 0;
            }
        }

        /*
         *  Store the message length as the last 8 octets
         */
        Message_Block[56] = (Length_High >> 24) & 0xFF;
        Message_Block[57] = (Length_High >> 16) & 0xFF;
        Message_Block[58] = (Length_High >> 8) & 0xFF;
        Message_Block[59] = (Length_High) & 0xFF;
        Message_Block[60] = (Length_Low >> 24) & 0xFF;
        Message_Block[61] = (Length_Low >> 16) & 0xFF;
        Message_Block[62] = (Length_Low >> 8) & 0xFF;
        Message_Block[63] = (Length_Low) & 0xFF;

        Process::MessageBlock( my_hash, Message_Block, Message_Block_Index );

        return my_hash;
    }

    template< typename T >
        hash SHA1( const T &input ) {
            hash h(5);
            h[0] = 0x67452301, h[1] = 0xEFCDAB89,
                h[2] = 0x98BADCFE, h[3] = 0x10325476,
                h[4] = 0xC3D2E1F0;
            hash raw = SHA1( input.data(), input.size() * sizeof( *input.begin() ), h );
            return raw;
        }

    hash SHA1( const void *mem, int len ) {
        hash h(5);
        h[0] = 0x67452301, h[1] = 0xEFCDAB89,
            h[2] = 0x98BADCFE, h[3] = 0x10325476,
            h[4] = 0xC3D2E1F0;
        hash raw = SHA1( mem, len, h );
        return raw;
    }

    std::vector<unsigned char> blob( const hash &raw ) {
        std::vector<unsigned char> blob;
        for( std::vector<basetype>::const_iterator it = raw.begin(); it != raw.end(); ++it ) {
            static int i = 1;
            static char *low = (char*)&i;
            static bool is_big = ( *low ? false : true );
            if( is_big )
                for( int i = 0; i < sizeof(basetype); ++i )
                    blob.push_back( ( (*it) >> (i * 8) ) & 0xff );
            else
                for( int i = sizeof(basetype) - 1; i >= 0; --i )
                    blob.push_back( ( (*it) >> (i * 8) ) & 0xff );
        }
        return blob;
    }
}

namespace
{
    std::vector<unsigned char> get_mysql_hash( const std::vector<unsigned char> &password, const unsigned char salt[20] )
    {
        // [ref] http://dev.mysql.com/doc/internals/en/authentication-method.html#packet-Authentication::Native41
        // SHA1( password ) XOR SHA1( "20-bytes random data from server" <concat> SHA1( SHA1( password ) ) )

        std::vector<unsigned char> hash1 = password; // blob( SHA1( "password" ) );
        std::vector<unsigned char> hash2 = blob( SHA1( hash1 ) );

        unsigned char concat[40];
        for( size_t i = 0; i < 40; i++ )
            concat[i] = ( i < 20 ? salt[i] : hash2[i-20] );

        std::vector<unsigned char> hash3 = blob( SHA1( concat, 40 ) );

        for( size_t i = 0; i < 20; ++i )
            hash3[i] ^= hash1[i];

        return hash3;
    }
}

#ifdef _MSC_VER
#   pragma warning( push )
#   pragma warning( disable : 4996 )
#endif

sq::light::light() : s(0), connected(false) {
    INIT();
}

sq::light::~light() {
    disconnect();
}

bool sq::light::acquire() {
    release();

    buf.resize( 1 << 24 ); // recv buffer is max row size 16 mb
    b = d = buf.data();

    return true;
}

void sq::light::release() {
    buf = std::vector<char>();
    b = d = 0;
}

bool sq::light::connect( const std::string &host, unsigned port, const std::string &user, const std::string &pass )
{
    if( user.empty() || pass.empty() || host.empty() || port == 0 || port >= 65536 )
        return false;

    this->host = host;
    this->port = port;
    this->user = user;
    this->pass = blob( SHA1( pass ) );

    return reconnect();
}

bool sq::light::reconnect() {
    disconnect();
    release();

    if( !acquire() )
        return false;

    connected = true;
    if( !test("SHOW DATABASES") )
        return connected = false;

    return connected = true;
}

void sq::light::disconnect() {
    if (s)
    {
        int ret = 0;
        ocall_close(&ret, s);
    }
    s = 0;
    connected = false;
}

// bool sq::light::is_connected() {
//   char buf;
//
//   if (!connected)
//     return false;
//
//   int res = recvfixed(s, &buf, 1, MSG_PEEK | $windows(0) $welse(MSG_DONTWAIT));
//   if (res<0)
//     {
//       // Maybe disconnected or maybe not...
//       if (errno != EAGAIN && errno != EWOULDBLOCK)
//     connected = false;
//     }
//   else if (res==0)
//     {
//       connected = false;
//     }
//
//   return connected;
// }

bool sq::light::fail( const char *error, const char *title )
{
    //disconnect();
    // (DCMMC) fail info
    LL_INFO("FAIL (%s): %s", title, error);
    return false;
}

bool sq::light::open()
{
    if(!s) {

        // (DCMMC) 使用 MBED TLS 库里面的函数来创建 TCP 连接
        // int ret = 0;
        // ocall_connect(&ret, &s, port, const_cast<char*>(host.c_str()));
        // if (ret < 0)
        //     return fail("Connect Failed  ");
        init_tls();

        ocall_recv((ssize_t *)&i, s, b, 1<<24, 0);

        // b: Protocol::HandshakeV10
        if (b[4] < 10 ) return fail(b+5,"Need MySql > 4.1");

        // Read server auth challenge and calc response by making SHA1 hashes from it and password
        // [ref] http://dev.mysql.com/doc/internals/en/connection-phase.html#packet-Protocol::Handshake

        std::vector<unsigned char> hash;

        // (lower 2 bytes)
        int capability_flag_1 = 0;
        capability_flag_1 += (int)(*((byte *)b + strlen(b + 5) + 19));
        capability_flag_1 += ((int)(*((byte *)b + strlen(b + 5) + 20))) << 8;
        LL_INFO("(DCMMC) MySQL capability flag of server: 0x%x%x",
                capability_flag_1 >> 8, capability_flag_1 & 0xff);
        hexdump("HandshakeV10", b, 48);

        // Construct client auth response
        // [ref] http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol#Client_Authentication_Packet

        // int<4> capability_flags
        capability_flags =
            CLIENT_FOUND_ROWS|
            CLIENT_PROTOCOL_41|
            CLIENT_SECURE_CONNECTION|
            CLIENT_LONG_PASSWORD|
            CLIENT_MULTI_RESULTS;        // for stored procedures
        // (DCMMC) if server support CLIENT_SSL, we use SSL
        if (capability_flag_1 & CLIENT_SSL)
        {
            LL_INFO("MySQL server supports SSL, client will send SSL Request Packet.");
            use_tls = true;
            // [ref] https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest
            capability_flags |= CLIENT_SSL;
            char ssl_req[36] = {0};
            // header
            // payload length: 32, sequence id: 1
            *(int *) ssl_req = 32 | (1 << 24);
            // capability flags, CLIENT_SSL always set
            *(int *) (ssl_req + 4) = capability_flags;
            // max-packet size: 16M
            *(int *) (ssl_req + 8) = 1 << 24;
            // character set: utf-8
            *(int *) (ssl_req + 12) = 8;
            // 23 bytes reserved (all [0])
            ocall_send((ssize_t *)&ret, s, ssl_req, 36, 0);
            LL_INFO("(DCMMC) SSL request packet sent.");
            connect_tls(host, port);
        }
        else
        {
            LL_CRITICAL("MySQL server does not support SSL!");
        }

        d = b + 4;
        {
            // salt: data start from auth-plugin-data-part-1
            byte *salt = (byte*)b+strlen(b+5)+10;
            memcpy(salt+8,salt+27,13);
            hash = get_mysql_hash( pass, salt );
        }
        *(int*)d = capability_flags;
        d+=4;

        *(int*)d = 1<<24;
        d += 4;      // max packet size = 16Mb
        // utf8 charset
        *d = 8;
        d += 1;
        memset(d, 0, 23);
        // 23 reversed (all 0)
        d += 23;
        memcpy(d, user.c_str(), user.size() + 1);
        d += 1 + user.size();
        // CLIENT_SECURE_CONNECTION, not CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
        *d = 20;
        d += 1;
        // 20 bytes auth-response
        for (i=0; i < 20; i++)
            d[i] = hash[i]^0;
        d += 22;     // XOR encrypt response
        // 4 bytes header of MySQL Packet
        // [ref] https://dev.mysql.com/doc/internals/en/mysql-packet.html
        // sequence id: 2
        *(int*)b = d-b-4 | (use_tls ? 2 : 1) << 24;                // calc final packet size and id

        if (use_tls)
            ret = send_tls(b, d - b);
        else
            ocall_send((ssize_t *)&ret, s, b, d - b, 0);
        LL_INFO("(DCMMC) client response sent.");

        if (use_tls)
            ret = recv_tls((char *) &no, 4);
        else
            ocall_recv((ssize_t *)&ret, s, (char *) &no, 4, 0);
        no &= (1<<24)-1;   // in case of login failure server sends us an error text
        LL_INFO("(DCMMC) receive no = %d", no);
        if (use_tls)
            ret = recv_tls(b, no);
        else
            ocall_recv((ssize_t *)&i, s, b, no, 0);
        hexdump("HandshakeResponse41", b, 48);

        if (i == -1 || *b)
            return fail(i==-1?"Timeout":b+3,"Login Failed");
    }

    return true;
}

bool sq::light::sends( const std::string &query )
{
    // Send sql query
    // Details at: http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol#Command_Packet
    // [ref] https://dev.mysql.com/doc/internals/en/com-query.html

    LL_INFO("(DCMMC) sends query=%s", query.c_str());
    d[4]=0x3;
    memcpy(d + 5, const_cast<char*>(query.c_str()), query.size() + 1);
    *(int*)d=strlen(d+5)+1;
    if (use_tls)
        i = send_tls(d, 4 + *((int *) d));
    else
        ocall_send((ssize_t *)&i, s, d, 4 + *((int *) d), $windows(0) $welse(MSG_NOSIGNAL));
    LL_INFO("(DCMMC) sends return=%d", i);
    if (i<0)
        return false;
    return true;
}

bool sq::light::recvs( void *userdata, void* onvalue, void* onfield, void *onsep )
{
    // Parse and display record set
    // Details at: http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol#Result_Set_Header_Packet
    // [ref] http://dev.mysql.com/doc/internals/en/overview.html#status-flags

    std::vector<char> txtv(65536, 0); // medium blob
    char *txt = txtv.data();

    char *buf_ptr = b;
    byte typ[1000] = {0};
    int fields=0, field=0, value=0, row=0, exit=0;
    // (DCMMC) 接收到的网络数据大小
    size_t received_size = 0;

    // (DCMMC) TODO deprecated
    // char &b0 = b[0];
    // char &b1 = b[1]; // warning count  low byte
    // char &b2 = b[2]; // warning count high byte
    // char &b3 = b[3]; // status  low byte
    // char &b4 = b[4]; // status high byte

    while (true) {
        if (use_tls)
        {
            // (DCMMC) receive 1MB at most
            // (TODO) may lead to error when data >= 1MB!
            // (DCMMC) TLS 会一次性把这些小包全部合在一起成一个包，不过依然会出现
            // 需要复杂的 fragment 的时候，现在暂不考虑...
            if (buf_ptr - b >= received_size) {
                LL_INFO("(DCMMC) received data are empty or run out.");
                buf_ptr = b;
                i = recv_tls(buf_ptr, 1 << 24);
                LL_INFO("(DCMMC) tls ret(length)=%d", i);
		hexdump("(DCMMC) Whole data received from tls", b, i);
                received_size = i;
            }
            no = *((int *)buf_ptr);
            buf_ptr += 4;
            no &= 0xffffff;
            LL_INFO("(DCMMC) new packet with no=%d", no);
            hexdump("Current processing Packet", buf_ptr - 4, no + 4);
        }
        else
        {
            buf_ptr = b;
            i = recvfixed(s, (char*)&no, 4, 0);
            // i=RECV(s,(char*)&no,4,0);
            // This is a bug. server sometimes don't send those 4 bytes together. will fix it (recvfixed fix the bug)
            // this also helps to skip packet sequence number: http://mysql.timesoft.cc/doc/internals/en/the-packet-header.html
            // (DCMMC) remove sequence id
            no &= 0xffffff;
            LL_INFO("(DCMMC) recv with no=%d", no);

            if (i < 0)
                return fail("connection lost");

            int rc = 0;
            while (rc < no)
            {
                ocall_recv((ssize_t *)&i, s, b + rc, no - rc, 0);
                if (i > 0)
                    rc += i;
                else
                    break;
            }
            if(i < 1)
                return fail("connection lost"); // Connection lost
        } // not use_tls
        // 0. For non query sql commands we get just single success or failure response
        // OK_Packet

        byte header = *(byte *) buf_ptr;
        // ERR_Packet
        // https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
        if (header == 0xff && !exit) {
            int error_code = (int)(*(((byte *)buf_ptr) + 1));
            error_code += ((int)(*(((byte *)buf_ptr) + 2))) << 8;
            int offset = capability_flags & CLIENT_PROTOCOL_41 ? 3 : 9;
            return fail(buf_ptr + offset, ("error_code=" + std::to_string(error_code)).c_str());
        } // failure: show server error text

        if (header == 0x00 && !exit)
        {
            LL_DEBUG("OK Packet (indicates non query sql commands we get just single success)");
            break;
        }

        // 1. first thing we receive is number of fields
        if(!fields) {
            fields = header;
            if (fields == 0xfc) {
                fields = (int)(*(((byte *) buf_ptr) + 2));
                fields += (int)(*(((byte *) buf_ptr) + 3)) << 8;
            }
            else if (fields == 0xfd) {
                // (DCMMC) TODO
            }
            else if (fields == 0xfe) {
                // (DCMMC) TODO
            }
            field = fields;
            LL_INFO("(DCMMC) first thing: number of fields=%d", fields);
	    buf_ptr += no;

            // https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
            if (fields == 0) {
                break;
            }
            else {
                continue;
            }
        } // field_count

        // 3. 5. after receiving last field info or row we get this EOF marker or more results exist
        // OK_Packet with EOF
        if (header == 0xfe && no < 9)
        {
            int status_flags_offset = 3;
            // deprected
            // (DCMMC) i.e. MySQL 7.5.6 and up uses OK Packet to represent EOF packet, and deprecat EOF Packet
            LL_INFO("(DCMMC) EOF Packet");
            // LL_INFO("(DCMMC) offset of status flags=%d", status_flags_offset);
            int status = (buf_ptr[status_flags_offset + 1] << 8) | buf_ptr[status_flags_offset];
            LL_INFO("(DCMMC) status flags=%d", status);
	    buf_ptr += no;
            if (status & 0x0008) {
		// no = 5
                // SERVER_MORE_RESULTS_EXISTS
                typedef void (*TOnSep)(void *);
                if (onsep)
                    ((TOnSep)onsep)(userdata);
                LL_INFO("(DCMMC) server has more results exists");
                continue;
            }
            else {
		// (DCMMC) first EOF is between column_def and row
                LL_INFO("(DCMMC) EOF");
		if (exit++)
			break;
		else
			continue;
            }
        }


        // 4. after receiving all field infos we receive row field values. One row per Receive/Packet
        while( value ) {
            *txt = 0;
            i = fields - field;
            size_t len = 1;
            byte g = *(byte *) buf_ptr;

            // ~net_field_length() @ libmysql.c {
            // int<lenenc>
            switch (g) {
                case 0:
                case 251: g=0;      break; // NULL_LENGTH
                default:
                case   1: g=1;      break;
                case 252: g=2, ++buf_ptr; break;
                case 253: g=3, ++buf_ptr; break;
                case 254: g=8, ++buf_ptr; break;
            }
            // @todo: beware little/big endianess here!
            memcpy(&len, buf_ptr, g);
            buf_ptr += g;
            //}

            auto &type = typ[i];
	    LL_INFO("(DCMMC) lenenc=%d, type=%d", len, type);
            switch( type )
            {
                case FIELD_TYPE_BIT:
                case FIELD_TYPE_BLOB:
                case FIELD_TYPE_DATE:
                case FIELD_TYPE_DATETIME:
                case FIELD_TYPE_DECIMAL:
                case FIELD_TYPE_DOUBLE:
                case FIELD_TYPE_ENUM:
                case FIELD_TYPE_FLOAT:
                case FIELD_TYPE_GEOMETRY:
                case FIELD_TYPE_INT24:
                case FIELD_TYPE_LONG:
                case FIELD_TYPE_LONG_BLOB:
                case FIELD_TYPE_LONGLONG:
                case FIELD_TYPE_MEDIUM_BLOB:
                case FIELD_TYPE_NEW_DECIMAL:
                case FIELD_TYPE_NEWDATE:
                case FIELD_TYPE_NULL:
                case FIELD_TYPE_SET:
                case FIELD_TYPE_SHORT:
                case FIELD_TYPE_STRING:
                case FIELD_TYPE_TIME:
                case FIELD_TYPE_TIMESTAMP:
                case FIELD_TYPE_TINY:
                case FIELD_TYPE_TINY_BLOB:
                case FIELD_TYPE_VAR_STRING:
                case FIELD_TYPE_VARCHAR:
                case FIELD_TYPE_YEAR:
                default: {
                     // @todo: beware little/big endianess here!
                     if (g)
                         memcpy(txt, buf_ptr, len);
                     txt[len] = 0;
		     LL_INFO("(DCMMC) ResultsetRow=%s", txt);
                     typedef long (*TOnValue)(void *,char*,int,int,int);
                     if (onvalue)
                         ret = ((TOnValue)onvalue)(userdata,txt,row,i,type);
                     break;
                 }
            }

            buf_ptr += len;
            if(!--value) {
                row++;
                value = fields;
                break;
            }
        }

        // 2. Second info we get are field infos like name type etc. One field per Receive/Packet
        // ColumnDefinition41
        if( field ) {
            i = fields - field;
            char *cat = buf_ptr;
            buf_ptr += 1 + *buf_ptr;
            *cat++ = 0;
            char *db = buf_ptr;
            buf_ptr += 1 + *buf_ptr;
            *db++ = 0;
            char *table = buf_ptr;
            buf_ptr += 1 + *buf_ptr;
            *table++ = 0;
            char *table_ = buf_ptr;
            buf_ptr += 1 + *buf_ptr;
            *table_++ = 0;
            char *name = buf_ptr;
            buf_ptr += 1 + *buf_ptr;
            *name++ = 0;
            char *name_ = buf_ptr;
            buf_ptr += 1 + *buf_ptr;
            *name_++=0;
            *buf_ptr++ = 0;
            short charset = *(short*)buf_ptr;
            buf_ptr += 2;
            long length = *(long *)buf_ptr;
            buf_ptr += 4;
            typ[i] = *(byte *) buf_ptr;
            buf_ptr += 1;
            short flags = *(short *) buf_ptr;
            buf_ptr += 2;
            byte digits = *(byte *) buf_ptr;
            buf_ptr += 3;
            char* Default = buf_ptr;

            auto &type = typ[i];
            switch( type )
            {
                case FIELD_TYPE_STRING:
                case FIELD_TYPE_VAR_STRING:
                case FIELD_TYPE_LONG:
                case FIELD_TYPE_LONGLONG:
                case FIELD_TYPE_DATETIME:
                case FIELD_TYPE_DATE:
                case FIELD_TYPE_FLOAT:
                case FIELD_TYPE_TINY:
                case FIELD_TYPE_BLOB:
                case FIELD_TYPE_NEW_DECIMAL:
                    break;
                default:
                    // (DCMMC) eliminate iostream
                    LL_CRITICAL("Warning: unsupported type %d in column: %s\n", int(type), name);
                    // std::cerr << "Warning: unsupported type " << int(type) << " in column: " << name << std::endl;
            }

            if(!--field)
                value = fields;
            length = std::max(length * 3, 60L);
            length = std::min(length, 200L);
            typedef long (*TOnField)(void *,char*,int,int,int);
            if (onfield)
                ((TOnField)onfield)(userdata,name,row,i,length);
        }
    }

    return true;
}

namespace
{
    char *strdup(char *txt)
    {
        char *txt_copy = (char *)malloc(strlen(txt) + 1);
        memcpy(txt_copy, txt, strlen(txt) + 1);
        return txt_copy;
    }

    struct local {
        int x, y;
        std::vector< char * > data;
        std::vector< char * > head;

        local() : x(0),y(0) {
        }

        ~local() {
            for( unsigned i = 0, end = data.size(); i < end; ++i )
                if( data[i] ) free( data[i] ), data[i] = 0;
            for( unsigned i = 0, end = head.size(); i < end; ++i )
                if( head[i] ) free( head[i] ), head[i] = 0;
        }
    };

    void GetText2f( void *userdata, char* txt ) {
        local *l = (local *)userdata;
        l->head.push_back( txt ? strdup(txt) : strdup("") );
    }
    void GetText2v( void *userdata, char* txt ) {
        local *l = (local *)userdata;
        l->data.push_back( txt ? strdup(txt) : strdup("") );
    }

    void GetText3f( void *userdata, char* txt ) {
        local *l = (local *)userdata;
        l->x++;
        l->y++;
        l->data.push_back( txt ? strdup(txt) : strdup("") );
    }
    void GetText3v( void *userdata, char* txt ) {
        local *l = (local *)userdata;
        l->y++;
        l->data.push_back( txt ? strdup(txt) : strdup("") );
    }
}

bool sq::light::test( const std::string &query )
{
    if( !connected )
        return false;

    // std::lock_guard<std::mutex> lock(mutex);

    no = 20;
    ret = 0;

    if( !query.empty() )
        if( open() ) // setup
            if( sends(query) ) // send
                if( recvs(0, 0, 0, 0) ) // recv and parse
                    return true;

    return false;
}

bool sq::light::exec( const std::string &query, sq::light::callback3 cb3, void *userdata )
{
    if( !connected )
        return false;

    // std::lock_guard<std::mutex> lock(mutex);

    local l;

    no = 20;
    ret = 0;

    if( !query.empty() )
        if( open() ) // setup
            if( sends(query) ) // send
                if( recvs( (void *)&l /*userdata*/, (void *)GetText3v, (void *)GetText3f, 0 /*onsep*/) ) { // recv and parse
                    if( l.x > 0 )
                        (*cb3)( userdata, l.x, l.y / l.x, (const char **)l.data.data() );
                    return true;
                }

    return false;
}

namespace {
    std::string escape( const std::string &text )  {
        std::string out;
        for( auto &it : text ) {
            /**/ if( it == '\\' ) out += "\\\\";
            else if( it == '\r' ) out += "\\r";
            else if( it == '\n' ) out += "\\n";
            else if( it == '\t' ) out += "\\t";
            else if( it == '\f' ) out += "\\f";
            else if( it == '\b' ) out += "\\b";
            else if( it == '\v' ) out += "\\v";
            else if( it ==  '"' ) out += "\\\"";
            else                  out += it;
        }
        return out;
    }
    void OnJSONCb( void *userdata, int w, int h, const char **map ) {
        std::string &array = *((std::string*)userdata);
        const char **field = &map[0];
        const char **value = &map[w];
        for( int y = 1; y < h; ++y ) {
            array += "{\n";
            for( int x = 0; x < w; ++x ) {
                array += "\"" + escape(std::string(*field++)) + "\": ";
                array += "\"" + escape(std::string(*value++)) + "\",\n";
            }
            if( w > 0 ) array[array.size()-2] = ' ';
            array += "},\n";

            field = map;
        }
        if( h > 0 && array.size() >= 2 ) array[array.size()-2] = ' ';
        array = "[\n" + array + "]\n";
    }
}

bool sq::light::json( const std::string &query, std::string &result ) {
    result = std::string();
    bool ok = exec(query,OnJSONCb,(void *)&result);
    if( !ok )
        result = std::string();
    return ok;
}

std::string sq::light::json( const std::string &query ) {
    std::string result;
    return json(query,result) ? result : std::string();
}

#undef INIT

#ifdef _MSC_VER
#   pragma warning( pop )
#endif
