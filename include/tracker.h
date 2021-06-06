#pragma once
#include "common.h"
#include "types.h"

struct tracker
{
    std::string name;
    int sock;
    struct addrinfo* addr_info;
    i64 connection_id;
    bool active = false;
};

//messages

#pragma pack(push, 1)
struct connection_req
{
    i64 connection_id = htobe64(0x41727101980);
    i32 action = 0;
    i32 transaction_id;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct connection_res
{
    i32 action;
    i32 transaction_id;
    i64 connection_id;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct connection_announce_req
{
    i64 connection_id;
    i32 action = htobe32(1);
    i32 transaction_id;
    i8 info_hash[20];
    i8 peer_id[20];
    i64 downloaded;
    i64 left;
    i64 uploaded;
    i32 event;
    u32 ip = 0;
    u32 key;
    i32 num_want = htobe32(10);
    u16 port;
    //u16 extensions;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct connection_announce_res
{
    i32 action;
    i32 transaction_id;
    i32 interval;
    i32 leechers;
    i32 seeders;
};
#pragma pack(pop)
