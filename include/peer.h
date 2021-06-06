#pragma once
#include "common.h"
#include "types.h"
#include <atomic>
#pragma pack(push, 1)
struct peer_info
{
    i32 ip;
    u16 port;
};
#pragma pack(pop)
#include <mutex>


//deallocate bitfield
struct peer
{
    struct peer_info info;
    int served = {0};
    int sock = -1;
    bool am_choking = true;
    bool am_interested = false;
    bool is_choking = true;
    bool is_interested = false;
    u8* bitfield = nullptr;
    u32 bitfield_size = 0;
    struct timespec timestamp;
};

#pragma pack(push, 1)
struct general_message
{
    u32 length_prefix;
    u8 id;
};
#pragma pack(pop)

