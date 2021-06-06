#pragma once
#include <string>
#include <vector>
#include "peer.h"
#include "tracker.h"
#include "common.h"

bool tracker_in_vector(std::vector <struct tracker>& v, std::string name);
bool peer_in_vector(std::vector <struct peer>& v, struct peer_info& val);
std::string url_encode(std::string& raw); 
i32 find(char* str, i32 size, i32 starting_pos, std::string del);
i32 find(char* str, i32 size, std::string del);

inline u32 min(u32 a, u32 b)
{
	return a < b ? a : b;
}

inline u8 bitfield_is_set(volatile u8* bitfield, u32 index)
{
	if(!bitfield)return 0;
	u32 byte = index / 8;
    u8 bit = index % 8;
	return (bitfield[byte] >> (7 - bit)) & 0x1;
}

inline void bitfield_set(volatile u8* bitfield, u32 index)
{
	if(!bitfield)return;
	u32 byte = index / 8;
    u8 bit = index % 8;
	bitfield[byte] |= (0x80 >> bit);
}

bool correct_read(u32 sock, u8* buf, i32 size, u32 timeout_s = 0);

inline u64 get_elapsed_milliseconds(struct timespec *end, struct timespec *start)
{
	u64 t1 = (end->tv_sec - start->tv_sec) * 1e9;
	i64 t2 = (end->tv_nsec - start->tv_nsec);
	return (t1 + t2) / 1e6;
}
