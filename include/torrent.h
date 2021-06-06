#pragma once
#include "common.h"
#include "tracker.h"
#include <vector>
#include "peer.h"
#include "sha.h"
#include "bencode.h"
#include "utils.h"
#include "thpool.h"
#include <mutex>

#define TORRENT_BUFFER_SIZE 10


struct piece
{
    std::atomic<i32> id = {-1};
    std::atomic<u32> counter = {0};
    std::mutex lock;
    u8* buffer = nullptr;
    struct timespec last_request = {0};
    u32 peer = -1;
};

#include <deque>

struct piece_hashes
{
    char* hash;
    u32 length;
};

struct torrent
{
    struct node* metainfo = nullptr;
    struct piece_hashes hashes;
    i8 info_hash[20];
    i8 client_id[20];
    std::vector<struct tracker> trackers;
    std::vector<struct peer> peers;
    std::deque<std::mutex> mutex_arr;
    u32 total_size = 0;
    u32 uploaded = 0;
    u32 downloaded = 0;
    u32 n_of_pieces = 0;
    u32 piece_size = 0;
    std::mutex general_lock;
    threadpool thpool = thpool_init(4);
    fd_set main_set;
    volatile u8 * bitfield = nullptr;
    u32 bitfield_size = 0;
    struct piece buffered_pieces[TORRENT_BUFFER_SIZE];
    u32 file_descriptor = -1;
};


#pragma pack(push, 1)
struct handshake_mex
{
    u8 pstr_len = 19;
    char pstr[19] = {'B','i','t','T','o','r','r','e','n','t',' ','p','r','o','t','o','c','o','l'};
    u8 res[8] = {0};
    u8 info_hash[20];
    u8 peer_id[20];

};
#pragma pack(pop)

u32 decode_torrent_size(struct node* tree);
bool decode_torrent(const char* filename, struct torrent* res);
void get_peer_list(struct torrent* main_torrent);
void connect_to_peer(void* pair);
void setup_peer_connections(struct torrent* main_torrent);
void start_torrent(struct torrent* main_torrent);
void handle_mex(void* p, void* t);
bool check_and_commit(u32 buffered_id, struct torrent* main_torrent);
void stop_torrent(i32 code);
void decode_file(struct torrent* main_torrent);
