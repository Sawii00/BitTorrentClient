#include "common.h"
#include "torrent.h"
#include "tracker.h"
#include "peer.h"
#include "thpool.h"
#include <thread>
#include <signal.h>
/*
std::string compute_escape_info_hash(char* file, u32 size)
{
    i32 pos = find(file, size, "4:info");
    struct internal_state hash = sha1((u8*)file + pos + 6, size - pos - 6 - 1);
    std::string hash_str = state_to_string(hash);
    return url_encode(hash_str);
}

std::string compute_escaped_user_id(void)
{
    std::string id_str = "NP";
    id_str += std::to_string(time(NULL));
    struct internal_state hash = sha1((u8*)id_str.c_str(), id_str.size());
    std::string hash_str = state_to_string(hash);
    return url_encode(hash_str);
}
*/

/*
TODO:
	- test multiple requests to different peers

PROBLEMS:
*/

int main(int argc, char** argv)
{
    
    if (argc != 2)
    {
        std::cerr << "Invalid Usage: .torrent is missing\n";
        exit(-1);
    }
	signal(SIGPIPE, SIG_IGN);

    std::thread thread_object([](const char* torrent_name)
    {
        struct torrent main_torrent;
        bool success = decode_torrent(torrent_name, &main_torrent);
        if (!success)
        {
        	std::cout << "Could not decode torrent\n";
        }

        if(main_torrent.trackers.size() == 0)
        {
            std::cerr << "Unable to find trackers\n";
            exit(1);
        }
        start_torrent(&main_torrent);
    }, argv[1]); 

    thread_object.join();
    std::cout << "Exiting application\n";

}
