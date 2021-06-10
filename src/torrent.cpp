#include "common.h"
#include <thread>
#include "torrent.h"
#include "peer.h"
#include "types.h"
#include "thpool.h"
#include <deque>
#include <sys/time.h>
#include <sys/resource.h>
#include <cmath>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <algorithm>



u32 decode_torrent_size(struct node* tree)
{
    std::vector<struct dict_node*> vec;

    get_dict_node("length", tree, vec);
    u32 tot_size = 0;
    for (auto& i : vec)
    {
        tot_size += i->val->value.val_int;
    }

    return tot_size;
}

//handle deallocations
bool decode_torrent(const char* filename, struct torrent* res)
{
    i32 file_id = open(filename, O_RDONLY);
    if (file_id < 0)
    {
    	std::cerr << "Could not open " << filename<<'\n';
    	return false;
    }

    i32 length = lseek(file_id, 0, SEEK_END);
    lseek(file_id, 0, SEEK_SET);

    char* s = (char*)malloc(length);
    char* s_cpy = s;
    read(file_id, s, length);

    close(file_id);
    res->metainfo = decode((char**)&s);

    //hash 
    i32 pos = find(s_cpy, length, "4:info");
    if(pos < 0)
    {
        std::cerr << "No info found\n";
        stop_torrent(-1);
    }

    i32 pieces_pos = find(s_cpy, length, "pieces");
    if(pieces_pos== -1)
    {
        std::cerr << "Could not find pieces\n";
        stop_torrent(1);
    }

    std::string pieces_str = std::string(s_cpy + pieces_pos + 6);
    i32 n_of_pieces = std::stoll(pieces_str);

    if(n_of_pieces % 20 != 0)
    {
        std::cerr << "Invalid Number of Pieces\n";
        stop_torrent(1);
    }
    res->n_of_pieces = n_of_pieces / 20;


    std::vector<struct dict_node*> v; 
    
    get_dict_node("info", res->metainfo, v);
    
    std::vector<struct dict_node*> piece_hash;
    
    if(v.empty())
    {
    	std::cerr << "Could not find info dictionary\n";
    	return false;
    }

    //contains the hash of all the pieces of the torrent
    get_dict_node("pieces", v[0]->val, piece_hash);

    if(piece_hash.empty())
    {
		std::cerr << "Could not find piece hashes\n";
		return false;
    }


    res->hashes.hash = piece_hash[0]->val->value.val_str;
    res->hashes.length = piece_hash[0]->val->size;

    //last will be the final element of the "info" dictionary
    struct dict_node* last = v[0]->val->value.val_dict + v[0]->val->size - 1;
    


    i32 last_key_pos = find(s_cpy, length, std::string(last->key)) + strlen(last->key);
    char* str_cpy = nullptr;

    i32 final_payload_length = strtol(s_cpy + last_key_pos, &str_cpy, 10); 
    i32 n_length = str_cpy - s_cpy - last_key_pos;

    i32 hashing_length = n_length + final_payload_length + last_key_pos - pos - 6 + 2;
    struct internal_state hash = sha1((u8*)s_cpy + pos + 6, hashing_length);

    struct node* n = v[0]->val;
    get_dict_node("piece length", n, v);
    if(v.empty())
        std::cerr << "Cannot retrieve piece length\n";

    struct node* piece_length_node = v[1]->val;
    u32 piece_length = piece_length_node->value.val_int;

    res->piece_size = piece_length;

    for(u8 i = 0; i < TORRENT_BUFFER_SIZE; ++i)
    {
        u8* temp_ptr = (u8*)malloc(sizeof(u8) * piece_length);
        if(temp_ptr != NULL)
        {
            res->buffered_pieces[i].buffer = temp_ptr;
        }
        else
        {
            std::cerr << "Could not allocate memory for buf: " << i << '\n';
        }

    }


    print_state(hash);
    i32 hash_buf[5];
    hash_buf[0] = htobe32(hash.A);
    hash_buf[1] = htobe32(hash.B);
    hash_buf[2] = htobe32(hash.C);
    hash_buf[3] = htobe32(hash.D);
    hash_buf[4] = htobe32(hash.E);

    memcpy(res->info_hash, (i8*)hash_buf, 20);

    free(s_cpy);

    std::vector<struct dict_node*> vec;
    get_dict_node("announce-list", res->metainfo, vec);
    if (vec.empty())
    {
		std::cerr << "Could not find announce-list\n";
		return false;
    }
    struct node* tracker_list = vec[0]->val;

    struct addrinfo* dns_res = NULL;
    //struct sockaddr* tracker_addr = NULL;

    for (i32 i = 0; i < tracker_list->size; ++i)
    {
        std::string s;

        char* str = tracker_list->value.val_arr[i]->value.val_arr[0]->value.val_str;
        if (find(str, strlen(str), "udp") != -1)
            (s = std::string(str));
        else
            continue;

        struct addrinfo hi32s = { 0 };
        hi32s.ai_flags = 0;
        hi32s.ai_family = AF_INET; // IPv4 and IPv6 allowed
        hi32s.ai_socktype = SOCK_DGRAM;


        i32 a = s.find(':', 6);
        std::string addr = s.substr(6, a - 6);
        std::string port = s.substr(a + 1, s.find("/announce") - a - 1);

        if(tracker_in_vector(res->trackers, addr))
            continue;


        i32 error_getaddrinfo = getaddrinfo(addr.c_str(), port.c_str(), &hi32s, &dns_res);
        if (error_getaddrinfo)
            continue;

        //tracker_addr = dns_res->ai_addr;

        i32 sock = socket(dns_res->ai_family, dns_res->ai_socktype, dns_res->ai_protocol);
        if (sock < 0)
        {
        	std::cerr << "Could not create socket with tracker\n";
        	return false;
        }

        struct tracker sess;
        sess.name = addr;
        sess.sock = sock;
        sess.addr_info = dns_res;
        res->trackers.push_back(sess);

    }

    res->file_descriptor = open("tmp", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    if(res->file_descriptor < 0)
    {
        perror("Could not open temp file: ");
        stop_torrent(1);
    }

    u32 n_of_bytes = res->n_of_pieces / 8 + 1;
    res->bitfield = (volatile u8*)malloc(n_of_bytes);
    memset((void*)res->bitfield, 0, n_of_bytes);
    res->bitfield_size = n_of_bytes;


    return true;

}

void get_peer_list(struct torrent* main_torrent)
{

    fd_set read_set; 
    FD_ZERO(&read_set);

    struct connection_req request;
    srand(time(NULL));
    request.transaction_id = rand();

    for (auto &s : main_torrent->trackers)
    {

        i32 sent = sendto(s.sock, &request, sizeof(struct connection_req), 0, s.addr_info->ai_addr, s.addr_info->ai_addrlen);

        if(sent != sizeof(struct connection_req))
        {
        
            std::cerr << "Invalid packet sent\n";
            stop_torrent(-1);
        }

        FD_SET(s.sock, &read_set);

    }

    struct connection_res response;

    struct timeval timeout;
    timeout.tv_sec = 3;

    sleep(1);

    i32 sel_res = select(main_torrent->trackers[main_torrent->trackers.size() - 1].sock + 1, &read_set, NULL, NULL, &timeout);

    if(sel_res <= 0)
    {
        std::cerr << "Unable to find trackers\n";
        stop_torrent(1);
    }

    struct connection_announce_req announce_req;
    announce_req.transaction_id = rand();
    memcpy(announce_req.info_hash, main_torrent->info_hash, 20);


    std::string user_id_str = "NP";
    user_id_str+= std::to_string((i32)time(NULL));
    struct internal_state hash = sha1((u8*)user_id_str.c_str(), user_id_str.size());

    u32 hash_buf[5];
    hash_buf[0] = htobe32(hash.A);
    hash_buf[1] = htobe32(hash.B);
    hash_buf[2] = htobe32(hash.C);
    hash_buf[3] = htobe32(hash.D);
    hash_buf[4] = htobe32(hash.E);

    memcpy(announce_req.peer_id, (i8*)hash_buf, 20);
    memcpy(main_torrent->client_id, (i8*)hash_buf, 20);

    announce_req.downloaded = htobe64(main_torrent->downloaded);
    if(main_torrent->total_size)
        announce_req.left = htobe64(main_torrent->total_size - main_torrent->downloaded);
    else
    {
        announce_req.left = htobe64(decode_torrent_size(main_torrent->metainfo));
        main_torrent->total_size = decode_torrent_size(main_torrent->metainfo);

        //setting RLIMIT_FSIZE for the process
        struct rlimit limit;
        limit.rlim_cur = RLIM_INFINITY;
        limit.rlim_max = RLIM_INFINITY;
        i32 s = setrlimit(RLIMIT_FSIZE, &limit);
        if (s < 0)
        {
            perror("Could not increase RLIMIT_FSIZE: ");
            stop_torrent(1);
        }
    }
    announce_req.uploaded = htobe64(main_torrent->uploaded);

    announce_req.event = htobe32(2);

    announce_req.ip = 0;

    announce_req.key = rand();
    announce_req.num_want = htobe32(50);
    announce_req.port = htobe16(6881);
    //announce_req.extensions = 0;

    FD_ZERO(&read_set);

    u8 temp_buf[512];
    for (auto& s: main_torrent->trackers)
    {

        memset(temp_buf, 0, sizeof(temp_buf));

        i32 recv = recvfrom(s.sock, temp_buf, sizeof(temp_buf), MSG_DONTWAIT,s.addr_info->ai_addr, &(s.addr_info->ai_addrlen));


        if(recv == -1 && (errno == EAGAIN))
            continue;

        s.active = true;

        response = *(struct connection_res*)temp_buf;

        if(response.action == (i32)htobe32(0x3))
        {
            std::cerr << "Error: "<<temp_buf[8]<<'\n';
            continue;
        }

        if(request.transaction_id != response.transaction_id)
        {
            std::cerr << "Invalid transaction id\n";
            stop_torrent(-1);
        }

        s.connection_id = response.connection_id;

        //already big endian
        announce_req.connection_id = s.connection_id;

        i32 sent = sendto(s.sock, &announce_req, sizeof(struct connection_announce_req), 0, s.addr_info->ai_addr, s.addr_info->ai_addrlen);

        if(sent != sizeof(struct connection_announce_req))
        {
            std::cerr << "Invalid packet sent\n";
            stop_torrent(-1);
        }
        FD_SET(s.sock, &read_set);


    }

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    sel_res = select(main_torrent->trackers[main_torrent->trackers.size() - 1].sock + 1, &read_set, NULL, NULL, &timeout);

    if(sel_res <= 0)
    {
        std::cerr << "Unable to find trackers\n";
        stop_torrent(1);
    }

    sleep(1);
    struct connection_announce_res announce_res;
    for (auto& s: main_torrent->trackers)
    {

        if(!s.active)
            continue;

        u8 temp_buf[512];
        memset(temp_buf, 0, sizeof(temp_buf));

        i32 recv = recvfrom(s.sock, temp_buf, sizeof(temp_buf), MSG_DONTWAIT,s.addr_info->ai_addr, &(s.addr_info->ai_addrlen));


        if(recv == -1 && (errno == EAGAIN))
            continue;

        announce_res = *(struct connection_announce_res*)temp_buf;

        std::cout << "\nTracker: "<< s.name << '\n';
        std::cout << "Leechers: "<< be32toh(announce_res.leechers) << '\n';
        std::cout << "Seeders: " << be32toh(announce_res.seeders) << '\n';
        std::cout << "i32erval: " << be32toh(announce_res.interval) << '\n';

        if(recv < sizeof(struct connection_announce_res))
        {
            std::cerr << "Invalid packet received\n";
            stop_torrent(-1);
        }

        if(announce_res.action == (i32)htobe32(0x3))
        {
            std::cerr << "Error: "<<temp_buf[8]<<'\n';
            continue;
        }

        if(announce_req.transaction_id != announce_res.transaction_id)
        {

            std::cerr << "Invalid transaction id\n";
            std::cerr << s.name<< std::endl;
            std::cerr << announce_req.transaction_id << "!="<<announce_res.transaction_id << std::endl;
            std::cerr << std::endl;
            continue;
        }



        u32 received_peers = (recv - sizeof(struct connection_announce_res)) / sizeof(struct peer_info);

        std::cout << "Received Peers: "<<received_peers<<'\n';
        for(u32 i = 0; i < received_peers; ++i)
        {

            struct peer_info p = *(struct peer_info*)(temp_buf + 20 + sizeof(struct peer_info) * i);
            p.ip = be32toh(p.ip);
            p.port = be16toh(p.port);

            if(peer_in_vector(main_torrent->peers, p) || p.ip == 0 || p.port == 0)
            {
                continue;
            }

            std::cout << p.ip<<" "<<p.port<<std::endl;
            struct peer complete_peer;
            complete_peer.info = p;
            complete_peer.served = 0;
            main_torrent->peers.push_back(complete_peer);

        }


    }
    main_torrent->mutex_arr.resize(main_torrent->peers.size());

}


bool connect_timeout(i32 soc, struct sockaddr* sockaddr, i32 size, i32 timeout_seconds) { 
  
  i32 res; 
  long arg; 
  fd_set myset; 
  struct timeval tv; 
  i32 valopt; 
  socklen_t lon; 


  // Set non-blocking 
  if( (arg = fcntl(soc, F_GETFL, NULL)) < 0) { 
     return false;
  } 
  arg |= O_NONBLOCK; 
  if( fcntl(soc, F_SETFL, arg) < 0) { 
     return false;
  } 
  // Trying to connect with timeout 
  res = connect(soc, sockaddr, size); 
  if (res < 0) { 
     if (errno == EINPROGRESS) { 
        do { 
           tv.tv_sec = timeout_seconds; 
           tv.tv_usec = 0; 
           FD_ZERO(&myset); 
           FD_SET(soc, &myset); 
           res = select(soc+1, NULL, &myset, NULL, &tv); 
           if (res < 0 && errno != EINTR) { 
              return false;
           } 
           else if (res > 0) { 
              // Socket selected for write 
              lon = sizeof(i32); 
              if (getsockopt(soc, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon) < 0) { 
                 return false;
              } 
              // Check the value returned... 
              if (valopt) { 
                 return false;
              } 
              break; 
           } 
           else { 
              return false;
           } 
        } while (1); 
     } 
     else { 
        return false;
     } 
  } 
  // Set to blocking mode again... 
  if( (arg = fcntl(soc, F_GETFL, NULL)) < 0) { 
     return false;
  } 
  arg &= (~O_NONBLOCK); 
  if( fcntl(soc, F_SETFL, arg) < 0) { 
     return false;
  } 

  return true;
}


void connect_to_peer(void* peer, void* torrent)
{
    struct torrent* t = (struct torrent*)torrent;
    struct peer* p = (struct peer*)peer;

    struct sockaddr_in serv_addr;
    i32 sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    {
        std::cerr << "Could not connect to TCP socket to ip: "<<p->info.ip<<" on port: " <<
                    p->info.port << "\n";        
        //stop_torrent(1);
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(p->info.port);
    serv_addr.sin_addr.s_addr = htonl(p->info.ip);
    
    
    if(!connect_timeout(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr), 5))
    {
        std::cerr << "Could not connect to TCP socket to ip: "<<p->info.ip<<" on port: " <<
            p->info.port << "\n";
        close(p->sock);
        p->sock = -1;
        return;
    }

    struct handshake_mex mex;
    memcpy(mex.info_hash, t->info_hash, 20);
    memcpy(mex.peer_id, t->client_id, 20);

    i32 sent = send(sock, &mex, sizeof(mex), 0);
    if(sent != sizeof(struct handshake_mex))
    {
        std::cerr << "Invalid mex sent\n";
        stop_torrent(1);
    }

    struct handshake_mex res;
    
    if(!correct_read(sock, (u8*)&res, sizeof(res), 10))
    {
        std::cerr << "Handshake failed\n";
        close(sock);
        p->sock = -1;
        return;
    }


    for(i32 i = 0; i < 20; ++i)
    {
        if((u8)(t->info_hash[i]) != (u8)(res.info_hash[i]))
        {
            std::cerr << "Invalid InfoHash from " << p->info.ip <<
                "(" << p->info.port<<")\n";
            close(sock);
            p->sock = -1;
            return;    
        }

    }

    t->general_lock.lock();
    FD_SET(sock, &t->main_set);
    t->general_lock.unlock();

    u32 n_of_bytes = t->n_of_pieces / 8 + 1;

    p->bitfield = (u8*)malloc(n_of_bytes);
    memset(p->bitfield, 0, n_of_bytes);
    p->bitfield_size = n_of_bytes;
    p->sock = sock;
    std::cout << "Peer connected with socket: "<< p->sock << '\n';
    p->timestamp.tv_nsec = 0;
    p->timestamp.tv_sec = 0;
}



void setup_peer_connections(struct torrent* main_torrent)
{
	main_torrent->general_lock.lock();
	FD_ZERO(&main_torrent->main_set);
	main_torrent->general_lock.unlock();


    for(struct peer& p: main_torrent->peers)
    {
        //will be deallocated inside connect_to_peer
        thpool_add_work(main_torrent->thpool, connect_to_peer, (void*)&p, (void*)main_torrent);
    }

}

volatile u8 run = 0x1;

void stop_torrent(i32 code)
{
    run = 0x0;
    std::cout << "Terminating torrent with code: " << code << '\n';
}


void decode_file(struct torrent* main_torrent)
{
    i32 off_t = lseek(main_torrent->file_descriptor, 0, SEEK_SET);

    std::vector<struct dict_node*> v; 

    get_dict_node("info", main_torrent->metainfo, v);
    if(v.empty())
    {
        std::cerr << "Could not locate info dictionary\n";
        return;
    }

    std::vector<struct dict_node*> temp_vec;

    get_dict_node("name", v[0]->val, temp_vec);

	std::string name = std::string(temp_vec[0]->val->value.val_str);
	temp_vec.clear();
    get_dict_node("files", v[0]->val, temp_vec);
	if(!temp_vec.size())
	{
		//handle single file torrent
	    std::string file_rename_cmd = std::string("mv ./tmp ") + "\"" + name + "\"";
	    i32 res = system(file_rename_cmd.c_str());
		if (res != 0)
		{
			std::cerr << "Could not rename tmp file\n";
			return;
		}

	}
	else
	{
	    std::string main_folder_cmd = std::string("mkdir -p \"") + name  + '"';

	    i32 res = system(main_folder_cmd.c_str());
	    if (res != 0)
	    {
	        std::cerr << "Could not create main folder\n";
	        return;
	    }

		struct node* file_list = temp_vec[0]->val;
		for (u32 i = 0; i < file_list->size; ++i)
		{
			struct node* element = file_list->value.val_arr[i];
			temp_vec.clear();
			get_dict_node("length", element, temp_vec);
			if(temp_vec.size() != 1)
			{
				std::cerr << "Did not find file length\n";
				return;
			}
			u32 file_length = temp_vec[0]->val->value.val_int;
			temp_vec.clear();

			get_dict_node("path", element, temp_vec);
			if(temp_vec.size() != 1)
			{
				std::cerr << "Did not find file path list\n";
				return;
			}

			std::string full_path = "\""+name+"\"/";
			u32 list_size = temp_vec[0]->val->size;
			for(u32 j = 0; j < list_size - 1; ++j)
			{
				struct node* path = temp_vec[0]->val->value.val_arr[j];
				std::string subfolder = std::string(path->value.val_str);
				full_path += "\""+subfolder + "\"/";
			}
		    std::string subfolder_cmd = std::string("mkdir -p ") + full_path;
		    i32 res = system(subfolder_cmd.c_str());
		    if (res != 0)
			{
				std::cerr << "Could not create sub folder\n";
				return;
			}

		    std::string file_name_with_path = full_path + "\"" + temp_vec[0]->val->value.val_arr[list_size - 1]->value.val_str+ "\"";

		    std::string test = "";

		    for (char c: file_name_with_path)
		    {
		    	if (c != '"')
		    		test += c;
		    }


		    i32 f_create = creat(test.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
		    if (f_create < 0)
		    {
		    	std::cout << "errno" << errno <<'\n';
		    	perror("Could not create file\n");
				return;
			}


		    i32 cpy = 0;
		    while(cpy < file_length)
		    {
		    	i32 t_cpy = sendfile(f_create, main_torrent->file_descriptor, NULL, file_length - cpy);
		    	if (t_cpy < 0)
				{
					std::cout << "errno" << errno <<'\n';
					perror("Could not copy tmp to final file\n");
					return;
				}
		    	cpy += t_cpy;
		    }


		}


	}


}


void start_torrent(struct torrent* main_torrent)
{

    get_peer_list(main_torrent);
    setup_peer_connections(main_torrent);

    srand(time(NULL));

    //keepalive thread
    //Think about implementing a timeout
    std::thread keep_alive_thread([&]()
    {
        struct general_message keep_alive;
        keep_alive.length_prefix = 0;
        while(run)
        {
            for(auto& p : main_torrent->peers)
            {
                if(p.sock > 0)
                {
                    i32 sent = send(p.sock, &keep_alive, 4, 0);
                    if(sent < 4)
                    {
                        perror("Invalid keep alive");
                        close(p.sock);
                        p.sock = -1;
                    }

                }

            }
            sleep(110);
        }
        std::cout << "KeepAlive terminating...\n";
    });


#define PIECE_REQUEST_MEX_SIZE 17
#define BLOCK_SIZE (1 << 14)

u32 REQUEST_TIMEOUT = (sqrt(main_torrent->piece_size) / 50)*1000;
std::cerr << "TIMEOUT: " << REQUEST_TIMEOUT<<" ms\n";

u8* pieces = (u8*)malloc(sizeof(u8) * main_torrent->n_of_pieces);
u32 n_of_blocks = (u32)ceil((float)main_torrent->piece_size / (1 << 14));

	std::thread request_manager_thread([&]()
    {

        sleep(3);

        while(run)
        {
            //Checking if the torrent has been completed
            bool torrent_complete = true;
            for(u32 i = 0; i < main_torrent->n_of_pieces; ++i)
            {
                if(!bitfield_is_set(main_torrent->bitfield, i))
                {
                    torrent_complete = false;
                    break;
                }
            }
            if(torrent_complete)break;
            
            //Filling the buffers and requesting pieces
            for(u32 i = 0; i < TORRENT_BUFFER_SIZE; ++i)
            {
                u32 min = 50;
                i32 min_id = main_torrent->buffered_pieces[i].id;
                if (min_id == -1)
                {
                	main_torrent->buffered_pieces[i].last_request = {0};
                	//If mid_id == -1 --> The slot in the buffer is empty and can be filled with a new piece.
                    memset(pieces, 0, sizeof(u8) * main_torrent->n_of_pieces);
                    for (u32 j = 0; j < main_torrent->n_of_pieces; ++j)
                    {
                    	for(auto& p: main_torrent->peers)
						{
							if(p.sock > 0)
							{
                                    //We compute the frequency of the pieces among the connected peers to pick the rarest first.
									pieces[j] += bitfield_is_set(p.bitfield, j);
							}
						}

                    }

                    for(i32 j = 0; j < (i32)main_torrent->n_of_pieces; ++j)
                    {
                        if (bitfield_is_set(main_torrent->bitfield, j))
                            continue;
                        if (pieces[j] < min && pieces[j] != 0)
                        {
                            for (i32 k = 0; k < TORRENT_BUFFER_SIZE; ++k)
                            {
                                //If the piece is already in the buffer or already owned we skip it
                                if (j == main_torrent->buffered_pieces[k].id) 
                                    goto next_cycle;
                            }
                            
                            min = pieces[j];
                            min_id = j;
                            next_cycle:;
                        }
                    }
                    if (min_id == -1)continue;

                }


                struct timespec curr_time;
                clock_gettime(CLOCK_REALTIME, &curr_time);

                u32 elapsed_time = get_elapsed_milliseconds(&curr_time, &main_torrent->buffered_pieces[i].last_request);
                if(elapsed_time < REQUEST_TIMEOUT / 5)
                {
                	continue;
                }
                //std::cout << "ELAPSED_TIME: "<< elapsed_time << "(" << i << ")\n";
                //if we get here it means we have found a piece to request and we set it into a buffer.
                u8 buf[PIECE_REQUEST_MEX_SIZE];
                u32 rand_peer = rand() % pieces[min_id] + 1;

                if (rand_peer > 20)
                	std::cout << "Incorrect random peer generation\n";

                for(auto & p: main_torrent->peers)
                {
                    if(p.sock > 0 && bitfield_is_set(p.bitfield, min_id))
                    {
                        if(p.am_interested == false)
                        {
                            //sends "interested" message
                            struct general_message mex;
                            mex.id = 2;
                            mex.length_prefix = htobe32(1);
                            i32 sent = send(p.sock, &mex, sizeof(mex), MSG_DONTWAIT | MSG_NOSIGNAL);
                            if(sent < 0)
                            {
                                if(errno == EPIPE)
                                {
                                    std::cerr << "Broken Pipe...\n";
                                    close(p.sock);
                                    free(p.bitfield); 
                                    p.sock = -1; 
                                    continue;
                                }
                                else
                                {
                                	perror("Error requesting piece: ");
                                	std::cerr << "Error code: " << errno << '\n';
                                }

                            }
                            if(sent != sizeof(mex))
                                std::cerr << "Invalid Interest sent\n";
                            p.am_interested = true;
                        }


                        u32 n_of_blocks_cpy = n_of_blocks;
                        u32 block_size = BLOCK_SIZE;
                        bool last_piece = false;
                        u32 last_block_size = 0;

                        struct timespec begin;
                        clock_gettime(CLOCK_REALTIME, &begin);


                        if(p.is_choking == false && !(--rand_peer) && get_elapsed_milliseconds(&begin, &p.timestamp) > 500)
                        {

                            bool quitting = false;
                            for(u32 z = 0; z < TORRENT_BUFFER_SIZE; ++z)
                            {
                                if(main_torrent->buffered_pieces[z].peer == p.sock)
                                {
                                    quitting = true;
                                    break;
                                }
                                    
                            }

                            //if(quitting)
                            //	continue;
                           
                        	std::cout << "REQUEST: " << min_id << "to "<<p.sock<<'\n';
                            if(bitfield_is_set(main_torrent->bitfield, min_id))
                            {
                                std::cout << "\n\nPiece already requested\n\n";
                                break;
                            }

                            //handles last piece which might be shorter
                            if(min_id == main_torrent->n_of_pieces - 1 && main_torrent->total_size % main_torrent->piece_size != 0)
                            {
                                std::cout << "Last piece being requested\n";
                                u32 last_piece_size = main_torrent->total_size - (main_torrent->n_of_pieces - 1) * main_torrent->piece_size;
                                n_of_blocks  = (u32)ceil((float)last_piece_size / block_size);
                                std::cout << "Blocks: " << n_of_blocks<<'\n';
                                last_piece = true;
                                last_block_size = last_piece_size - (n_of_blocks - 1) * block_size;
                            }


                            main_torrent->buffered_pieces[i].lock.lock();
                            main_torrent->buffered_pieces[i].peer = p.sock;
                            main_torrent->buffered_pieces[i].counter = 0;
                            main_torrent->buffered_pieces[i].last_request = begin;
                            main_torrent->buffered_pieces[i].id = min_id;
                            main_torrent->buffered_pieces[i].lock.unlock();

                            for(u32 j = 0; j < n_of_blocks; ++j)
                            {
                        

                                struct general_message mex;
                                mex.id = 6;
                                mex.length_prefix = htobe32(13);
                                memcpy(buf, &mex, sizeof(struct general_message));
                                //index
                                *(u32*)(buf + 5) = htobe32(min_id);
                                //offset
                                *(u32*)(buf + 9) = htobe32(j * block_size);
                                //length 
                                if(last_piece && j == n_of_blocks - 1)
                                	if(last_block_size != 0)
                                		*(u32*)(buf + 13) = htobe32(last_block_size);
                                	else
                                		stop_torrent(-1);
                                else
                            		*(u32*)(buf + 13) = htobe32(block_size);


                                i32 sent = send(p.sock, buf, sizeof(buf), MSG_DONTWAIT | MSG_NOSIGNAL);
                                if(sent != sizeof(buf))
                                    std::cerr << "Invalid piece request sent with code " << sent<<"\n";
                                if(sent < 0)
                                {
                                    if(errno == EPIPE)
                                    {
                                        close(p.sock);
                                        free(p.bitfield); 
                                        p.sock = -1; 
                                        break;
                                    }
                                    else
                                    {
                                    	perror("Error requesting piece: ");
                                    	std::cerr << "Error code: " << errno << '\n';
                                    	close(p.sock);
										free(p.bitfield);
										p.sock = -1;
										break;
                                    }
                                }
                            }

                            p.timestamp = begin;
                        }
                        n_of_blocks = n_of_blocks_cpy;
                        
                    }

                }
                
            }

        }

        std::cout << "\n\n\nTORRENT IS COMPLETE\n\n\n\n\n";
        stop_torrent(69);

        decode_file(main_torrent);
        exit(1);

    }); 


   
    fd_set actual_set;

    threadpool thpool = thpool_init(20);
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    
    u32 c = 0;


    while(run)
    {
    	FD_ZERO(&actual_set);
    	u32 counter = 0;
    	u32 max = 0;
    	for(auto& p: main_torrent->peers)
    	{
    		if(p.sock > 0)
    		{
    			if(p.sock > max)
    				max = p.sock;
    			FD_SET(p.sock, &actual_set);
    			counter += 1;
    		}
    	}

    	if(++c % 100000 == 0)
    		std::cout << "Connected PEERS: " << counter << '\n';



        i32 sel = select(max + 1, &actual_set, NULL, NULL, &timeout);
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;

        if(sel <= 0)
        {
            if (sel < 0)
            {
            	perror("SELECT error: ");

            }
            continue;

        }


        for(u32 i = 0; i < main_torrent->peers.size(); ++i)
        {
            struct peer& p = main_torrent->peers[i];
            main_torrent->mutex_arr[i].lock();
            bool being_served = p.served;
            if(p.sock > 0 && !being_served && FD_ISSET(p.sock, &actual_set))
            {
                p.served = 1;
                thpool_add_work(thpool, handle_mex, &p, main_torrent);
            }     
            main_torrent->mutex_arr[i].unlock();
        }



    }
    std::cout << "MexHandler terminating...\n";
    thpool_wait(thpool);
    thpool_destroy(thpool);
    keep_alive_thread.join();
    request_manager_thread.join();

}

#include "sha.h"

bool check_and_commit(u32 buffered_id, struct torrent* main_torrent)
{
    //hash check
    char* actual_hash = main_torrent->hashes.hash +  20 * 
        main_torrent->buffered_pieces[buffered_id].id;
    u32 piece_size;
    if(main_torrent->buffered_pieces[buffered_id].id == main_torrent->n_of_pieces - 1)
    	piece_size = (main_torrent->total_size - (main_torrent->n_of_pieces - 1) * main_torrent->piece_size);
    else
    	piece_size = main_torrent->piece_size;

    struct internal_state hash = sha1(main_torrent->buffered_pieces[buffered_id].buffer, 
        piece_size);

    u32 hash_buf[5];
    hash_buf[0] = htobe32(hash.A);
    hash_buf[1] = htobe32(hash.B);
    hash_buf[2] = htobe32(hash.C);
    hash_buf[3] = htobe32(hash.D);
    hash_buf[4] = htobe32(hash.E);

    for(i32 i = 0; i < 20; ++i)
    {
        if(((u8*)hash_buf)[i] != ((u8*)actual_hash)[i])
        {
            std::cerr << "Invalid piece hash\n";
            return false;    
        }
    }

    //write to disk
    //EVERYBODY IS WRITING AT THE SAME TIME--> CAREFUL
    i32 off_t = lseek(main_torrent->file_descriptor, 
        main_torrent->piece_size * main_torrent->buffered_pieces[buffered_id].id, SEEK_SET);

    i32 written = 0;
    main_torrent->buffered_pieces[buffered_id].lock.lock();
    while(written < piece_size)
    {
        i32 wr = write(main_torrent->file_descriptor, main_torrent->buffered_pieces[buffered_id].buffer + written,
            piece_size - written);
        if (wr > 0)
        {
            written += wr;
        }
        else
        {
            perror("Invalid write to disk: ");
        }
    }
    main_torrent->buffered_pieces[buffered_id].lock.unlock();

    bitfield_set(main_torrent->bitfield, main_torrent->buffered_pieces[buffered_id].id);

    return true;
}



/*
    Possible issue with simultaneous modification of peers objects inside the torrent peers vector
        --> maybe not thread safe
        --> maybe caching problem for vectors
*/
void handle_mex(void* p, void* t)
{
    
    u32 id = 0;
    
    struct peer* p_ptr = (struct peer*)p;
    struct torrent* t_ptr = (struct torrent*)t;
    for(u32 i = 0; i < t_ptr->peers.size(); ++i)
    {
        if(t_ptr->peers[i].sock == p_ptr->sock)
        {       
            id = i;
            break;
        }
    }

    struct general_message temp_mex;
    
    if(!correct_read(p_ptr->sock, (u8*)&temp_mex, sizeof(temp_mex), 5))
    {
    	std::cerr << "Error in handling correct read\n";
    	return;
    }


    temp_mex.length_prefix = htobe32(temp_mex.length_prefix);
    
    i32 read = 0;
    
    if(temp_mex.length_prefix == 0)
        return;
    
    switch (temp_mex.id)
    {
    case 0: //choke
        t_ptr->mutex_arr[id].lock();
        p_ptr->is_choking = true;
        p_ptr->am_interested = false;
        p_ptr->served = 0;
        t_ptr->mutex_arr[id].unlock();
        return;
    case 1: //unchoke
        t_ptr->mutex_arr[id].lock();
        p_ptr->is_choking = false;
        p_ptr->served = 0;
        t_ptr->mutex_arr[id].unlock();        
        return;
    case 2: //interested
        t_ptr->mutex_arr[id].lock();
        p_ptr->is_interested = true;
        p_ptr->served = 0;
        t_ptr->mutex_arr[id].unlock();
        return;
    case 3: //not interested
        t_ptr->mutex_arr[id].lock();
        p_ptr->is_interested = false;
        p_ptr->served = 0;
        t_ptr->mutex_arr[id].unlock();
        return;
    case 4: //have
    {
        u32 index;
        bool res = correct_read(p_ptr->sock, (u8*)&index, sizeof(index));
        if(!res)
        {
            std::cerr << "Invalid Have Received\n";
            return;
        }
        index = be32toh(index);
        t_ptr->mutex_arr[id].lock();
        bitfield_set(p_ptr->bitfield, index);
        p_ptr->served = 0;
        t_ptr->mutex_arr[id].unlock();
        return;
    }
    case 5: //bitfield
    {
        u32 bitfield_length = temp_mex.length_prefix - 1;
        if(bitfield_length != p_ptr->bitfield_size)
        {
            std::cerr << "Bitfield length not compatible\n";
            close(p_ptr->sock);
            p_ptr->sock = -1;
            return;
        }
        t_ptr->mutex_arr[id].lock();
        bool res = correct_read(p_ptr->sock, p_ptr->bitfield, p_ptr->bitfield_size);
        if(!res)
        {
            p_ptr->sock = -1;
            free(p_ptr->bitfield);
        }
        p_ptr->served = 0;
        t_ptr->mutex_arr[id].unlock();
        return;
    }
    case 6: //request
        t_ptr->mutex_arr[id].lock();
        p_ptr->served = 0;
        t_ptr->mutex_arr[id].unlock();
        return;
    case 7: //piece
    {
        
        u32 msg_length = temp_mex.length_prefix - 9;
        u32 index;
        u32 begin;
        read = recv(p_ptr->sock, &index, sizeof(index), 0);
        if(read < 0)
        {
        	std::cerr << "Incorrect INDEX read\n";
        }
        read = recv(p_ptr->sock, &begin, sizeof(begin), 0);
        if(read < 0)
		{
			std::cerr << "Incorrect BEGIN read\n";
		}
        index = htobe32(index);
        begin = htobe32(begin);
        //std::cout << "PIECE: msg_length: " << msg_length<< ", index: " << index << ", begin: " << begin<<'\n';
        i32 piece_id = -1;
        for(u32 i = 0; i < TORRENT_BUFFER_SIZE; ++i)
        {
            if((u32)t_ptr->buffered_pieces[i].id == index)
            {
                piece_id = i;
                break;
            }
        }
        if(piece_id < 0)
        {
            std::cerr << "Piece not found in buffer... skipping\n";
            read = 0;
            u32 junk[2048];
            while (read < msg_length)
			{
				i32 read_res = recv(p_ptr->sock, junk, min(sizeof(junk), msg_length - read), 0);
				if(read_res < 0)
				{
					perror("Junk Error: ");
                    close(p_ptr->sock);
                    p_ptr->sock = -1;
                    return;
				}
				else
					read += read_res;
			}
            return;
        }
        read = 0;
        //is the lock useful?
        t_ptr->buffered_pieces[piece_id].lock.lock();
        bool res = correct_read(p_ptr->sock, t_ptr->buffered_pieces[piece_id].buffer + begin, msg_length, 5);
        if(!res)
		{
			perror("Piece Error: ");
			std::cerr << "Piece_ID: "<<piece_id << " begin: " << begin << " read: " << read << '\n';
			//close(p_ptr->sock);
			//p_ptr->sock = -1;
			return;
		}

        t_ptr->buffered_pieces[piece_id].lock.unlock();
        u32 n_of_blocks;
        if(index != t_ptr->n_of_pieces - 1)
        	n_of_blocks = (u32)ceil((float)t_ptr->piece_size / (1 << 14));
        else
        {
        	u32 last_piece_size = (t_ptr->total_size - (t_ptr->n_of_pieces - 1) * t_ptr->piece_size);
        	n_of_blocks = (u32)ceil((float)last_piece_size / (1 << 14));
        }

        t_ptr->buffered_pieces[piece_id].counter++;
        if(t_ptr->buffered_pieces[piece_id].counter == n_of_blocks)
        {
            std::cout << "PIECE_COMPLETED\n";
            //piece is complete
            //POSSIBLE ERROR: insert LOCKS
            t_ptr->buffered_pieces[piece_id].counter = 0;
            if(check_and_commit(piece_id, t_ptr))
            {
                std::cout << "PIECE_COMMITED\n";
                t_ptr->buffered_pieces[piece_id].id = -1;
                t_ptr->buffered_pieces[piece_id].peer = -1;
            }
        }
        t_ptr->mutex_arr[id].lock();
        p_ptr->served = 0;
        t_ptr->mutex_arr[id].unlock();
        return;
    }
    case 8: //cancel
        t_ptr->mutex_arr[id].lock();
        p_ptr->served = 0;
        t_ptr->mutex_arr[id].unlock();
        return;
    default:
        std::cerr << "Mex not recognized by ip: "<<p_ptr->info.ip <<"(" << p_ptr->info.port<<")\n";
        std::cerr << "Temp_Mex ID: "<< temp_mex.id << ", LENGTH: " << temp_mex.length_prefix<< '\n';
        std::cerr << '\n';
        t_ptr->mutex_arr[id].lock();
        p_ptr->served = 0;
        t_ptr->mutex_arr[id].unlock();
        return;
    }



}
