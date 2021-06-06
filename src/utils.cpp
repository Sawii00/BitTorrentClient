#include "utils.h"
#include <sstream>



bool tracker_in_vector(std::vector <struct tracker>& v, std::string name)
{
    for(auto& p: v)
    {
        if(p.name == name)
            return true;
    }
    return false;
}

bool peer_in_vector(std::vector <struct peer>& v, struct peer_info& val)
{
    for(auto& p: v)
    {
        if(p.info.ip == val.ip)
            return true;
    }
    return false;
}

std::string url_encode(std::string& raw) 
{
	std::string res = "";
	for (int i = 0; i < raw.length(); i+=2)
	{
		u32 val;
		std::string sub = raw.substr(i, 2);
		std::stringstream ss;
		ss << std::hex << sub;
		ss >> val;
		if ((val >= 48 && val <= 57) || (val >= 65 && val <= 90) || (val >= 97 && val <= 122) || val == 45 || val == 46 || val == 126)
		{
			res.push_back(val);
		}
		else
		{
			res.push_back('%');
			res.push_back(raw[i]);
			res.push_back(raw[i+1]);
		}
	}
	return res;
}

i32 find(char* str, i32 size, i32 starting_pos, std::string del)
{
    if(starting_pos + del.size() >= size)
        return -1;

	bool found = false;
	for (i32 i = starting_pos; i < size - del.size(); ++i)
	{
		for (i32 j = 0; j < del.size(); ++j)
		{
			found = true;
			if (str[i + j] != del[j])
			{
				found = false;
				break;
			}
		}

		if (found)
			return i;
	}

	return -1;

}

i32 find(char* str, i32 size, std::string del)
{
	bool found = false;
	for (i32 i = 0; i < size - del.size(); ++i)
	{
		for (i32 j = 0; j < del.size(); ++j)
		{
			found = true;
			if (str[i + j] != del[j])
			{
				found = false;
				break;
			}
		}

		if (found)
			return i;
	}

	return -1;

}

bool correct_read(u32 sock, u8* buf, i32 size, u32 timeout_s)
{
	i32 read = 0;
	u32 start = time(NULL);
	while(read < size)
	{
		i32 temp = recv(sock, buf + read, size - read, MSG_DONTWAIT);
		if(temp == -1 && (errno != EAGAIN))
		{
			perror("Invalid read: ");
			return false;
		}
		if(temp > 0)
			read += temp;
		if(time(NULL) - start > timeout_s)return false;
	}
	return true;
}
