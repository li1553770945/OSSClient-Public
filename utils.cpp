#include "utils.h"

atomic_ullong g_msg_id(0);

unsigned int IpToInt(const char *str_ip)
{
    in_addr addr;
    unsigned int int_ip;
    if (inet_aton(str_ip, &addr))
    {
        int_ip = ntohl(addr.s_addr);
    }
    return int_ip;
}

string IpToDot(unsigned int n_ip)
{
    in_addr addr;
    addr.s_addr = htonl(n_ip);
    string strip = inet_ntoa(addr);
    if (!strip.empty())
    {
        return strip;
    }
    return NULL;
}
string GenerateRandomString(int length)
{
    string result;
    for (int i = 1; i <= length; i++)
    {
        int x = random() % 62;
        if (x < 10)
        {
            result += x + '0';
        }
        else if (x < 36)
        {
            result += x - 10 + 'a';
        }
        else
        {
            result += x - 36 + 'A';
        }
    }
    return result;
}

int RecvWithRetry(Msg &msg, sockaddr *server_addr, Msg &result, Types expect_types, int max_retry_time, int time_out_milli)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        cout << "RecvWithRetry: init socket error!" << errno << endl;
        return -1;
    }
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        cout << "set timeout fail! errno:" << errno << endl;
    }
    for (int i = 1; i <= max_retry_time; i++)
    {
        int ret = sendto(fd, &msg, sizeof(msg), 0, (sockaddr *)server_addr, sizeof(sockaddr_in));
        if (ret > 0)
        {
            int count = recvfrom(fd, &result, sizeof(result), 0, 0, 0);
            if (count > 0 && result.id == msg.id && result.type == expect_types)
            {
                return 0;
            }
            else if (count < 0)
            {
                if (errno == EAGAIN)
                {
                    continue;
                }
                else
                {
                    cout << "recv fail!" << errno << endl;
                }
            }
        }
        else
        {
            cout << "sendto fail! errno:" << errno << endl;
        }
    }
    cout << "recv with retry error" << endl;
    close(fd);
    return -1;
}