#include <iostream>
#include "SDK.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <filesystem>
#include <sys/sendfile.h>
#include "easylogging++.h"
using namespace std;

INITIALIZE_EASYLOGGINGPP

atomic_ullong g_add_server_time, g_add_num, g_add_total_time;
atomic_ullong g_get_server_time, g_get_num, g_get_total_time;

const int MAX_RETRY_TIMES = 3;
const int TCP_PACKAGE_SIZE = 1024;

OSSSDK::OSSSDK(string ip, int port, string ak, string sk)
{

    m_registry_addr.sin_family = AF_INET;
    m_registry_addr.sin_port = htons(port);
    m_registry_addr.sin_addr.s_addr = htonl(IpToInt(ip.data()));
    m_ak = ak;
    m_sk = sk;
}
int OSSSDK::Init()
{

    bool conn_success = false;
    for (int i = 1; i <= MAX_RETRY_TIMES; i++)
    {
        LOG(INFO) << "geting server..." << endl;
        IpPort server_ip(159851401, 13001);
        if (server_ip.port == 0)
        {
            return -1;
        }
        LOG(INFO) << "server:" << IpToDot(server_ip.ip) << ":" << server_ip.port << endl;
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_ip.port);
        server_addr.sin_addr.s_addr = htonl(server_ip.ip);

        LOG(INFO) << "connecting to server..." << endl;

        m_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_fd < 0)
        {
            LOG(ERROR) << "invalid socket !";
            continue;
        }
        if (connect(m_fd, (sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            LOG(ERROR) << "connect error !" << endl;
            continue;
        }
        conn_success = true;
        break;
    }

    if (!conn_success)
    {
        LOG(ERROR) << "connect to server error !" << endl;
        m_err_msg = "connect to server fail!";
        return -1;
    }
    conn_success = false;
    int port = 14001;
    for (int i = 1; i <= MAX_RETRY_TIMES; i++)
    {
        IpPort file_server_ip;
        file_server_ip = IpPort(159851401, port);
        port++;
        if (file_server_ip.port == 0)
        {
            return -1;
        }
        LOG(INFO) << "file server:" << IpToDot(file_server_ip.ip) << ":" << file_server_ip.port << endl;
        struct sockaddr_in file_server_addr;
        file_server_addr.sin_family = AF_INET;
        file_server_addr.sin_port = htons(file_server_ip.port);
        file_server_addr.sin_addr.s_addr = htonl(file_server_ip.ip);
        LOG(INFO) << "connecting to file server..." << endl;
        m_file_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_file_fd < 0)
        {
            LOG(ERROR) << "invalid socket !";
            continue;
        }
        if (connect(m_file_fd, (sockaddr *)&file_server_addr, sizeof(file_server_addr)) < 0)
        {
            // LOG(ERROR)<<"connect file server error !"<<errno<<endl;
            continue;
        }
        conn_success = true;
        LOG(INFO) << "connect to file server success!" << endl;
        break;
    }
    if (!conn_success)
    {
        LOG(ERROR) << "connect to file server error !" << endl;
        m_err_msg = "connect to file server fail!";
        return -1;
    }
    if (Login(m_fd) != 0)
    {
        m_err_msg = "login to server fail!";
        return -1;
    }
    if (Login(m_file_fd) != 0)
    {
        m_err_msg = "login to file server fail!";
        return -1;
    }
    return 0;
}
int OSSSDK::Login(int fd)
{
    Msg msg;
    msg.type = Types::LoginRequest;
    LoginReq *req = (LoginReq *)msg.data;
    strcpy(req->ak, m_ak.data());
    strcpy(req->sk, m_sk.data());
    msg.id = g_msg_id++;

    send(fd, &msg, sizeof(msg), 0);

    Msg result;
    if (recv(fd, &result, sizeof(Msg), 0) <= 0)
    {
        LOG(ERROR) << "Login to server error,recv error" << errno << endl;
        return -1;
    }
    else
    {
        LoginRes *res = (LoginRes *)result.data;
        if (res->err == Errors::Success)
        {
            LOG(INFO) << "login to server success!" << endl;
            return 0;
        }
        else
        {
            LOG(ERROR) << "login to server failed:" << res->msg << endl;
            return -1;
        }
    }
}
IpPort OSSSDK::GetServer()
{
    Msg msg, result;
    msg.type = Types::GetServerRequest;
    msg.id = g_msg_id++;
    if (RecvWithRetry(msg, (sockaddr *)&m_registry_addr, result, Types::GetServerResponse) == 0)
    {
        IpPort *ip = (IpPort *)result.data;
        return IpPort(ip->ip, ip->port);
    }
    else
    {
        LOG(ERROR) << "get server failed! registry report error" << endl;
        return IpPort(0, 0);
    }
}

IpPort OSSSDK::GetFileServer()
{
    Msg msg, result;
    msg.type = Types::GetFileServerRequest;
    msg.id = g_msg_id++;

    if (RecvWithRetry(msg, (sockaddr *)&m_registry_addr, result, Types::GetFileServerResponse) == 0)
    {
        IpPort *ip = (IpPort *)result.data;
        return IpPort(ip->ip, ip->port);
    }
    else
    {
        LOG(ERROR) << "get file server fail!" << endl;

        return IpPort(0, 0);
    }
}

string OSSSDK::GetToken(string access_key, string secret_key)
{
    return access_key;
}

int OSSSDK::AddFile(string file_path, string &file_id)
{

    //获取文件信息
    int file_fd = open(file_path.c_str(), O_RDONLY);
    if (file_fd < 0)
    {
        LOG(ERROR) << "Open file failed! errno:" << errno << endl;
        return -1;
    }
    filesystem::path file(file_path.data());
    string file_name = file.filename();
    uint64_t file_size = filesystem::file_size(file);

    //添加meta
    Msg msg, result;
    msg.type = Types::AddFileMetaRequest;
    msg.id = g_msg_id++;
    msg.len = file_path.length();
    AddFileMetaReq *req = (AddFileMetaReq *)msg.data;
    strcpy(req->file_name, file_name.data());
    req->file_size = file_size;
    int ret = send(m_fd, &msg, sizeof(msg), 0);
    if (ret < 0)
    {
        LOG(ERROR) << "send to server error!" << endl;
        return -1;
    }
    ret = recv(m_fd, &result, sizeof(Msg), 0);
    if (ret < 0)
    {
        LOG(ERROR) << "recv from server error!" << endl;
        return -1;
    }
    AddFileMetaRes *res = (AddFileMetaRes *)result.data;
    file_id = res->file_id;

    //请求上传文件
    msg.type = Types::AddFileRequest;
    msg.id = g_msg_id++;
    AddFileReq *file_req = (AddFileReq *)msg.data;
    strcpy(file_req->file_id, file_id.data());
    file_req->file_size = file_size;

    ret = send(m_file_fd, &msg, sizeof(msg), 0);
    if (ret < 0)
    {
        LOG(ERROR) << "send req to file server error!" << endl;
        return -1;
    }

    //上传文件

    ret = sendfile64(m_file_fd, file_fd, nullptr, file_size);
    if (ret < 0)
    {
        LOG(ERROR) << "send file to server error!" << endl;
        return -1;
    }
    LOG(INFO) << "send over" << endl;
    return 0;
}

int OSSSDK::GetFile(string file_id)
{
    Msg msg;
    msg.type = Types::GetFileMetaRequest;
    msg.id = g_msg_id++;

    GetFileMetaReq *meta_req = (GetFileMetaReq *)msg.data;
    strcpy(meta_req->file_id, file_id.data());

    Msg result;
    int ret = send(m_fd, &msg, sizeof(Msg), 0);
    if (ret < 0)
    {
        LOG(ERROR) << "get file error,send toserver error:" << errno;
        return -1;
    }

    ret = recv(m_fd, &result, sizeof(Msg), 0);
    if (ret < 0)
    {
        LOG(ERROR) << "get file error,recv from server error:" << errno;
        return -1;
    }

    GetFileMetaRes *meta_res = (GetFileMetaRes *)result.data;
    switch (meta_res->err)
    {
    case Errors::FileNotExist:
    {
        LOG(ERROR) << "File id " << file_id << " not exist!" << endl;
        return -1;
    }
    case Errors::FileStoreNotExist:
    {
        LOG(ERROR) << "Fileid " << file_id << " store not exist,this may be caused by upload delay.you can try it later." << endl;
        return -1;
    }
    default:
        break;
    }

    string file_name = meta_res->file_name;
    uint64_t file_size = meta_res->file_size;
    LOG(INFO) << "Geting file name:" << file_name << " size:" << file_size << endl;

    msg.type = Types::GetFileSroteServerRequest;
    msg.id = g_msg_id++;
    GetFileStoreServerReq *store_server_req = (GetFileStoreServerReq *)msg.data;
    strcpy(store_server_req->file_id, file_id.data());

    memset(&result, 0, sizeof(result));
    ret = send(m_fd, &msg, sizeof(Msg), 0);
    if (ret < 0)
    {
        LOG(ERROR) << "get file error,send to server error:" << errno;
        return -1;
    }
    ret = recv(m_fd, &result, sizeof(Msg), 0);
    if (ret < 0)
    {
        LOG(ERROR) << "get file error,recv from server error:" << errno;
        return -1;
    }

    GetFileStoreServerRes *store_server_res = (GetFileStoreServerRes *)result.data;

    uint64_t recv_size = 0;
    int store_server_size = store_server_res->size;
    for (int i = 0; i < store_server_size; i++)
    {
        LOG(INFO) << "Geting file from " << IpToDot(store_server_res->ip[i].ip) << ":" << store_server_res->ip[i].port << endl;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            LOG(ERROR) << "Get file fail! create tcp socket fail!" << endl;
            return -1;
        }
        struct sockaddr_in ser;
        ser.sin_family = AF_INET;
        ser.sin_port = htons(store_server_res->ip[i].port);
        ser.sin_addr.s_addr = htonl(store_server_res->ip[i].ip);
        socklen_t len = sizeof(sockaddr_in);
        if (connect(fd, (sockaddr *)&ser, len) < 0)
        {
            LOG(ERROR) << "Get file fail! connect to file server fail!" << endl;
            close(fd);
            continue;
        }

        if (Login(fd) != 0)
        {
            LOG(ERROR) << "get file failed,login to file server error" << endl;
            close(fd);
            continue;
        }
        msg.type = Types::GetFileRequest;
        msg.id = g_msg_id++;
        GetFileReq *get_file_req = (GetFileReq *)msg.data;
        strcpy(get_file_req->file_id, file_id.data());
        get_file_req->offset = recv_size;
        if (send(fd, &msg, sizeof(msg), 0) < 0)
        {
            LOG(ERROR) << "Send request to file server failed!" << endl;
            close(fd);
            continue;
        }

        memset(&result, 0, sizeof(result));
        int ret = recv(fd, &result, sizeof(result), 0);
        if (ret < 0)
        {
            LOG(ERROR) << "Recv from file server failed!" << endl;
            close(fd);
            continue;
        }
        else if (ret == 0)
        {
            LOG(ERROR) << "File server closed unexpected!" << endl;
            close(fd);
            continue;
        }
        ResultResponse *err = (ResultResponse *)result.data;
        if (err->err == Errors::Success) //文件服务器回复success
        {
            LOG(INFO) << "File server report ok,begin to recv..." << ret << endl;
            char buffer[TCP_PACKAGE_SIZE];

            FILE *fp = fopen((string("receive/") + file_name.data()).data(), "w+");
            while (recv_size < file_size) //开始接收
            {

                if (recv_size + TCP_PACKAGE_SIZE > file_size)
                {
                    ret = recv(fd, buffer, file_size - recv_size, 0);
                }
                else
                {
                    ret = recv(fd, buffer, TCP_PACKAGE_SIZE, 0);
                }
                if (ret <= 0)
                {
                    LOG(ERROR) << "recv from file server interrupt! ret:" << ret << endl;
                    fclose(fp);
                    close(fd);
                    break;
                }
                else
                {
                    fwrite(buffer, sizeof(char), ret, fp);
                    recv_size += ret;
                }
            }
            fclose(fp);
        }
        else
        {
            LOG(ERROR) << "File server report a failure,code:" << (int)err->err << endl;
            close(fd);
            continue;
        }
        if (recv_size == file_size)
        {
            LOG(INFO) << "Recv file success." << endl;
            break;
        }
    }

    if (recv_size != file_size)
    {
        LOG(ERROR) << "Sorry.We tried all the file server,but they all failed!" << endl;
        return -1;
    }
    return 0;
}
int OSSSDK::DeleteFile(string file_id)
{

    Msg msg;
    msg.type = Types::DeleteFileMetaRequest;
    msg.id = g_msg_id++;

    DeleteFileMetaReq *req = (DeleteFileMetaReq *)msg.data;
    strcpy(req->file_id, file_id.data());
    send(m_fd, &msg, sizeof(Msg), 0);
    return 0;
}

int OSSSDK::AddMutiFile(vector<string> file_paths, vector<pair<string, string>> &file_ids)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t total_start = tv.tv_sec * 1000000 + tv.tv_usec;
    m_upload_num = 0;
    m_need_upload = true;

    thread t(&OSSSDK::Uploader, this, ref(file_ids));
    for (auto &file_path : file_paths)
    {
        int file_fd = open(file_path.c_str(), O_RDONLY);
        if (file_fd < 0)
        {
            LOG(ERROR) << "Open file failed! errno:" << errno << endl;
            return -1;
        }
        filesystem::path file(file_path.data());
        string file_name = file.filename();
        uint64_t file_size = filesystem::file_size(file);

        //添加meta
        Msg msg, result;
        msg.type = Types::AddFileMetaRequest;
        msg.id = g_msg_id++;
        msg.len = file_path.length();
        AddFileMetaReq *req = (AddFileMetaReq *)msg.data;
        strcpy(req->file_name, file_name.data());
        req->file_size = file_size;
        gettimeofday(&tv, NULL);
        uint64_t start = tv.tv_sec * 1000000 + tv.tv_usec;
        int ret = send(m_fd, &msg, sizeof(msg), 0);
        if (ret < 0)
        {
            LOG(ERROR) << "send to server error!" << endl;
            return -1;
        }
        ret = recv(m_fd, &result, sizeof(Msg), 0);
        if (ret < 0)
        {
            LOG(ERROR) << "recv from server error!" << endl;
            return -1;
        }
        gettimeofday(&tv, NULL);
        g_add_server_time += tv.tv_sec * 1000000 + tv.tv_usec - start;
        g_add_num++;
        AddFileMetaRes *res = (AddFileMetaRes *)result.data;
        m_add_q.enqueue(UploadDesc(file_path, res->file_id, file_fd, file_size));
        m_upload_num++;
    }
    m_need_upload = false;
    t.join();

    gettimeofday(&tv, NULL);
    g_add_total_time += tv.tv_sec * 1000000 + tv.tv_usec - total_start;
    return 0;
}
int OSSSDK::GetMutiFile(vector<string> file_ids)
{
    m_need_download = true;
    m_download_num = 0;
    thread t(&OSSSDK::Downloader, this);
    Msg msg;
    timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t total_start = tv.tv_sec * 1000000 + tv.tv_usec;
    for (auto &file_id : file_ids)
    {
        msg.type = Types::GetFileMetaRequest;
        msg.id = g_msg_id++;
        //查询文件信息
        GetFileMetaReq *meta_req = (GetFileMetaReq *)msg.data;
        strcpy(meta_req->file_id, file_id.data());
        g_get_num++;
        Msg result;
        int ret = send(m_fd, &msg, sizeof(Msg), 0);
        if (ret < 0)
        {
            LOG(ERROR) << "get file error,send to server error:" << errno;
            return -1;
        }

        ret = recv(m_fd, &result, sizeof(Msg), 0);
        if (ret < 0)
        {
            LOG(ERROR) << "get file error,recv from server error:" << errno;
            continue;
        }

        GetFileMetaRes *meta_res = (GetFileMetaRes *)result.data;
        switch (meta_res->err)
        {
        case Errors::FileNotExist:
        {
            LOG(ERROR) << "File id " << file_id << " not exist!" << endl;
            continue;
        }
        case Errors::FileStoreNotExist:
        {
            LOG(ERROR) << "File id " << file_id << " store not exist,this may be caused by upload delay.you can try it later." << endl;
            continue;
        }
        default:
            break;
        }
        //查询文件所在服务器
        string file_name = meta_res->file_name;
        uint64_t file_size = meta_res->file_size;
        LOG(INFO) << "Geting file name:" << file_name << " size:" << file_size << endl;

        msg.type = Types::GetFileSroteServerRequest;
        msg.id = g_msg_id++;
        GetFileStoreServerReq *store_server_req = (GetFileStoreServerReq *)msg.data;
        strcpy(store_server_req->file_id, file_id.data());

        memset(&result, 0, sizeof(result));
        ret = send(m_fd, &msg, sizeof(Msg), 0);
        if (ret < 0)
        {
            LOG(ERROR) << "get file error,send to server error:" << errno;
            return -1;
        }
        ret = recv(m_fd, &result, sizeof(Msg), 0);
        if (ret < 0)
        {
            LOG(ERROR) << "get file error,recv from server error:" << errno;
            return -1;
        }

        GetFileStoreServerRes *store_server_res = (GetFileStoreServerRes *)result.data;

        uint64_t recv_size = 0;
        int store_server_size = store_server_res->size;
        IpPort ip = store_server_res->ip[0];
        m_get_q.enqueue(DownloadDesc(file_name, file_id, ip, file_size));
        m_download_num++;
    }
    m_need_download = false;
    t.join();
    gettimeofday(&tv, NULL);
    g_get_total_time += tv.tv_sec * 1000000 + tv.tv_usec - total_start;
    return 0;
}

void OSSSDK::Uploader(vector<pair<string, string>> &file_ids)
{
    Msg msg;
    msg.type = Types::AddFileRequest;
    int ret;
    UploadDesc desc;
    struct timeval tv;
    while (m_need_upload || m_upload_num)
    {
        if (m_add_q.try_dequeue(desc))
        {
            m_upload_num--;
            msg.id = g_msg_id++;
            AddFileReq *file_req = (AddFileReq *)msg.data;
            strcpy(file_req->file_id, desc.file_id.data());
            file_req->file_size = desc.file_size;
            ret = send(m_file_fd, &msg, sizeof(msg), 0);
            if (ret < 0)
            {
                LOG(ERROR) << "send req to file server error!" << errno << endl;
                continue;
            }

            //上传文件

            ret = sendfile64(m_file_fd, desc.file_fd, nullptr, desc.file_size);
            if (ret < 0)
            {
                LOG(ERROR) << "send file to server error!" << errno << endl;
            }
            file_ids.emplace_back(make_pair(desc.file_name, desc.file_id));
        }
    }
    LOG(INFO) << "send over" << endl;
}
void OSSSDK::Downloader()
{
    Msg msg, result;
    msg.type = Types::GetFileRequest;
    int ret;
    DownloadDesc desc;
    unordered_map<IpPort, int> fds;
    while (m_need_download || m_download_num)
    {

        if (m_get_q.try_dequeue(desc))
        {

            m_download_num--;
            if (fds[desc.server] == 0)
            {
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0)
                {
                    LOG(ERROR) << "Get file fail! create tcp socket fail!" << endl;
                    continue;
                }
                struct sockaddr_in ser;
                ser.sin_family = AF_INET;
                ser.sin_port = htons(desc.server.port);
                ser.sin_addr.s_addr = htonl(desc.server.ip);
                socklen_t len = sizeof(sockaddr_in);
                if (connect(fd, (sockaddr *)&ser, len) < 0)
                {
                    LOG(ERROR) << "Get file fail! connect to file server fail!" << endl;
                    close(fd);
                    continue;
                }

                if (Login(fd) != 0)
                {
                    LOG(ERROR) << "get file failed,login to file server error" << endl;
                    close(fd);
                    continue;
                }
                fds[desc.server] = fd;
            }

            msg.id = g_msg_id++;
            int recv_size = 0;
            GetFileReq *get_file_req = (GetFileReq *)msg.data;
            strcpy(get_file_req->file_id, desc.file_id.data());
            get_file_req->offset = recv_size;
            if (send(fds[desc.server], &msg, sizeof(msg), 0) < 0)
            {
                LOG(ERROR) << "Send request to file server failed!" << endl;
                close(fds[desc.server]);
                fds[desc.server] = 0;
                continue;
            }

            memset(&result, 0, sizeof(result));
            int ret = recv(fds[desc.server], &result, sizeof(result), 0);
            if (ret < 0)
            {
                LOG(ERROR) << "Recv from file server failed!" << endl;
                close(fds[desc.server]);
                fds[desc.server] = 0;
                continue;
            }
            else if (ret == 0)
            {
                LOG(ERROR) << "File server closed unexpected!" << endl;
                close(fds[desc.server]);
                fds[desc.server] = 0;
                continue;
            }
            ResultResponse *err = (ResultResponse *)result.data;
            if (err->err == Errors::Success) //文件服务器回复success
            {
                LOG(INFO) << "File server report ok,begin to recv..." << ret << endl;
                char buffer[TCP_PACKAGE_SIZE];
                int file_fd = open((string("receive/") + desc.file_name).c_str(), O_WRONLY | O_CREAT);
                while (recv_size < desc.file_size) //开始接收
                {

                    if (recv_size + TCP_PACKAGE_SIZE > desc.file_size)
                    {
                        ret = recv(fds[desc.server], buffer, desc.file_size - recv_size, 0);
                    }
                    else
                    {
                        ret = recv(fds[desc.server], buffer, TCP_PACKAGE_SIZE, 0);
                    }
                    if (ret <= 0)
                    {
                        LOG(ERROR) << "recv from file server interrupt! ret:" << ret << endl;
                        close(file_fd);
                        close(fds[desc.server]);
                        fds[desc.server] = 0;
                        break;
                    }
                    else
                    {
                        // cout<<"write"<<endl;
                        write(file_fd, buffer, ret);
                        recv_size += ret;
                    }
                }
                close(file_fd);
            }
            else
            {
                LOG(ERROR) << "File server report a failure,code:" << (int)err->err << endl;
                continue;
            }
        } // if deque
    }     // main while

    for (auto &[ip, fd] : fds)
    {
        close(fd);
    }
}
string OSSSDK::GetErrMsg()
{
    return m_err_msg;
}
OSSSDK::~OSSSDK()
{
    close(m_fd);
    close(m_file_fd);
}