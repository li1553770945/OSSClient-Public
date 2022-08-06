#pragma once
#include <iostream>
#include <vector>
#include "utils.h"
#include "concurrentqueue.h"
#include "atomic"
using namespace std;
struct UploadDesc
{
	string file_id, file_name;
	int file_fd;
	uint64_t file_size;

	UploadDesc()
	{
	}
	UploadDesc(string _file_name, string _file_id, int _file_fd, uint64_t _file_size)
	{
		file_name = _file_name;
		file_id = _file_id;
		file_fd = _file_fd;
		file_size = _file_size;
	}
};

struct DownloadDesc
{
	string file_id, file_name;
	uint64_t file_size;
	IpPort server;
	DownloadDesc()
	{
	}
	DownloadDesc(string _file_name, string _file_id, IpPort _server, uint64_t _file_size)
	{
		file_name = _file_name;
		file_id = _file_id;
		file_size = _file_size;
		server = _server;
	}
};

class OSSSDK
{
private:
	string m_token, m_ak, m_sk;
	int m_fd, m_file_fd;
	sockaddr_in m_server_addr, m_registry_addr;
	moodycamel::ConcurrentQueue<UploadDesc> m_add_q;
	moodycamel::ConcurrentQueue<DownloadDesc> m_get_q;
	atomic_bool m_need_upload, m_need_download;
	atomic_int m_upload_num, m_download_num;
	string m_err_msg;

private:
	int Login(int fd);
	IpPort GetServer();
	IpPort GetFileServer();

	void Uploader(vector<pair<string, string>> &file_ids); //上传多个文件的线程
	void Downloader();

public:
	OSSSDK(string ip, int port, string ak, string sk);
	int Init();
	string GetToken(string access_key, string secret_key); //用户请求登录
	int AddFile(string file_path, string &file_id);		   //用户请求上传单个文件
	int GetFile(string file_id);						   //用户请求下载文件

	int AddMutiFile(vector<string> file_paths, vector<pair<string, string>> &file_isd); //请求上传多个文件
	int GetMutiFile(vector<string> file_ids);											//请求下载多个文件

	int DeleteFile(string file_id); //用户请求删除文件
	string GetErrMsg();

	~OSSSDK();
};
