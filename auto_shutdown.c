#include <stdio.h>        // 标准输入输出库，用于 printf 和 scanf 等函数
#include <stdlib.h>       // 标准库，提供内存分配（如 malloc、free）和退出程序（如 exit）功能
#include <stdbool.h>      // 布尔类型支持，定义 true 和 false
#include <stdint.h>       // 定义 uint8_t, uint32_t 等固定宽度整数类型
#include <string.h>       // 字符串操作库，用于 memset 和 memcpy 等函数
#include <signal.h>       // 信号处理库，用于捕获和处理操作系统信号
#include <time.h>         // 时间处理库，提供时间获取和转换功能（如 time 和 mktime）
#include <unistd.h>       // POSIX 系统头文件，提供 sleep 和 access 等函数（非 Windows）
#include "cJSON.h"  // cJSON 库，用于解析 JSON 数据

#ifdef _WIN32
#include <winsock2.h> // Windows Sockets
#include <ws2tcpip.h> // For getaddrinfo
#include <windows.h>      // Windows 平台特定头文件，提供 Sleep 函数等
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> // For getaddrinfo
#endif

// 定义常量，方便管理和维护
#define CONFIG_FILE "config.json"           // 配置文件名
#define CHECK_INTERVAL 10                   // 检查间隔时间（秒）
#define NTP_PORT "123" // NTP服务器端口
#define NTP_PACKET_SIZE 48 // NTP报文大小（字节）
#define NTP_TIMESTAMP_DELTA 2208988800ULL // 从1900年到1970年1月1日0时0分0秒的秒数

// 全局变量，用于控制程序是否继续运行（volatile 确保多线程或信号处理中的可见性）
volatile bool keep_running = true;

// 信号处理函数，处理中断信号（如 Ctrl+C）或终止信号
void handle_signal(int signal) {
	// 检查接收到的信号是否为 SIGINT（中断）或 SIGTERM（终止）
	if (signal == SIGINT || signal == SIGTERM) {
		keep_running = false; // 将运行标志设置为 false，触发程序优雅退出
	}
}

// 初始化信号处理，根据平台设置信号处理函数
void setup_signal_handling() {
#ifdef _WIN32
	// Windows 平台使用 signal 函数绑定信号处理
	signal(SIGINT, handle_signal);   // 绑定 Ctrl+C 中断信号
	signal(SIGTERM, handle_signal);  // 绑定终止信号
#else
	// POSIX 系统（如 Linux）使用 sigaction 更安全地绑定信号
	struct sigaction action;         // 定义信号处理结构体
	memset(&action, 0, sizeof(struct sigaction)); // 初始化结构体为 0
	action.sa_handler = handle_signal; // 设置信号处理函数
	sigaction(SIGINT, &action, NULL);  // 绑定 SIGINT 信号
	sigaction(SIGTERM, &action, NULL); // 绑定 SIGTERM 信号
#endif
}

// 跨平台的睡眠函数，支持信号中断检查
void platform_sleep(int total_seconds) {
#ifdef _WIN32
	// Windows 平台实现可中断的睡眠
	const int check_interval_ms = 200; // 定义每次检查的时间间隔为 200 毫秒
	int elapsed_ms = 0;                // 已逝去的总时间（毫秒）
	// 循环睡眠，直到达到指定时间或收到退出信号
	while (keep_running && elapsed_ms < total_seconds * 1000) {
		Sleep(check_interval_ms);      // 睡眠 200 毫秒
		elapsed_ms += check_interval_ms; // 更新已逝去时间
	}
#else
	// POSIX 系统直接使用 sleep 函数，睡眠指定秒数
	sleep(total_seconds);
#endif
}

// NTP报文结构 (Simplified)
// 这是一个简化的NTP客户端请求/响应结构，只包含关键字段
typedef struct {
	uint8_t li_vn_mode;      // Leap Indicator, Version Number, Mode
	uint8_t stratum;         // Stratum level of the local clock
	uint8_t poll;            // Poll interval
	uint8_t precision;       // Precision of the local clock
	uint32_t root_delay;     // Total round trip delay to the primary reference source
	uint32_t root_dispersion; // Total dispersion to the primary reference source
	uint32_t ref_id;          // Reference ID
	uint32_t ref_timestamp_secs;// Last update time of the local clock
	uint32_t ref_timestamp_fraq;
	uint32_t orig_timestamp_secs;// Originate Time
	uint32_t orig_timestamp_fraq;
	uint32_t recv_timestamp_secs;// Receive Time
	uint32_t recv_timestamp_fraq;
	uint32_t trans_timestamp_secs;// Transmit Time (最重要的字段，客户端将其设置为当前时间，服务器会返回其发送响应的时间)
	uint32_t trans_timestamp_fraq;
} ntp_packet;

// 清理Winsock (仅Windows)
#ifdef _WIN32
void cleanup_winsock() {
	WSACleanup();
}
#endif

// 获取互联网时间，通过 NTP 服务器获取当前时间
time_t get_internet_time() {
	time_t result_time = -1;
#ifdef _WIN32
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		fprintf(stderr, "WSAStartup failed: %d\n", iResult);
		return -1;
	}
#endif

	int sockfd = -1;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	ntp_packet packet;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; // IPv4 或 IPv6
	hints.ai_socktype = SOCK_DGRAM; // UDP 套接字

	// 尝试解析 time.windows.com
	rv = getaddrinfo("time.windows.com", NTP_PORT, &hints, &servinfo);
	if (rv != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(rv));
#ifdef _WIN32
		cleanup_winsock();
#endif
		return -1;
	}

	// 遍历所有解析到的地址，尝试发送和接收
	for (p = servinfo; p != NULL; p = p->ai_next) {
		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd == -1) {
			continue;
		}
		// 设置超时
		struct timeval tv;
		tv.tv_sec = 500;
		tv.tv_usec = 0;
		setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
		setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

		// 初始化NTP请求包
		memset(&packet, 0, sizeof(ntp_packet));
		packet.li_vn_mode = 0x1B; // Leap Indicator (0), Version (3), Mode (3: Client)

		// 发送NTP请求
		if (sendto(sockfd, (char*)&packet, sizeof(ntp_packet), 0, p->ai_addr, p->ai_addrlen) == -1) {
#ifdef _WIN32
			closesocket(sockfd);
#else
			close(sockfd);
#endif
			sockfd = -1;
			continue;
		}

		// 接收NTP响应
		socklen_t addr_len = (socklen_t)p->ai_addrlen;
		if (recvfrom(sockfd, (char*)&packet, sizeof(ntp_packet), 0, p->ai_addr, &addr_len) == -1) {
#ifdef _WIN32
			int err = WSAGetLastError();
			// 打印详细的错误信息，帮助调试
			fprintf(stderr, "recvfrom failed on current address, WSAGetLastError = %d\n", err);
			closesocket(sockfd);
#else
			perror("recvfrom failed on current address");
			close(sockfd);
#endif
			sockfd = -1;
			continue;
		}
		// 如果成功接收，就退出循环
		break; 
	}

	if (sockfd == -1) {
		fprintf(stderr, "Failed to communicate with NTP server after trying all addresses.\n");
		freeaddrinfo(servinfo);
#ifdef _WIN32
		cleanup_winsock();
#endif
		return -1;
	}

	// 从NTP报文中提取时间戳
	// NTP时间戳是64位无符号整数，前32位是秒数，后32位是小数部分
	// 需要将网络字节序（大端）转换为主机字节序
	uint32_t ntp_seconds = ntohl(packet.trans_timestamp_secs);
	result_time = (time_t)(ntp_seconds - NTP_TIMESTAMP_DELTA);

	// 将NTP时间（从1900年开始）转换为UNIX时间（从1970年开始）
	result_time = (time_t)(ntp_seconds - NTP_TIMESTAMP_DELTA);

#ifdef _WIN32
	closesocket(sockfd);
	cleanup_winsock();
#else
	close(sockfd);
#endif
	freeaddrinfo(servinfo);

	return result_time;
}

// 从 JSON 配置文件中读取配置信息
void read_config(const char *config_file_path, int *shutdown_times[], int *shutdown_time_count, bool *enable_internet_time_check, int *max_time_diff) {
	FILE *fp = fopen(config_file_path, "r"); // 打开配置文件
	if (fp == NULL) {                        // 如果文件打开失败
		perror("Failed to open config file"); // 输出错误信息
		exit(1);                             // 退出程序
	}

	// 获取文件大小
	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// 分配内存以存储文件内容
	char *file_content = (char *)malloc(file_size + 1);
	if (file_content == NULL) {              // 如果内存分配失败
		perror("Failed to allocate memory for config file"); // 输出错误信息
		fclose(fp);                          // 关闭文件
		exit(1);                             // 退出程序
	}

	// 读取文件内容并添加字符串结束符
	fread(file_content, 1, file_size, fp);
	file_content[file_size] = '\0';
	fclose(fp);                              // 关闭文件

	// 解析 JSON 配置文件
	cJSON *json = cJSON_Parse(file_content);
	if (json == NULL) {                      // 如果解析失败
		fprintf(stderr, "Failed to parse JSON config file\n"); // 输出错误信息
		free(file_content);                  // 释放内存
		exit(1);                             // 退出程序
	}

	// 获取 "shutdown_times" 数组
	cJSON *shutdown_times_array = cJSON_GetObjectItem(json, "shutdown_times");
	if (shutdown_times_array == NULL || !cJSON_IsArray(shutdown_times_array)) { // 如果数组无效
		fprintf(stderr, "Invalid or missing 'shutdown_times' array in config file\n"); // 输出错误信息
		cJSON_Delete(json);                  // 释放 JSON 对象
		free(file_content);                  // 释放文件内容内存
		exit(1);                             // 退出程序
	}

	// 获取关机时间数量并分配内存
	*shutdown_time_count = cJSON_GetArraySize(shutdown_times_array);
	*shutdown_times = (int *)malloc(*shutdown_time_count * 2 * sizeof(int)); // 每项包含小时和分钟
	if (*shutdown_times == NULL) {           // 如果内存分配失败
		perror("Failed to allocate memory for shutdown times"); // 输出错误信息
		cJSON_Delete(json);                  // 释放 JSON 对象
		free(file_content);                  // 释放文件内容内存
		exit(1);                             // 退出程序
	}

	// 遍历关机时间数组，提取小时和分钟
	for (int i = 0; i < *shutdown_time_count; i++) {
		cJSON *time_item = cJSON_GetArrayItem(shutdown_times_array, i);
		if (time_item == NULL || !cJSON_IsObject(time_item)) { // 如果项无效
			fprintf(stderr, "Invalid time item in 'shutdown_times' array\n"); // 输出错误信息
			free(*shutdown_times);           // 释放已分配的内存
			cJSON_Delete(json);
			free(file_content);
			exit(1);
		}

		cJSON *hour_item = cJSON_GetObjectItem(time_item, "hour");
		cJSON *minute_item = cJSON_GetObjectItem(time_item, "minute");
		if (hour_item == NULL || minute_item == NULL || !cJSON_IsNumber(hour_item) || !cJSON_IsNumber(minute_item)) { // 如果字段无效
			fprintf(stderr, "Invalid hour or minute in time item\n"); // 输出错误信息
			free(*shutdown_times);
			cJSON_Delete(json);
			free(file_content);
			exit(1);
		}

		(*shutdown_times)[i * 2] = hour_item->valueint;     // 保存小时
		(*shutdown_times)[i * 2 + 1] = minute_item->valueint; // 保存分钟
	}

	// 解析是否启用互联网时间检查
	cJSON *enable_check_item = cJSON_GetObjectItem(json, "enable_internet_time_check");
	if (enable_check_item != NULL && cJSON_IsBool(enable_check_item)) {
		*enable_internet_time_check = cJSON_IsTrue(enable_check_item); // 设置布尔值
	} else {
		*enable_internet_time_check = true; // 默认启用
	}

	// 解析最大时间差
	cJSON *max_diff_item = cJSON_GetObjectItem(json, "max_time_diff");
	if (max_diff_item != NULL && cJSON_IsNumber(max_diff_item)) {
		*max_time_diff = max_diff_item->valueint; // 设置时间差
	} else {
		*max_time_diff = 60;             // 默认 60 秒
	}

	// 清理资源
	cJSON_Delete(json);
	free(file_content);
}

// 检查当前时间是否匹配某个关机时间（允许 1 分钟的误差）
bool should_shutdown(time_t now, int hour, int min) {
	struct tm tm_info;                   // 用于存储分解后的时间
	#ifdef _WIN32
		localtime_s(&tm_info, &now);     // Windows 安全的本地时间转换
	#else
		localtime_r(&now, &tm_info);     // POSIX 线程安全的本地时间转换
	#endif

	// 将当前时间和目标时间转换为分钟数
	int current_time_in_minutes = tm_info.tm_hour * 60 + tm_info.tm_min;
	int target_time_in_minutes = hour * 60 + min;

	// 判断时间差是否在 1 分钟以内
	return abs(current_time_in_minutes - target_time_in_minutes) <= 1;
}

// 主函数，程序入口
int main(int argc, char *argv[]) {
	int *shutdown_times = NULL;          // 存储关机时间（小时和分钟对）
	int shutdown_time_count = 0;         // 关机时间数量
	bool enable_internet_time_check = true; // 是否启用互联网时间检查
	int max_time_diff = 60;              // 最大允许的时间差（秒）
	const char *config_file = CONFIG_FILE; // 默认配置文件路径

	setup_signal_handling();             // 初始化信号处理

	// 如果命令行参数指定了配置文件路径，则使用它
	if (argc > 1) {
		config_file = argv[1];
	}

	// 检查配置文件是否存在
	if (access(config_file, F_OK) == -1) {
		perror("Config file does not exist"); // 输出错误信息
		exit(1);                          // 退出程序
	}

	// 读取配置文件中的关机时间和其他设置
	read_config(config_file, &shutdown_times, &shutdown_time_count, &enable_internet_time_check, &max_time_diff);

	// 打印配置信息
	printf("Shutdown times:\n");
	for (int i = 0; i < shutdown_time_count; i++) {
		printf("%02d:%02d\n", shutdown_times[i * 2], shutdown_times[i * 2 + 1]); // 格式化输出时间
	}
	printf("Enable internet time check: %s\n", enable_internet_time_check ? "true" : "false");
	printf("Max time diff: %d seconds\n", max_time_diff);

	// 主循环，检查是否需要关机
	while (keep_running) {
		time_t now = time(NULL);         // 获取当前系统时间
		printf("System time: %s", ctime(&now)); // 打印当前系统时间

		bool shutdown = false;           // 是否需要关机
		// 检查每个关机时间点
		for (int i = 0; i < shutdown_time_count; i++) {
			if (should_shutdown(now, shutdown_times[i * 2], shutdown_times[i * 2 + 1])) {
				shutdown = true;         // 时间匹配，标记需要关机
				break;
			}
		}

		if (shutdown) {                  // 如果需要关机
			if (enable_internet_time_check) { // 如果启用了互联网时间检查
				time_t internet_time = get_internet_time(); // 获取互联网时间
				if (internet_time == (time_t)-1) { // 如果获取失败
					fprintf(stderr, "Failed to get internet time\n");
				} else {
					printf("Internet time: %s", ctime(&internet_time)); // 打印互联网当前时间
					// 检查系统时间与互联网时间的差值
					if (abs(difftime(now, internet_time)) > max_time_diff) {
						printf("System time and internet time are out of sync!\n"); // 时间不同步
					} else {
						printf("System shutting down...\n"); // 时间同步，执行关机
						#ifdef _WIN32
							system("shutdown /s"); // Windows 关机命令
						#else
							if (geteuid() != 0) { // 检查是否为 root 用户
								fprintf(stderr, "This program must be run as root.\n");
								exit(1);
							}
							system("shutdown now"); // Linux 关机命令
						#endif
						break;           // 退出循环
					}
				}
			} else {                     // 不检查互联网时间，直接关机
				printf("System shutting down...\n");
				#ifdef _WIN32
					system("shutdown /s");
				#else
					if (geteuid() != 0) {
						fprintf(stderr, "This program must be run as root.\n");
						exit(1);
					}
					system("shutdown now");
				#endif
				break;                   // 退出循环
			}
		}

		platform_sleep(CHECK_INTERVAL); // 休眠指定间隔时间
	}

	// 清理动态分配的内存
	if (shutdown_times) free(shutdown_times);
	printf("An exit signal is received and the program ends\n"); // 程序结束提示
	return 0;                            // 返回成功状态
}
