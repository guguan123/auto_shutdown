#include <stdio.h>        // 标准输入输出库，用于 printf 和 scanf 等函数
#include <stdlib.h>       // 标准库，提供内存分配（如 malloc、free）和退出程序（如 exit）功能
#include <stdbool.h>      // 布尔类型支持，定义 true 和 false
#include <string.h>       // 字符串操作库，用于 memset 和 memcpy 等函数
#include <signal.h>       // 信号处理库，用于捕获和处理操作系统信号
#include <time.h>         // 时间处理库，提供时间获取和转换功能（如 time 和 mktime）
#include <windows.h>      // Windows 平台特定头文件，提供 Sleep 函数等
#include <unistd.h>       // POSIX 系统头文件，提供 sleep 和 access 等函数（非 Windows）
#include <curl/curl.h>    // libcurl 库，用于发起 HTTP 请求
#include <cjson/cJSON.h>  // cJSON 库，用于解析 JSON 数据

// 定义常量，方便管理和维护
#define CONFIG_FILE "config.json"           // 配置文件名
#define CHECK_INTERVAL 10                   // 检查间隔时间（秒）
#define TIME_API_URL "https://timeapi.io/api/Time/current/zone?timezone=Asia/Shanghai" // 获取时间的 API 地址

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

// 定义用于存储 curl 请求响应的结构体
struct memory {
	char *response;  // 动态分配的内存，用于存储 HTTP 响应数据
	size_t size;     // 响应数据的字节大小
};

// curl 的写回调函数，将 HTTP 响应数据保存到内存中
static size_t write_callback(void *ptr, size_t size, size_t nmemb, struct memory *mem) {
	size_t total_size = size * nmemb; // 计算本次接收的数据总大小
	// 重新分配内存以容纳新数据（原大小 + 新数据大小 + 1 个字节用于 '\0'）
	void *new_mem = realloc(mem->response, mem->size + total_size + 1);
	if (new_mem == NULL) {            // 如果内存分配失败
		free(mem->response);          // 释放已有内存
		fprintf(stderr, "Out of memory!\n"); // 输出错误信息
		exit(1);                      // 退出程序
	}
	mem->response = new_mem;          // 更新内存指针
	// 将新数据复制到已有数据的末尾
	memcpy(mem->response + mem->size, ptr, total_size);
	mem->size += total_size;          // 更新数据总大小
	mem->response[mem->size] = '\0';  // 在末尾添加字符串结束符
	return total_size;                // 返回处理的数据量，通知 curl 已成功处理
}

// 清理 curl 和 JSON 相关的资源，防止内存泄漏
void cleanup_resources(CURL *curl, struct memory *chunk, cJSON *json) {
	if (chunk->response) free(chunk->response); // 释放 HTTP 响应数据的内存
	if (curl) curl_easy_cleanup(curl);          // 清理 curl 会话
	if (json) cJSON_Delete(json);               // 释放 JSON 对象
	curl_global_cleanup();                      // 清理 libcurl 全局资源
}

// 获取互联网时间，通过 API 返回当前时间
time_t get_internet_time() {
	CURL *curl = NULL;               // curl 会话句柄
	CURLcode res;                    // curl 操作的结果代码
	struct memory chunk = { .response = NULL, .size = 0 }; // 初始化内存结构体，用于存储响应
	cJSON *json = NULL;              // JSON 对象指针

	curl_global_init(CURL_GLOBAL_DEFAULT); // 初始化 libcurl 全局环境
	curl = curl_easy_init();         // 创建一个 curl 会话

	if (!curl) {                     // 如果 curl 初始化失败
		fprintf(stderr, "Failed to initialize curl\n"); // 输出错误信息
		cleanup_resources(curl, &chunk, json); // 清理资源
		return -1;                   // 返回错误值
	}

	// 设置 HTTP 请求头，指定接受 JSON 格式数据
	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "User-Agent: curl/1.0");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	// 禁用 SSL 验证
	//curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	//curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	// 配置 curl 请求选项
	curl_easy_setopt(curl, CURLOPT_URL, TIME_API_URL);       // 设置请求的 URL
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback); // 设置写回调函数
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);       // 指定写回调的目标内存
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);           // 最大重定向次数

	// 执行 HTTP 请求
	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {           // 如果请求失败
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res)); // 输出错误信息
		cleanup_resources(curl, &chunk, json); // 清理资源
		return -1;                   // 返回错误值
	}

	// 解析返回的 JSON 数据
	json = cJSON_Parse(chunk.response);
	if (json == NULL) {              // 如果 JSON 解析失败
		fprintf(stderr, "Failed to parse JSON response: %s\n", chunk.response); // 输出错误信息
		cleanup_resources(curl, &chunk, json); // 清理资源
		return -1;                   // 返回错误值
	}

	// 从 JSON 中提取 "datetime" 字段
	cJSON *datetime_item = cJSON_GetObjectItem(json, "datetime");
	if (datetime_item == NULL) {     // 如果未找到 "datetime" 字段
		fprintf(stderr, "Failed to find 'datetime' in JSON response\n"); // 输出错误信息
		cleanup_resources(curl, &chunk, json); // 清理资源
		return -1;                   // 返回错误值
	}

	// 解析时间字符串（如 "2023-10-15T14:30:00"）
	const char *datetime = datetime_item->valuestring;
	struct tm tm = {0};              // 初始化时间结构体
	if (sscanf(datetime, "%4d-%2d-%2dT%2d:%2d:%2d",
			   &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
			   &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) { // 解析失败
		fprintf(stderr, "Failed to parse datetime from response.\n"); // 输出错误信息
		cleanup_resources(curl, &chunk, json); // 清理资源
		return -1;                   // 返回错误值
	}

	// 调整时间结构体的年份和月份（tm_year 是从 1900 开始，tm_mon 是 0-11）
	tm.tm_year -= 1900;
	tm.tm_mon -= 1;

	// 将 struct tm 转换为 time_t 类型的时间戳
	time_t result = mktime(&tm);

	// 清理资源并返回结果
	cleanup_resources(curl, &chunk, json);
	return result;
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
		printf("System time: %s", ctime(&now)); // 打印当前时间

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
				if (internet_time == -1) { // 如果获取失败
					fprintf(stderr, "Failed to get internet time\n");
				} else {
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
