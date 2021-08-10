
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


#define HAVE_PRIVILEGED_PROCESS_PATCH   1


#define HAVE_INTERCEPT_ERROR_LOG_PATCH


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);
typedef ngx_int_t (*ngx_log_intercept_pt) (ngx_log_t *log, ngx_uint_t level,
    u_char *buf, size_t len);

struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
    void                     *sync;
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


struct ngx_cycle_s {
    void                  ****conf_ctx; /* 保存着所有模块存储配置项的结构体的指针 */
    ngx_pool_t               *pool;

    ngx_log_t                *log; /* 日志模块提供生成ngx_log_t日志对象的功能，在还没有执行ngx_init_cycle方法前，也就是还没有解析配置前，如果有信息需要输出到日志，就会使用这个对象，他会将日志输出到屏幕上。在ngx_init_cycle之后，将会根据nginx.conf中的配置，构造出正确的日志文件，会对log进行重新赋值 */
    ngx_log_t                 new_log; /* 读取nginx.conf配置文件之后，初始化error_log日志文件，文件指针即为new_log，上述的log指针指向屏幕，这里会使用new_log代替log，初始化成功之后，会将new_log赋值给log */

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    ngx_connection_t        **files; /* 像poll、rtsig这样的事件处理模块，会以有效文件句柄数来预先建立ngx_connection_t结构体，以加速事件的收集和分发。files 保存所有的ngx_connection_t的指针组成的数组 */
    ngx_connection_t         *free_connections; /* 可用连接池 */
    ngx_uint_t                free_connection_n; /* 可用连接池的数量 */

    ngx_module_t            **modules;
    ngx_uint_t                modules_n;
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */

    ngx_queue_t               reusable_connections_queue; /* 双向链表，可重复使用的连接队列 */
    ngx_uint_t                reusable_connections_n;
    time_t                    connections_reuse_time;

    ngx_array_t               listening; /* 动态数组，数组元素类型 ngx_listening_t，每个数组元素保存一个监听的端口 */
    ngx_array_t               paths; /* 动态数组容器，保存nginx要操作的目录，如果目录不存在，则重新创建，而创建目录失败，会导致nginx启动失败 */

    ngx_array_t               config_dump;
    ngx_rbtree_t              config_dump_rbtree;
    ngx_rbtree_node_t         config_dump_sentinel;

    ngx_list_t                open_files; /* 单链表，元素类型为 ngx_open_file_t，Nginx 已经打开的文件，Nginx框架不会向该链表中添加文件，感兴趣的模块向其中添加，Nginx框架会在ngx_init_cycle中打开这些文件 */
    ngx_list_t                shared_memory; /* 单链表，元素类型为 ngx_shm_zone_t 结构体，每个元素表示一块共享内存 */

    ngx_uint_t                connection_n; /* 当前进程中所有连接数 */
    ngx_uint_t                files_n;

    ngx_connection_t         *connections; /* 当前进程中所有连接对象 */
    ngx_event_t              *read_events; /* 当前进程中所有读事件对象 */
    ngx_event_t              *write_events; /* 当前进程中所有写事件对象 */

    ngx_cycle_t              *old_cycle; /* 旧的ngx_cycle_t对象 */

    ngx_str_t                 conf_file; /* 配置文件相对于安装目录的路径名称 */
    ngx_str_t                 conf_param; /* 命令行中携带的配置参数 */
    ngx_str_t                 conf_prefix; /* 配置文件所在目录的路径 */
    ngx_str_t                 prefix; /* 安装目录的路径 */
    ngx_str_t                 lock_file; /* 用于进程间同步的文件锁名称 */
    ngx_str_t                 hostname; /* 使用 gethostname 系统调用获得的主机名 */

    ngx_log_intercept_pt      intercept_error_log_handler;
    void                     *intercept_error_log_data;
    unsigned                  entered_logger;    /* :1 */
};


typedef struct {
    ngx_flag_t                daemon;
    ngx_flag_t                master;
    ngx_flag_t                privileged_agent;

    ngx_msec_t                timer_resolution;
    ngx_msec_t                shutdown_timeout;

    ngx_int_t                 worker_processes;
    ngx_int_t                 debug_points;

    ngx_int_t                 rlimit_nofile;
    off_t                     rlimit_core;

    int                       priority;

    ngx_uint_t                cpu_affinity_auto;
    ngx_uint_t                cpu_affinity_n;
    ngx_cpuset_t             *cpu_affinity;

    char                     *username;
    ngx_uid_t                 user;
    ngx_gid_t                 group;

    ngx_str_t                 working_directory;
    ngx_str_t                 lock_file;

    ngx_str_t                 pid;
    ngx_str_t                 oldpid;

    ngx_array_t               env;
    char                    **environment;

    ngx_uint_t                transparent;  /* unsigned  transparent:1; */
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);
void ngx_set_shutdown_timer(ngx_cycle_t *cycle);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
