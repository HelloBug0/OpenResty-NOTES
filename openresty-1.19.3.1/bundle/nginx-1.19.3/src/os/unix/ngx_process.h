
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


#include <ngx_setaffinity.h>
#include <ngx_setproctitle.h>


typedef pid_t       ngx_pid_t;

#define NGX_INVALID_PID  -1

typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

typedef struct {
    ngx_pid_t           pid;
    int                 status; /* 由 waitpid 系统调用获得的进程状态 */
    ngx_socket_t        channel[2]; /* 由 socketpair 系统调用产生的用于进程间通信的 socket 句柄，这一对 socket 可以互相通信，目前用于 master 父进程和 worker 子进程间的通信 */

    ngx_spawn_proc_pt   proc; /* 子进程的循环执行方法，当父进程调用 ngx_spawn_process 生成子进程时使用 */
    void               *data; /* 上面函数 proc 的第二个参数指针 */
    char               *name; /* 进程名称，操作系统中显示的进程名称和 name 名称相同 */

    unsigned            respawn:1; /* 标志位，=1：在重新生成子进程 */
    unsigned            just_spawn:1; /* 标志位，=1：正在生成子进程 */
    unsigned            detached:1; /* 标志位，=1：在进行父子进程分离 */
    unsigned            exiting:1; /* 标志位，=1：进程正在退出 */
    unsigned            exited:1; /* 标志位，=1：进程已经退出 */
} ngx_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;


#define NGX_MAX_PROCESSES         1024 /* 最多只能有1024个工作进程 */

#define NGX_PROCESS_NORESPAWN     -1
#define NGX_PROCESS_JUST_SPAWN    -2
#define NGX_PROCESS_RESPAWN       -3
#define NGX_PROCESS_JUST_RESPAWN  -4
#define NGX_PROCESS_DETACHED      -5


#define ngx_getpid   getpid
#define ngx_getppid  getppid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
    ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(ngx_log_t *log);
void ngx_debug_point(void);


#if (NGX_HAVE_SCHED_YIELD)
#define ngx_sched_yield()  sched_yield()
#else
#define ngx_sched_yield()  usleep(1)
#endif


extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

extern ngx_pid_t      ngx_pid;
extern ngx_pid_t      ngx_parent;
extern ngx_socket_t   ngx_channel;
extern ngx_int_t      ngx_process_slot;
extern ngx_int_t      ngx_last_process;
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */
