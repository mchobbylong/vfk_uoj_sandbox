#include <string>
#include <vector>
#include <map>

#ifndef __x86_64__
#error only x86-64 is supported!
#endif

/*
 * a mask that tells seccomp that it should SCMP_ACT_ERRNO(no)
 * when syscall #(mask | no) is called
 * used to implement SCMP_ACT_ERRNO(no) using ptrace:
 *     set the syscall number to mask | no;
 *     PTRACE_CONT
 *     seccomp performs SCMP_ACT_ERRNO(no)
 */
const int SYSCALL_SOFT_BAN_MASK = 996 << 18;

std::vector<int> supported_soft_ban_errno_list = {
	ENOENT,     // No such file or directory
	EPERM,      // Operation not permitted
	EACCES,     // Permission denied
};

std::set<std::string> available_program_type_set = {
	"default", "python2.7", "python3", "java8", "java11", "java17", "compiler"
};

/*
 * folder program: the program to run is a folder, not a single regular file
 */
std::set<std::string> folder_program_type_set = {
	"java8", "java11", "java17"
};

std::map<std::string, std::vector<std::pair<int, syscall_info>>> allowed_syscall_list = {
	{"default", {
		{__NR_read           , syscall_info::unlimited()},
		{__NR_pread64        , syscall_info::unlimited()},
		{__NR_write          , syscall_info::unlimited()},
		{__NR_pwrite64       , syscall_info::unlimited()},
		{__NR_readv          , syscall_info::unlimited()},
		{__NR_writev         , syscall_info::unlimited()},
		{__NR_preadv         , syscall_info::unlimited()},
		{__NR_pwritev        , syscall_info::unlimited()},
		{__NR_sendfile       , syscall_info::unlimited()},

		{__NR_close          , syscall_info::unlimited()},
		{__NR_fstat          , syscall_info::unlimited()},
		{__NR_fstatfs        , syscall_info::unlimited()},
		{__NR_lseek          , syscall_info::unlimited()},
		{__NR_dup            , syscall_info::unlimited()},
		{__NR_dup2           , syscall_info::unlimited()},
		{__NR_dup3           , syscall_info::unlimited()},
		{__NR_ioctl          , syscall_info::unlimited()},
		{__NR_fcntl          , syscall_info::unlimited()},

		{__NR_gettid         , syscall_info::unlimited()},
		{__NR_getpid         , syscall_info::unlimited()},

		{__NR_mmap           , syscall_info::unlimited()},
		{__NR_mprotect       , syscall_info::unlimited()},
		{__NR_munmap         , syscall_info::unlimited()},
		{__NR_brk            , syscall_info::unlimited()},
		{__NR_mremap         , syscall_info::unlimited()},
		{__NR_msync          , syscall_info::unlimited()},
		{__NR_mincore        , syscall_info::unlimited()},
		{__NR_madvise        , syscall_info::unlimited()},

		{__NR_rt_sigaction   , syscall_info::unlimited()},
		{__NR_rt_sigprocmask , syscall_info::unlimited()},
		{__NR_rt_sigreturn   , syscall_info::unlimited()},
		{__NR_rt_sigpending  , syscall_info::unlimited()},
		{__NR_sigaltstack    , syscall_info::unlimited()},

		{__NR_getcwd         , syscall_info::unlimited()},
		{__NR_uname          , syscall_info::unlimited()},

		{__NR_exit           , syscall_info::unlimited()},
		{__NR_exit_group     , syscall_info::unlimited()},

		{__NR_arch_prctl     , syscall_info::unlimited()},

		{__NR_getrusage      , syscall_info::unlimited()},
		{__NR_getrlimit      , syscall_info::unlimited()},

		{__NR_gettimeofday   , syscall_info::unlimited()},
		{__NR_times          , syscall_info::unlimited()},
		{__NR_time           , syscall_info::unlimited()},
		{__NR_clock_gettime  , syscall_info::unlimited()},
		{__NR_clock_getres   , syscall_info::unlimited()},

		{__NR_restart_syscall, syscall_info::unlimited()},

        // for startup
		{__NR_set_tid_address, syscall_info::count_based(1)},
		{__NR_rseq           , syscall_info::count_based(1)},
		{__NR_futex          , syscall_info::count_based(1)},
		{__NR_setitimer      , syscall_info::count_based(1)},
		{__NR_execve         , syscall_info::count_based(1)},
		{__NR_set_robust_list, syscall_info::unlimited()   },

		// need to check file permissions
		{__NR_open           , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_CHECK_OPEN_FLAGS)},
		{__NR_openat         , syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_CHECK_OPEN_FLAGS)},
		{__NR_readlink       , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_S)},
		{__NR_readlinkat     , syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_S)},
		{__NR_access         , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_R)},
		{__NR_faccessat      , syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_R)},
		{__NR_faccessat2     , syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_R)},
		{__NR_stat           , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_S)},
		{__NR_statfs         , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_S)},
		{__NR_lstat          , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_S)},
		{__NR_newfstatat     , syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_S)},

		// kill could be DGS or RE
		{__NR_kill           , syscall_info::kill_type_syscall()},
		{__NR_tkill          , syscall_info::kill_type_syscall()},
		{__NR_tgkill         , syscall_info::kill_type_syscall()},

		// for python
		{__NR_prlimit64      , syscall_info::soft_ban()},

		// for python and java
		{__NR_sysinfo        , syscall_info::unlimited()},

		// python3 uses this call to generate random numbers
		// for fairness, all types of programs can use this call
		{__NR_getrandom      , syscall_info::unlimited()},

		// some python library uses epoll (e.g., z3-solver)
		{__NR_epoll_create   , syscall_info::unlimited()},
		{__NR_epoll_create1  , syscall_info::unlimited()},
		{__NR_epoll_ctl      , syscall_info::unlimited()},
		{__NR_epoll_wait     , syscall_info::unlimited()},
		{__NR_epoll_pwait    , syscall_info::unlimited()},

		// for java
		{__NR_geteuid        , syscall_info::unlimited()},
		{__NR_getuid         , syscall_info::unlimited()},
		{__NR_setrlimit      , syscall_info::soft_ban()},
		{__NR_socket         , syscall_info::soft_ban()},
		{__NR_connect        , syscall_info::soft_ban()},
	}},

	{"allow_proc", {
		{__NR_clone          , syscall_info::unlimited()},
		{__NR_fork           , syscall_info::unlimited()},
		{__NR_vfork          , syscall_info::unlimited()},
		{__NR_nanosleep      , syscall_info::unlimited()},
		{__NR_clock_nanosleep, syscall_info::unlimited()},
		{__NR_wait4          , syscall_info::unlimited()},

		{__NR_execve         , syscall_info::with_extra_check(ECT_FILE_OP | ECT_FILE_R)},
	}},

	{"python2.7", {
		{__NR_set_tid_address, syscall_info::count_based(1)},

		{__NR_futex          , syscall_info::unlimited()},
		{__NR_getdents       , syscall_info::unlimited()},
		{__NR_getdents64     , syscall_info::unlimited()},
	}},

	{"python3", {
		{__NR_set_tid_address, syscall_info::count_based(1)},

		{__NR_futex          , syscall_info::unlimited()},
		{__NR_getdents       , syscall_info::unlimited()},
		{__NR_getdents64     , syscall_info::unlimited()},
	}},

	{"java8", {
		{__NR_set_tid_address  , syscall_info::count_based(1)},
		{__NR_clone            , syscall_info::with_extra_check(ECT_CLONE_THREAD, 9)},

		{__NR_futex            , syscall_info::unlimited()},
		{__NR_getdents         , syscall_info::unlimited()},
		{__NR_getdents64       , syscall_info::unlimited()},

		{__NR_sched_getaffinity, syscall_info::unlimited()},
		{__NR_sched_yield      , syscall_info::unlimited()},
	}},

	{"java11", {
		{__NR_set_tid_address  , syscall_info::count_based(1)},
		{__NR_clone            , syscall_info::with_extra_check(ECT_CLONE_THREAD, 11)},
		{__NR_prctl            , syscall_info::unlimited()}, // TODO: add extra checks for prctl
		{__NR_prlimit64        , syscall_info::unlimited()}, // TODO: add extra checks for prlimit64

		{__NR_futex            , syscall_info::unlimited()},
		{__NR_getdents         , syscall_info::unlimited()},
		{__NR_getdents64       , syscall_info::unlimited()},

		{__NR_sched_getaffinity, syscall_info::unlimited()},
		{__NR_sched_yield      , syscall_info::unlimited()},

		{__NR_nanosleep        , syscall_info::unlimited()},
		{__NR_clock_nanosleep  , syscall_info::unlimited()},
	}},

	{"java17", {
		{__NR_set_tid_address  , syscall_info::count_based(1)},
		{__NR_clone            , syscall_info::with_extra_check(ECT_CLONE_THREAD, 13)},
		{__NR_prctl            , syscall_info::unlimited()}, // TODO: add extra checks for prctl
		{__NR_prlimit64        , syscall_info::unlimited()}, // TODO: add extra checks for prlimit64

		{__NR_futex            , syscall_info::unlimited()},
		{__NR_getdents         , syscall_info::unlimited()},
		{__NR_getdents64       , syscall_info::unlimited()},

		{__NR_sched_getaffinity, syscall_info::unlimited()},
		{__NR_sched_yield      , syscall_info::unlimited()},

		{__NR_nanosleep        , syscall_info::unlimited()},
		{__NR_clock_nanosleep  , syscall_info::unlimited()},
	}},

	{"compiler", {
		{__NR_set_tid_address  , syscall_info::unlimited()},
		{__NR_futex            , syscall_info::unlimited()},

		{__NR_clone            , syscall_info::unlimited()},
		{__NR_fork             , syscall_info::unlimited()},
		{__NR_vfork            , syscall_info::unlimited()},
		{__NR_nanosleep        , syscall_info::unlimited()},
		{__NR_clock_nanosleep  , syscall_info::unlimited()},
		{__NR_wait4            , syscall_info::unlimited()},

		{__NR_geteuid          , syscall_info::unlimited()},
		{__NR_getuid           , syscall_info::unlimited()},
		{__NR_getgid           , syscall_info::unlimited()},
		{__NR_getegid          , syscall_info::unlimited()},
		{__NR_getppid          , syscall_info::unlimited()},

		{__NR_setrlimit        , syscall_info::unlimited()},
		{__NR_prlimit64        , syscall_info::unlimited()},
		{__NR_prctl            , syscall_info::unlimited()},

		{__NR_pipe             , syscall_info::unlimited()},
		{__NR_pipe2            , syscall_info::unlimited()},

		// for java... we have no choice
		{__NR_socketpair       , syscall_info::unlimited()},
		{__NR_socket           , syscall_info::unlimited()},
		{__NR_getsockname      , syscall_info::unlimited()},
		{__NR_setsockopt       , syscall_info::unlimited()},
		{__NR_connect          , syscall_info::unlimited()},
		{__NR_sendto           , syscall_info::unlimited()},
		{__NR_poll             , syscall_info::unlimited()},
		{__NR_recvmsg          , syscall_info::unlimited()},
		{__NR_sysinfo          , syscall_info::unlimited()},

		{__NR_umask            , syscall_info::unlimited()},
		{__NR_getdents         , syscall_info::unlimited()},
		{__NR_getdents64       , syscall_info::unlimited()},

		{__NR_chdir            , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_S)},
		{__NR_fchdir           , syscall_info::unlimited()},

		{__NR_execve           , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_R)},
		{__NR_execveat         , syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_R)},

		{__NR_truncate         , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_W)},
		{__NR_ftruncate        , syscall_info::unlimited()},

		{__NR_chmod            , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_W)},
		{__NR_fchmodat         , syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_W)},
		{__NR_fchmod           , syscall_info::unlimited()},

		{__NR_rename           , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_W | ECT_FILE2_W)},
		{__NR_renameat         , syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_W | ECT_FILE2_W)},
		{__NR_renameat2        , syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_W | ECT_FILE2_W)},

		{__NR_unlink           , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_W)},
		{__NR_unlinkat         , syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_W)},

		{__NR_mkdir            , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_W)},
		{__NR_mkdirat          , syscall_info::with_extra_check(ECT_FILEAT_OP | ECT_FILE_W)},

		{__NR_rmdir            , syscall_info::with_extra_check(ECT_FILE_OP   | ECT_FILE_W)},

		{__NR_fadvise64        , syscall_info::unlimited()},

		{__NR_sched_getaffinity, syscall_info::unlimited()},
		{__NR_sched_yield      , syscall_info::unlimited()},

		{__NR_kill           , syscall_info::kill_type_syscall(ECT_KILL_SIG0_ALLOWED, -1)},
		{__NR_tkill          , syscall_info::kill_type_syscall(ECT_KILL_SIG0_ALLOWED, -1)},
		{__NR_tgkill         , syscall_info::kill_type_syscall(ECT_KILL_SIG0_ALLOWED, -1)},

		{__NR_rseq             , syscall_info::unlimited()},
	}},
};

std::map<std::string, std::vector<std::string>> soft_ban_file_name_list = {
	{"default", {
		"/dev/tty",

		// for python 3.9
		"/usr/lib/python39.zip",

		// for java and javac...
		"/etc/nsswitch.conf",
		"/etc/passwd",
	}}
};

std::map<std::string, std::vector<std::string>> statable_file_name_list = {
	{"default", {}},

	{"python2.7", {
		"/usr",
		"/usr/bin",
		"/usr/lib",
	}},

	{"python3", {
		"/usr",
		"/usr/bin",
		"/usr/lib",
	}},

	{"java8", {
		"/usr/java/",
		"/tmp/",
	}},

	{"java11", {
		"/tmp/",
	}},

	{"java17", {
		"/tmp/",
	}},

	{"compiler", {
		"/*",
		"/boot/",
	}}
};

std::map<std::string, std::vector<std::string>> readable_file_name_list = {
	{"default", {
		"/lib/x86_64-linux-gnu/",
		"/usr/lib/x86_64-linux-gnu/",
		"/usr/lib/locale/",
		"/usr/share/zoneinfo/",
		"/etc/ld.so.nohwcap",
		"/etc/ld.so.preload",
		"/etc/ld.so.cache",
		"/etc/timezone",
		"/etc/localtime",
		"/etc/locale.alias",
		"/proc/self/",
		"/proc/*",
		"/dev/random",
		"/dev/urandom",
		"/sys/devices/system/cpu/", // for java & some python libraries
		"/proc/sys/vm/", // for java
		"/opt/gcc-12.3.0/", // for programs compiled by custom gcc compiler
	}},

	{"python2.7", {
		"/etc/python2.7/",
		"/usr/bin/python2.7",
		"/usr/lib/python2.7/",
		"/usr/bin/lib/python2.7/",
		"/usr/local/lib/python2.7/",
		"/usr/lib/pymodules/python2.7/",
		"/usr/bin/Modules/",
		"/usr/bin/pybuilddir.txt",
	}},

	{"python3", {
		"/etc/python3.9/",
		"/usr/bin/python3.9",
		"/usr/lib/python3.9/",
		"/usr/lib/python3/dist-packages/",
		"/usr/bin/lib/python3.9/",
		"/usr/local/lib/python3.9/",
		"/usr/bin/pyvenv.cfg",
		"/usr/pyvenv.cfg",
		"/usr/bin/Modules/",
		"/usr/bin/pybuilddir.txt",
		"/usr/lib/dist-python",
	}},

	{"java8", {
		"/sys/fs/cgroup/",
	}},

	{"java11", {
		UOJ_OPEN_JDK11 "/",
		"/sys/fs/cgroup/",
		"/etc/java-11-openjdk/",
		"/usr/share/java/",
	}},

	{"java17", {
		UOJ_OPEN_JDK17 "/",
		"/sys/fs/cgroup/",
		"/etc/java-17-openjdk/",
		"/usr/share/java/",
	}},

	{"compiler", {
		"system_root",
		"/usr/",
		"/lib/",
		"/lib64/",
		"/bin/",
		"/sbin/",
		"/sys/fs/cgroup/",
		"/proc/",
		"/etc/timezone",
		"/etc/python2.7/",
		"/etc/python3.10/",
		"/etc/fpc-3.2.2.cfg",
		"/etc/java-11-openjdk/",
		"/etc/java-17-openjdk/",
		"/etc/alternatives/",
		"/opt/gcc-12.3.0/", // for custom gcc compiler
	}}
};

std::map<std::string, std::vector<std::string>> writable_file_name_list = {
	{"default", {
		"/dev/null",

		// for java11 and java17
		"/proc/self/coredump_filter",
	}},

	{"compiler", {
		"/tmp/",
	}}
};

const int MAX_SYSCALL_NO = 450;
std::map<int, std::string> syscall_name = {
	{0, "read"},
	{1, "write"},
	{2, "open"},
	{3, "close"},
	{4, "stat"},
	{5, "fstat"},
	{6, "lstat"},
	{7, "poll"},
	{8, "lseek"},
	{9, "mmap"},
	{10, "mprotect"},
	{11, "munmap"},
	{12, "brk"},
	{13, "rt_sigaction"},
	{14, "rt_sigprocmask"},
	{15, "rt_sigreturn"},
	{16, "ioctl"},
	{17, "pread64"},
	{18, "pwrite64"},
	{19, "readv"},
	{20, "writev"},
	{21, "access"},
	{22, "pipe"},
	{23, "select"},
	{24, "sched_yield"},
	{25, "mremap"},
	{26, "msync"},
	{27, "mincore"},
	{28, "madvise"},
	{29, "shmget"},
	{30, "shmat"},
	{31, "shmctl"},
	{32, "dup"},
	{33, "dup2"},
	{34, "pause"},
	{35, "nanosleep"},
	{36, "getitimer"},
	{37, "alarm"},
	{38, "setitimer"},
	{39, "getpid"},
	{40, "sendfile"},
	{41, "socket"},
	{42, "connect"},
	{43, "accept"},
	{44, "sendto"},
	{45, "recvfrom"},
	{46, "sendmsg"},
	{47, "recvmsg"},
	{48, "shutdown"},
	{49, "bind"},
	{50, "listen"},
	{51, "getsockname"},
	{52, "getpeername"},
	{53, "socketpair"},
	{54, "setsockopt"},
	{55, "getsockopt"},
	{56, "clone"},
	{57, "fork"},
	{58, "vfork"},
	{59, "execve"},
	{60, "exit"},
	{61, "wait4"},
	{62, "kill"},
	{63, "uname"},
	{64, "semget"},
	{65, "semop"},
	{66, "semctl"},
	{67, "shmdt"},
	{68, "msgget"},
	{69, "msgsnd"},
	{70, "msgrcv"},
	{71, "msgctl"},
	{72, "fcntl"},
	{73, "flock"},
	{74, "fsync"},
	{75, "fdatasync"},
	{76, "truncate"},
	{77, "ftruncate"},
	{78, "getdents"},
	{79, "getcwd"},
	{80, "chdir"},
	{81, "fchdir"},
	{82, "rename"},
	{83, "mkdir"},
	{84, "rmdir"},
	{85, "creat"},
	{86, "link"},
	{87, "unlink"},
	{88, "symlink"},
	{89, "readlink"},
	{90, "chmod"},
	{91, "fchmod"},
	{92, "chown"},
	{93, "fchown"},
	{94, "lchown"},
	{95, "umask"},
	{96, "gettimeofday"},
	{97, "getrlimit"},
	{98, "getrusage"},
	{99, "sysinfo"},
	{100, "times"},
	{101, "ptrace"},
	{102, "getuid"},
	{103, "syslog"},
	{104, "getgid"},
	{105, "setuid"},
	{106, "setgid"},
	{107, "geteuid"},
	{108, "getegid"},
	{109, "setpgid"},
	{110, "getppid"},
	{111, "getpgrp"},
	{112, "setsid"},
	{113, "setreuid"},
	{114, "setregid"},
	{115, "getgroups"},
	{116, "setgroups"},
	{117, "setresuid"},
	{118, "getresuid"},
	{119, "setresgid"},
	{120, "getresgid"},
	{121, "getpgid"},
	{122, "setfsuid"},
	{123, "setfsgid"},
	{124, "getsid"},
	{125, "capget"},
	{126, "capset"},
	{127, "rt_sigpending"},
	{128, "rt_sigtimedwait"},
	{129, "rt_sigqueueinfo"},
	{130, "rt_sigsuspend"},
	{131, "sigaltstack"},
	{132, "utime"},
	{133, "mknod"},
	{134, "uselib"},
	{135, "personality"},
	{136, "ustat"},
	{137, "statfs"},
	{138, "fstatfs"},
	{139, "sysfs"},
	{140, "getpriority"},
	{141, "setpriority"},
	{142, "sched_setparam"},
	{143, "sched_getparam"},
	{144, "sched_setscheduler"},
	{145, "sched_getscheduler"},
	{146, "sched_get_priority_max"},
	{147, "sched_get_priority_min"},
	{148, "sched_rr_get_interval"},
	{149, "mlock"},
	{150, "munlock"},
	{151, "mlockall"},
	{152, "munlockall"},
	{153, "vhangup"},
	{154, "modify_ldt"},
	{155, "pivot_root"},
	{156, "_sysctl"},
	{157, "prctl"},
	{158, "arch_prctl"},
	{159, "adjtimex"},
	{160, "setrlimit"},
	{161, "chroot"},
	{162, "sync"},
	{163, "acct"},
	{164, "settimeofday"},
	{165, "mount"},
	{166, "umount2"},
	{167, "swapon"},
	{168, "swapoff"},
	{169, "reboot"},
	{170, "sethostname"},
	{171, "setdomainname"},
	{172, "iopl"},
	{173, "ioperm"},
	{174, "create_module"},
	{175, "init_module"},
	{176, "delete_module"},
	{177, "get_kernel_syms"},
	{178, "query_module"},
	{179, "quotactl"},
	{180, "nfsservctl"},
	{181, "getpmsg"},
	{182, "putpmsg"},
	{183, "afs_syscall"},
	{184, "tuxcall"},
	{185, "security"},
	{186, "gettid"},
	{187, "readahead"},
	{188, "setxattr"},
	{189, "lsetxattr"},
	{190, "fsetxattr"},
	{191, "getxattr"},
	{192, "lgetxattr"},
	{193, "fgetxattr"},
	{194, "listxattr"},
	{195, "llistxattr"},
	{196, "flistxattr"},
	{197, "removexattr"},
	{198, "lremovexattr"},
	{199, "fremovexattr"},
	{200, "tkill"},
	{201, "time"},
	{202, "futex"},
	{203, "sched_setaffinity"},
	{204, "sched_getaffinity"},
	{205, "set_thread_area"},
	{206, "io_setup"},
	{207, "io_destroy"},
	{208, "io_getevents"},
	{209, "io_submit"},
	{210, "io_cancel"},
	{211, "get_thread_area"},
	{212, "lookup_dcookie"},
	{213, "epoll_create"},
	{214, "epoll_ctl_old"},
	{215, "epoll_wait_old"},
	{216, "remap_file_pages"},
	{217, "getdents64"},
	{218, "set_tid_address"},
	{219, "restart_syscall"},
	{220, "semtimedop"},
	{221, "fadvise64"},
	{222, "timer_create"},
	{223, "timer_settime"},
	{224, "timer_gettime"},
	{225, "timer_getoverrun"},
	{226, "timer_delete"},
	{227, "clock_settime"},
	{228, "clock_gettime"},
	{229, "clock_getres"},
	{230, "clock_nanosleep"},
	{231, "exit_group"},
	{232, "epoll_wait"},
	{233, "epoll_ctl"},
	{234, "tgkill"},
	{235, "utimes"},
	{236, "vserver"},
	{237, "mbind"},
	{238, "set_mempolicy"},
	{239, "get_mempolicy"},
	{240, "mq_open"},
	{241, "mq_unlink"},
	{242, "mq_timedsend"},
	{243, "mq_timedreceive"},
	{244, "mq_notify"},
	{245, "mq_getsetattr"},
	{246, "kexec_load"},
	{247, "waitid"},
	{248, "add_key"},
	{249, "request_key"},
	{250, "keyctl"},
	{251, "ioprio_set"},
	{252, "ioprio_get"},
	{253, "inotify_init"},
	{254, "inotify_add_watch"},
	{255, "inotify_rm_watch"},
	{256, "migrate_pages"},
	{257, "openat"},
	{258, "mkdirat"},
	{259, "mknodat"},
	{260, "fchownat"},
	{261, "futimesat"},
	{262, "newfstatat"},
	{263, "unlinkat"},
	{264, "renameat"},
	{265, "linkat"},
	{266, "symlinkat"},
	{267, "readlinkat"},
	{268, "fchmodat"},
	{269, "faccessat"},
	{270, "pselect6"},
	{271, "ppoll"},
	{272, "unshare"},
	{273, "set_robust_list"},
	{274, "get_robust_list"},
	{275, "splice"},
	{276, "tee"},
	{277, "sync_file_range"},
	{278, "vmsplice"},
	{279, "move_pages"},
	{280, "utimensat"},
	{281, "epoll_pwait"},
	{282, "signalfd"},
	{283, "timerfd_create"},
	{284, "eventfd"},
	{285, "fallocate"},
	{286, "timerfd_settime"},
	{287, "timerfd_gettime"},
	{288, "accept4"},
	{289, "signalfd4"},
	{290, "eventfd2"},
	{291, "epoll_create1"},
	{292, "dup3"},
	{293, "pipe2"},
	{294, "inotify_init1"},
	{295, "preadv"},
	{296, "pwritev"},
	{297, "rt_tgsigqueueinfo"},
	{298, "perf_event_open"},
	{299, "recvmmsg"},
	{300, "fanotify_init"},
	{301, "fanotify_mark"},
	{302, "prlimit64"},
	{303, "name_to_handle_at"},
	{304, "open_by_handle_at"},
	{305, "clock_adjtime"},
	{306, "syncfs"},
	{307, "sendmmsg"},
	{308, "setns"},
	{309, "getcpu"},
	{310, "process_vm_readv"},
	{311, "process_vm_writev"},
	{312, "kcmp"},
	{313, "finit_module"},
	{314, "sched_setattr"},
	{315, "sched_getattr"},
	{316, "renameat2"},
	{317, "seccomp"},
	{318, "getrandom"},
	{319, "memfd_create"},
	{320, "kexec_file_load"},
	{321, "bpf"},
	{322, "execveat"},
	{323, "userfaultfd"},
	{324, "membarrier"},
	{325, "mlock2"},
	{326, "copy_file_range"},
	{327, "preadv2"},
	{328, "pwritev2"},
	{329, "pkey_mprotect"},
	{330, "pkey_alloc"},
	{331, "pkey_free"},
	{332, "statx"},
	{333, "io_pgetevents"},
	{334, "rseq"},
	{424, "pidfd_send_signal"},
	{425, "io_uring_setup"},
	{426, "io_uring_enter"},
	{427, "io_uring_register"},
	{428, "open_tree"},
	{429, "move_mount"},
	{430, "fsopen"},
	{431, "fsconfig"},
	{432, "fsmount"},
	{433, "fspick"},
	{434, "pidfd_open"},
	{435, "clone3"},
	{436, "close_range"},
	{437, "openat2"},
	{438, "pidfd_getfd"},
	{439, "faccessat2"},
	{440, "process_madvise"},
	{441, "epoll_pwait2"},
	{442, "mount_setattr"},
	{443, "quotactl_fd"},
	{444, "landlock_create_ruleset"},
	{445, "landlock_add_rule"},
	{446, "landlock_restrict_self"},
	{447, "memfd_secret"},
	{448, "process_mrelease"},
	{449, "futex_waitv"},
	{450, "set_mempolicy_home_node"},
};
