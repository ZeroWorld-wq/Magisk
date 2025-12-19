#include <consts.hpp>
#include <base.hpp>

#include "policy.hpp"

using namespace std;

void sepolicy::magisk_rules() {
    // Temp suppress warnings
    set_log_level_state(LogLevel::Warn, false);

    // Allow everything to change sepolicy (放宽策略加载限制)
    allow(ALL, "kernel", "security", "load_policy");

    type(SEPOL_PROC_DOMAIN, "domain");
    permissive(SEPOL_PROC_DOMAIN);  /* Just in case something is missing */
    typeattribute(SEPOL_PROC_DOMAIN, "mlstrustedsubject");
    typeattribute(SEPOL_PROC_DOMAIN, "netdomain");
    typeattribute(SEPOL_PROC_DOMAIN, "bluetoothdomain");
    type(SEPOL_FILE_TYPE, "file_type");
    typeattribute(SEPOL_FILE_TYPE, "mlstrustedobject");
    type(SEPOL_LOG_TYPE, "file_type");
    typeattribute(SEPOL_LOG_TYPE, "mlstrustedobject");

    // Make our root domain unconstrained
    allow(SEPOL_PROC_DOMAIN, ALL, ALL, ALL);
    // Allow us to do any ioctl
    if (impl->db->policyvers >= POLICYDB_VERSION_XPERMS_IOCTL) {
        allowxperm(SEPOL_PROC_DOMAIN, ALL, "blk_file", ALL_XPERM);
        allowxperm(SEPOL_PROC_DOMAIN, ALL, "fifo_file", ALL_XPERM);
        allowxperm(SEPOL_PROC_DOMAIN, ALL, "chr_file", ALL_XPERM);
    }

    // Create unconstrained file type
    allow(ALL, SEPOL_FILE_TYPE, "file", ALL);
    allow(ALL, SEPOL_FILE_TYPE, "dir", ALL);
    allow(ALL, SEPOL_FILE_TYPE, "fifo_file", ALL);
    allow(ALL, SEPOL_FILE_TYPE, "chr_file", ALL);
    allow(ALL, SEPOL_FILE_TYPE, "lnk_file", ALL);
    allow(ALL, SEPOL_FILE_TYPE, "sock_file", ALL);

    // Allow all processes to open log pipe
    allow(ALL, SEPOL_LOG_TYPE, "fifo_file", "open");
    allow(ALL, SEPOL_LOG_TYPE, "fifo_file", "read");
    // Allow all processes to output logs
    allow(ALL, SEPOL_LOG_TYPE, "fifo_file", "write");

    // Allow these processes to access MagiskSU and output logs
    const char *clients[] {
        "zygote", "shell", "system_app", "platform_app",
        "priv_app", "untrusted_app", "untrusted_app_all", "init"
    };
    
    // 为所有客户端域设置宽容模式并放宽限制
    for (auto type: clients) {
        if (!exists(type))
            continue;
        
        // 设置为宽容域
        permissive(type);
        
        // 允许这些域访问 MagiskSU
        allow(type, SEPOL_PROC_DOMAIN, "unix_stream_socket", "connectto");
        allow(type, SEPOL_PROC_DOMAIN, "unix_stream_socket", "getopt");
        
        // 放宽限制：允许这些域执行大部分操作
        allow(type, ALL, "process", ALL);
        allow(type, ALL, "fd", ALL);
        allow(type, ALL, "fifo_file", ALL);
        allow(type, ALL, "file", ALL);
        allow(type, ALL, "dir", ALL);
        allow(type, ALL, "chr_file", ALL);
        allow(type, ALL, "blk_file", ALL);
        allow(type, ALL, "lnk_file", ALL);
        allow(type, ALL, "sock_file", ALL);
        allow(type, ALL, "unix_stream_socket", ALL);
        allow(type, ALL, "unix_dgram_socket", ALL);
        allow(type, ALL, "tcp_socket", ALL);
        allow(type, ALL, "udp_socket", ALL);
        allow(type, ALL, "binder", ALL);
        allow(type, ALL, "property_socket", ALL);
        allow(type, ALL, "socket", ALL);
        
        // 允许执行和共享内存操作
        allow(type, type, "process", "execmem");
        allow(type, type, "process", "execstack");
        allow(type, type, "process", "execheap");
        allow(type, ALL, "process", "ptrace");
        
        // 允许加载内核模块和执行系统调用
        allow(type, "kernel", "system", ALL);
        allow(type, "kernel", "security", ALL);
        
        // 允许操作所有文件系统
        allow(type, ALL, "filesystem", ALL);
        
        // 允许网络相关操作
        allow(type, ALL, "netlink", ALL);
        allow(type, ALL, "packet", ALL);
        allow(type, ALL, "key", ALL);
        allow(type, ALL, "dbus", ALL);
        
        // 允许所有ioctl操作
        if (impl->db->policyvers >= POLICYDB_VERSION_XPERMS_IOCTL) {
            allowxperm(type, ALL, "blk_file", ALL_XPERM);
            allowxperm(type, ALL, "fifo_file", ALL_XPERM);
            allowxperm(type, ALL, "chr_file", ALL_XPERM);
        }
    }

    // Let everyone access tmpfs files (for SAR sbin overlay)
    allow(ALL, "tmpfs", "file", ALL);
    allow(ALL, "tmpfs", "dir", ALL);
    allow(ALL, "tmpfs", "fifo_file", ALL);
    allow(ALL, "tmpfs", "chr_file", ALL);

    // Allow magiskinit daemon to handle mock selinuxfs
    allow("kernel", "tmpfs", "fifo_file", "write");

    // For relabelling files
    allow("rootfs", "labeledfs", "filesystem", "associate");
    allow(SEPOL_FILE_TYPE, "pipefs", "filesystem", "associate");
    allow(SEPOL_FILE_TYPE, "devpts", "filesystem", "associate");
    allow(ALL, ALL, "filesystem", "associate");  // 放宽文件系统关联限制

    // Let init transit to SEPOL_PROC_DOMAIN
    allow("kernel", "kernel", "process", "setcurrent");
    allow("kernel", SEPOL_PROC_DOMAIN, "process", "dyntransition");
    allow(ALL, ALL, "process", "dyntransition");  // 放宽域转换限制

    // Let init run stuffs
    allow("kernel", SEPOL_PROC_DOMAIN, "fd", "use");
    allow("init", SEPOL_PROC_DOMAIN, "process", ALL);
    allow(ALL, ALL, "process", ALL);  // 放宽进程操作限制

    // suRights - 放宽所有域的服务管理器访问
    allow(ALL, SEPOL_PROC_DOMAIN, "dir", "search");
    allow(ALL, SEPOL_PROC_DOMAIN, "dir", "read");
    allow(ALL, SEPOL_PROC_DOMAIN, "file", "open");
    allow(ALL, SEPOL_PROC_DOMAIN, "file", "read");
    allow(ALL, SEPOL_PROC_DOMAIN, "process", "getattr");
    allow(ALL, SEPOL_PROC_DOMAIN, "process", "sigchld");

    // allowLog - 放宽日志访问
    allow(ALL, SEPOL_PROC_DOMAIN, "dir", "search");
    allow(ALL, SEPOL_PROC_DOMAIN, "file", "read");
    allow(ALL, SEPOL_PROC_DOMAIN, "file", "open");
    allow(ALL, SEPOL_PROC_DOMAIN, "file", "getattr");

    // dumpsys - 放宽所有域
    allow(ALL, SEPOL_PROC_DOMAIN, "fd", "use");
    allow(ALL, SEPOL_PROC_DOMAIN, "fifo_file", "write");
    allow(ALL, SEPOL_PROC_DOMAIN, "fifo_file", "read");
    allow(ALL, SEPOL_PROC_DOMAIN, "fifo_file", "open");
    allow(ALL, SEPOL_PROC_DOMAIN, "fifo_file", "getattr");

    // bootctl - 放宽硬件服务管理器
    allow("hwservicemanager", SEPOL_PROC_DOMAIN, "dir", "search");
    allow("hwservicemanager", SEPOL_PROC_DOMAIN, "file", "read");
    allow("hwservicemanager", SEPOL_PROC_DOMAIN, "file", "open");
    allow("hwservicemanager", SEPOL_PROC_DOMAIN, "process", "getattr");

    // For mounting loop devices, mirrors, tmpfs
    allow("kernel", ALL, "file", "read");
    allow("kernel", ALL, "file", "write");
    allow(ALL, ALL, "file", ALL);  // 放宽文件访问

    // Allow all binder transactions
    allow(ALL, SEPOL_PROC_DOMAIN, "binder", ALL);
    allow(ALL, ALL, "binder", ALL);  // 放宽所有域的binder通信

    // For changing file context
    allow("rootfs", "tmpfs", "filesystem", "associate");
    allow(ALL, ALL, "filesystem", "associate");  // 放宽所有文件系统关联

    // Zygisk rules - 放宽Zygisk限制
    allow("zygote", "zygote", "process", "execmem");
    allow("zygote", "zygote", "process", "execstack");
    allow("zygote", "zygote", "process", "execheap");
    allow("zygote", "fs_type", "filesystem", "unmount");
    allow("system_server", "system_server", "process", "execmem");
    allow("system_server", "system_server", "process", "execstack");
    allow("system_server", "system_server", "process", "execheap");

    // 放宽所有域的ptrace权限，不记录拒绝
    dontaudit(ALL, ALL, "process", "ptrace");
    allow(ALL, ALL, "process", "ptrace");  // 允许所有域ptrace

    // 放宽/data/adb/* 上下文限制
    allow("init", "adb_data_file", "dir", "search");
    allow("init", "adb_data_file", "dir", "read");
    allow("init", "adb_data_file", "dir", "write");
    allow("init", "adb_data_file", "file", ALL);
    allow("vendor_init", "adb_data_file", "dir", "search");
    allow("vendor_init", "adb_data_file", "dir", "read");
    allow("vendor_init", "adb_data_file", "dir", "write");
    allow("vendor_init", "adb_data_file", "file", ALL);

    // 放宽所有域的设备访问
    allow(ALL, ALL, "device", ALL);
    
    // 放宽所有域的安全上下文操作
    allow(ALL, ALL, "security", ALL);
    
    // 放宽所有域的能力操作
    allow(ALL, ALL, "capability", ALL);
    
    // 放宽所有域的网络操作
    allow(ALL, ALL, "netif", ALL);
    allow(ALL, ALL, "port", ALL);
    allow(ALL, ALL, "node", ALL);
    
    // 放宽所有域的系统属性操作
    allow(ALL, ALL, "property_type", ALL);
    
    // 放宽所有域的资源限制
    allow(ALL, ALL, "resource", ALL);
    
    // 放宽所有域的信号发送
    allow(ALL, ALL, "process", "signal");

    // 移除所有dontaudit规则（完全开放）
    impl->strip_dontaudit();

    set_log_level_state(LogLevel::Warn, true);
}
