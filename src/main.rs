use std::env;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::os::windows::process::CommandExt;
use std::os::windows::ffi::OsStrExt;
use walkdir::WalkDir;

use windows_sys::Win32::System::RestartManager::{
    RmStartSession, RmRegisterResources, RmGetList, RmShutdown, RmEndSession,
    RmForceShutdown, RM_PROCESS_INFO
};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, ERROR_MORE_DATA, CloseHandle};
use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

const CREATE_NO_WINDOW: u32 = 0x08000000;
const EXE_NAME: &str = "force_delete.exe";

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy()
        .to_lowercase()
        .trim_start_matches(r#"\\?\"#)
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_string()
}

// 动态获取系统实际盘符
fn get_system_drive() -> String {
    env::var("SystemDrive")
        .unwrap_or_else(|_| "C:".to_string())
        .to_lowercase()
}

// 获取动态安全的安装目录
fn get_install_dir() -> PathBuf {
    let program_files = env::var("ProgramFiles")
        .unwrap_or_else(|_| format!("{}\\Program Files", get_system_drive()));
    PathBuf::from(program_files).join("ForceDelete")
}

// 检测是否为系统关键路径
fn is_critical_path(path: &Path) -> bool {
    let clean_path = normalize_path(path);
    let sys_drive = get_system_drive();
    
    let blocked_paths = [
        format!("{}\\", sys_drive),
        format!("{}\\windows", sys_drive),
        format!("{}\\windows\\system32", sys_drive),
        format!("{}\\users", sys_drive),
        format!("{}\\program files", sys_drive),
        format!("{}\\program files (x86)", sys_drive),
        format!("{}\\programdata", sys_drive),
    ];

    for blocked in &blocked_paths {
        if clean_path == *blocked || clean_path == blocked.trim_end_matches('\\') {
            return true;
        }
    }
    false
}

// 释放 Restart Manager 资源的守卫
struct RmSessionGuard { handle: u32 }
impl Drop for RmSessionGuard {
    fn drop(&mut self) {
        if self.handle != 0 { unsafe { let _ = RmEndSession(self.handle); } }
    }
}

// 授权核心逻辑
fn grant_permissions(path: &Path) {
    let path_str = path.to_string_lossy();
    let _ = Command::new("takeown").creation_flags(CREATE_NO_WINDOW).args(&["/f", &path_str, "/r", "/d", "y"]).status();
    let _ = Command::new("icacls").creation_flags(CREATE_NO_WINDOW).args(&[&path_str, "/grant", "administrators:F", "/t", "/q"]).status();
}

// 解除占用并杀进程
fn unlock_resources(files: &[PathBuf]) -> bool {
    if files.is_empty() { return true; }
    unsafe {
        let mut session_handle = 0;
        let mut session_key = [0u16; 33];
        
        let res = RmStartSession(&mut session_handle, 0, session_key.as_mut_ptr());
        if res != ERROR_SUCCESS as u32 { return false; }
        let _guard = RmSessionGuard { handle: session_handle };

        let mut wide_paths: Vec<Vec<u16>> = files.iter().map(|p| {
            let mut v: Vec<u16> = p.as_os_str().encode_wide().collect();
            v.push(0); v
        }).collect();

        let pcwstr_paths: Vec<*const u16> = wide_paths.iter().map(|v| v.as_ptr()).collect();
        let res = RmRegisterResources(session_handle, pcwstr_paths.len() as u32, pcwstr_paths.as_ptr(), 0, std::ptr::null(), 0, std::ptr::null());
        if res != ERROR_SUCCESS as u32 { return false; }

        let mut proc_info_needed = 0;
        let mut proc_info = 0;
        let mut reboot_reasons = 0;
        let res = RmGetList(session_handle, &mut proc_info_needed, &mut proc_info, std::ptr::null_mut(), &mut reboot_reasons);
        if res != ERROR_SUCCESS as u32 && res != ERROR_MORE_DATA as u32 { return false; }
        if proc_info_needed == 0 { return true; }

        let mut process_info = vec![std::mem::zeroed::<RM_PROCESS_INFO>(); proc_info_needed as usize];
        proc_info = proc_info_needed;
        let res = RmGetList(session_handle, &mut proc_info_needed, &mut proc_info, process_info.as_mut_ptr(), &mut reboot_reasons);
        if res != ERROR_SUCCESS as u32 { return false; }

        println!("[2/3] 发现 {} 个占用进程，正在尝试终止...", proc_info);
        for info in process_info.iter().take(proc_info as usize) {
            let name = String::from_utf16_lossy(&info.strAppName);
            println!("  - 终止占用进程: {} (PID: {})", name.trim_matches('\0'), info.Process.dwProcessId);
        }

        let res = RmShutdown(session_handle, RmForceShutdown as u32, None);
        if res != ERROR_SUCCESS as u32 {
            for info in process_info.iter().take(proc_info as usize) {
                let h_process = OpenProcess(PROCESS_TERMINATE, 0, info.Process.dwProcessId);
                if h_process != 0 {
                    let _ = TerminateProcess(h_process, 0);
                    let _ = CloseHandle(h_process);
                }
            }
        }
    }
    true
}

// 执行安装逻辑
fn install_self(current_exe: &Path) {
    println!("=== 目录夺权工具-安装程序 ===");
    print!("是否将“强制删除”和“获取所有权”安装到系统右键菜单？(y/n): ");
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
    if input.trim().to_lowercase() != "y" {
        println!("安装已取消。");
        system_pause();
        return;
    }

    let target_dir = get_install_dir();
    let target_exe = target_dir.join(EXE_NAME);

    // 1. 创建目录并复制自身
    let _ = std::fs::create_dir_all(&target_dir);
    if let Err(e) = std::fs::copy(current_exe, &target_exe) {
        println!("复制文件失败（请确保以管理员身份运行）: {}", e);
        system_pause();
        return;
    }

    // 2. 写入右键菜单：强制删除
    let delete_cmd_str = format!("\"{}\" \"%1\"", target_exe.to_string_lossy());
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", "HKCR\\AllFilesystemObjects\\shell\\ForceDelete", "/ve", "/t", "REG_SZ", "/d", "强制删除", "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", "HKCR\\AllFilesystemObjects\\shell\\ForceDelete", "/v", "Icon", "/t", "REG_SZ", "/d", "shell32.dll,-240", "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", "HKCR\\AllFilesystemObjects\\shell\\ForceDelete", "/v", "HasLUAShield", "/t", "REG_SZ", "/d", "", "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", "HKCR\\AllFilesystemObjects\\shell\\ForceDelete\\command", "/ve", "/t", "REG_SZ", "/d", &delete_cmd_str, "/f"]).status();

    // 3. 写入右键菜单：获取所有权
    let own_cmd_str = format!("\"{}\" --take-ownership \"%1\"", target_exe.to_string_lossy());
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", "HKCR\\AllFilesystemObjects\\shell\\TakeOwnership", "/ve", "/t", "REG_SZ", "/d", "获取所有权", "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", "HKCR\\AllFilesystemObjects\\shell\\TakeOwnership", "/v", "Icon", "/t", "REG_SZ", "/d", "shell32.dll,-45", "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", "HKCR\\AllFilesystemObjects\\shell\\TakeOwnership", "/v", "HasLUAShield", "/t", "REG_SZ", "/d", "", "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", "HKCR\\AllFilesystemObjects\\shell\\TakeOwnership\\command", "/ve", "/t", "REG_SZ", "/d", &own_cmd_str, "/f"]).status();

    // 4. 写入控制面板卸载信息
    let uninstall_key = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\ForceDelete";
    let uninstall_cmd = format!("\"{}\" --uninstall", target_exe.to_string_lossy());
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", uninstall_key, "/v", "DisplayName", "/t", "REG_SZ", "/d", "强制删除与所有权工具", "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", uninstall_key, "/v", "UninstallString", "/t", "REG_SZ", "/d", &uninstall_cmd, "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", uninstall_key, "/v", "DisplayIcon", "/t", "REG_SZ", "/d", &target_exe.to_string_lossy(), "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", uninstall_key, "/v", "DisplayVersion", "/t", "REG_SZ", "/d", "1.0.0", "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", uninstall_key, "/v", "Publisher", "/t", "REG_SZ", "/d", "个人开发", "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", uninstall_key, "/v", "NoModify", "/t", "REG_DWORD", "/d", "1", "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["add", uninstall_key, "/v", "NoRepair", "/t", "REG_DWORD", "/d", "1", "/f"]).status();

    println!("\n安装成功！你现在可以右键任意目录，选择“获取所有权”或“强制删除”了。");
    system_pause();
}

// 执行卸载逻辑
fn uninstall_self() {
    println!("=== 正在卸载工具 ===");

    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["delete", "HKCR\\AllFilesystemObjects\\shell\\ForceDelete", "/f"]).status();
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["delete", "HKCR\\AllFilesystemObjects\\shell\\TakeOwnership", "/f"]).status();

    let uninstall_key = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\ForceDelete";
    let _ = Command::new("reg").creation_flags(CREATE_NO_WINDOW).args(&["delete", uninstall_key, "/f"]).status();

    println!("注册表已清理。正在注销程序文件并退出...");
    let install_dir = get_install_dir();
    let self_exe = install_dir.join(EXE_NAME);
    let self_exe_str = self_exe.to_string_lossy();
    let install_dir_str = install_dir.to_string_lossy();

    let _ = Command::new("cmd")
        .creation_flags(CREATE_NO_WINDOW)
        .args(&[
            "/c",
            &format!("ping 127.0.0.1 -n 2 > nul && del /f /q \"{}\" && rd /s /q \"{}\"", self_exe_str, install_dir_str)
        ])
        .spawn();
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let current_exe = env::current_exe().unwrap_or_default();

    // 场景 A：无参数运行
    if args.len() < 2 {
        let installed_exe = get_install_dir().join(EXE_NAME);
        if normalize_path(&current_exe) != normalize_path(&installed_exe) {
            install_self(&current_exe);
        } else {
            println!("强制删除与所有权工具已成功安装。");
            println!("右键点击任意目标即可使用。如需卸载，请前往 控制面板 -> 卸载程序。");
            system_pause();
        }
        return;
    }

    // 场景 B：执行卸载
    if args[1] == "--uninstall" {
        uninstall_self();
        return;
    }

    // 场景 C：只修改权限，不执行删除
    if args[1] == "--take-ownership" {
        if args.len() < 3 {
            println!("错误: 未提供目标路径。");
            system_pause();
            return;
        }
        let target_path = Path::new(&args[2]);
        if !target_path.exists() {
            println!("错误: 目标路径不存在。");
            system_pause();
            return;
        }

        if is_critical_path(target_path) {
            println!("【安全拦截】检测到目标路径属于 Windows 关键系统目录，已拦截“获取所有权”操作。");
            println!("警告：对 Windows 系统核心目录递归获取所有权，会导致微软商店、开始菜单等组件永久性损坏！");
            system_pause();
            return;
        }
        
        println!("[获取所有权] 正在处理: {}", target_path.to_string_lossy());
        grant_permissions(target_path);
        println!("所有权已获取，完全控制权限已授予！你现在可以直接双击进入该目录了。");
        system_pause();
        return;
    }

    // 场景 D：默认右键菜单调用 -> 强制删除
    let target_path = Path::new(&args[1]);
    if !target_path.exists() {
        println!("错误: 目标路径不存在。");
        system_pause();
        return;
    }

    if is_critical_path(target_path) {
        println!("【安全拦截】检测到目标路径属于 Windows 关键系统目录，已拒绝删除。");
        system_pause();
        return;
    }

    grant_permissions(target_path);

    let mut files_to_unlock = Vec::new();
    if target_path.is_dir() {
        for entry in WalkDir::new(target_path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                files_to_unlock.push(entry.into_path());
            }
        }
    } else {
        files_to_unlock.push(target_path.to_path_buf());
    }

    unlock_resources(&files_to_unlock);
    grant_permissions(target_path);

    println!("[3/3] 正在强制删除...");
    let delete_result = if target_path.is_dir() {
        std::fs::remove_dir_all(target_path)
    } else {
        std::fs::remove_file(target_path)
    };

    if delete_result.is_ok() {
        println!("删除成功。");
    } else {
        println!("警告: 部分文件可能未完全删除。");
        system_pause();
    }
}

fn system_pause() {
    let _ = Command::new("cmd").args(&["/c", "pause"]).status();
}