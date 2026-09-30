use std::env;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;
use std::os::windows::process::CommandExt;
use std::os::windows::ffi::OsStrExt;
use walkdir::WalkDir;

use windows_sys::Win32::System::RestartManager::{
    RmStartSession, RmRegisterResources, RmGetList, RmShutdown, RmEndSession,
    RmForceShutdown, RM_PROCESS_INFO
};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, ERROR_MORE_DATA, ERROR_INVALID_PARAMETER, WAIT_OBJECT_0, CloseHandle, GetLastError};
use windows_sys::Win32::System::Console::SetConsoleOutputCP;
use windows_sys::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, QueryFullProcessImageNameW,
    PROCESS_TERMINATE, PROCESS_QUERY_LIMITED_INFORMATION,
};

const CREATE_NO_WINDOW: u32 = 0x08000000;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
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
    // takeown/icacls 只认反斜杠，正斜杠路径会报"找不到文件"
    let path_str = path.to_string_lossy().replace('/', "\\");
    let _ = Command::new("takeown").creation_flags(CREATE_NO_WINDOW)
        .args(&["/f", &path_str, "/r", "/d", "y"])
        .stdout(Stdio::null()).stderr(Stdio::null()).status();
    let _ = Command::new("icacls").creation_flags(CREATE_NO_WINDOW)
        .args(&[&path_str, "/grant", "administrators:F", "/t", "/q"])
        .stdout(Stdio::null()).stderr(Stdio::null()).status();
}

// 收集需要解除占用的文件列表。
// 注意：不能把目录注册进 Restart Manager —— 实测注册目录会让 RmGetList 整体返回
// ERROR_ACCESS_DENIED(5)，连带所有文件都查不到占用者。
fn collect_unlock_targets(target_path: &Path) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    if target_path.is_dir() {
        for entry in WalkDir::new(target_path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                targets.push(entry.into_path());
            }
        }
    } else {
        targets.push(target_path.to_path_buf());
    }
    targets
}

// 获取进程可执行文件路径（失败返回空串）
fn process_image_path(pid: u32) -> String {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h == 0 { return String::new(); }
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(h);
        if ok == 0 { String::new() } else { String::from_utf16_lossy(&buf[..size as usize]) }
    }
}

// 系统关键进程不能杀，杀了直接蓝屏/登不出
fn is_critical_process(exe_path: &str, pid: u32) -> bool {
    if pid == 0 || pid == 4 || pid == std::process::id() { return true; }
    let name = exe_path.rsplit('\\').next().unwrap_or("").to_lowercase();
    matches!(name.as_str(),
        "csrss.exe" | "smss.exe" | "wininit.exe" | "winlogon.exe" | "lsass.exe" | "services.exe")
}

// 强制终止进程并等它真正退出（最多 5 秒）。返回结果描述。
fn terminate_and_wait(pid: u32) -> String {
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE_ACCESS, 0, pid);
        if h == 0 {
            return if GetLastError() == ERROR_INVALID_PARAMETER {
                "进程已退出".to_string()
            } else {
                "权限不足，无法终止".to_string()
            };
        }
        if TerminateProcess(h, 1) == 0 {
            let err = GetLastError();
            // RmShutdown 可能已抢先杀掉：快速探一下句柄是否已 signaled
            if WaitForSingleObject(h, 500) == WAIT_OBJECT_0 {
                CloseHandle(h);
                return "进程已退出".to_string();
            }
            CloseHandle(h);
            return format!("终止失败 (错误码 {})", err);
        }
        let _ = WaitForSingleObject(h, 5000);
        CloseHandle(h);
        "已终止".to_string()
    }
}

// 单轮：查询占用进程 -> 尽力 RmShutdown -> 逐个击杀。返回本轮查到的占用进程数
fn find_and_kill_lockers(files: &[PathBuf], round: u32) -> Result<u32, ()> {
    unsafe {
        let mut session_handle = 0;
        let mut session_key = [0u16; 33];

        let res = RmStartSession(&mut session_handle, 0, session_key.as_mut_ptr());
        if res != ERROR_SUCCESS as u32 {
            eprintln!("[占用查询] 启动 Restart Manager 会话失败 (错误码 {})", res);
            return Err(());
        }
        let _guard = RmSessionGuard { handle: session_handle };

        let wide_paths: Vec<Vec<u16>> = files.iter().map(|p| {
            let mut v: Vec<u16> = p.as_os_str().encode_wide().collect();
            v.push(0); v
        }).collect();

        let pcwstr_paths: Vec<*const u16> = wide_paths.iter().map(|v| v.as_ptr()).collect();
        let res = RmRegisterResources(session_handle, pcwstr_paths.len() as u32, pcwstr_paths.as_ptr(), 0, std::ptr::null(), 0, std::ptr::null());
        if res != ERROR_SUCCESS as u32 {
            eprintln!("[占用查询] 注册待查文件失败 (错误码 {}, 文件数 {})", res, pcwstr_paths.len());
            return Err(());
        }

        let mut proc_info_needed = 0;
        let mut proc_info = 0;
        let mut reboot_reasons = 0;
        let res = RmGetList(session_handle, &mut proc_info_needed, &mut proc_info, std::ptr::null_mut(), &mut reboot_reasons);
        if res != ERROR_SUCCESS as u32 && res != ERROR_MORE_DATA as u32 {
            eprintln!("[占用查询] 查询占用进程失败 (错误码 {})", res);
            return Err(());
        }
        if proc_info_needed == 0 {
            if round == 1 { println!("[2/3] 未发现占用进程。"); }
            return Ok(0);
        }

        let mut process_info = vec![std::mem::zeroed::<RM_PROCESS_INFO>(); proc_info_needed as usize];
        proc_info = proc_info_needed;
        let res = RmGetList(session_handle, &mut proc_info_needed, &mut proc_info, process_info.as_mut_ptr(), &mut reboot_reasons);
        if res != ERROR_SUCCESS as u32 { return Err(()); }

        let count = proc_info;
        if round == 1 {
            println!("[2/3] 发现 {} 个占用进程，正在终止...", count);
        } else {
            println!("  仍有 {} 个占用进程，继续终止...", count);
        }

        // 先请求系统级关闭（对部分应用更干净），失败无所谓，下面硬杀兜底
        let _ = RmShutdown(session_handle, RmForceShutdown as u32, None);

        for info in process_info.iter().take(count as usize) {
            let pid = info.Process.dwProcessId;
            let app_name = String::from_utf16_lossy(&info.strAppName).trim_matches('\0').to_string();
            let exe = process_image_path(pid);
            if is_critical_process(&exe, pid) {
                println!("  - 跳过系统关键进程: {} (PID {})", app_name, pid);
                continue;
            }
            let label = if exe.is_empty() { app_name } else { exe };
            let outcome = terminate_and_wait(pid);
            println!("  - {}: {} (PID {})", outcome, label, pid);
        }
        Ok(count)
    }
}

// 解除占用：循环“查占用 -> 杀 -> 再查”直到文件不再被占用；返回是否已解锁
fn unlock_resources(files: &[PathBuf]) -> bool {
    if files.is_empty() { return true; }
    for round in 1..=4 {
        match find_and_kill_lockers(files, round) {
            Ok(0) => return true,
            Ok(_) if round < 4 => sleep(Duration::from_millis(400)),
            Ok(_) => {}
            Err(()) => return false,
        }
    }
    false
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
    // 控制台默认 GBK，而 Rust println 输出 UTF-8，不设置会全乱码
    unsafe { SetConsoleOutputCP(65001); }

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

    println!("[1/3] 正在夺取文件权限...");
    grant_permissions(target_path);

    let mut files_to_unlock = collect_unlock_targets(target_path);

    // 循环：查占用 -> 杀进程 -> 尝试删除 -> 失败再查再杀，最多 5 轮
    let mut delete_result = None;
    for round in 1..=5 {
        if round > 1 {
            println!("[重试 {}/5] 删除未完成，重新查找占用进程...", round);
            if !target_path.exists() { break; }
            files_to_unlock = collect_unlock_targets(target_path);
        }

        unlock_resources(&files_to_unlock);
        grant_permissions(target_path);

        println!("[3/3] 正在强制删除...");
        let result = if target_path.is_dir() {
            std::fs::remove_dir_all(target_path)
        } else {
            std::fs::remove_file(target_path)
        };

        match result {
            Ok(()) => { delete_result = Some(()); break; }
            Err(e) => {
                if !target_path.exists() {
                    delete_result = Some(());
                    break;
                }
                println!("  删除失败: {}", e);
                delete_result = None;
                sleep(Duration::from_millis(300));
            }
        }
    }

    if delete_result.is_some() {
        println!("删除成功。");
    } else {
        println!("警告: 删除失败。可能仍有进程占用，或剩余文件为只读/系统保护文件。");
        system_pause();
    }
}

fn system_pause() {
    let _ = Command::new("cmd").args(&["/c", "pause"]).status();
}