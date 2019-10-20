use crate::equipment::Equipment;
use crate::payloads;
use crate::errors::SSLNetworkError;
use shrust::{Shell, ShellIO, ExecResult};
use std::net::{SocketAddr, TcpListener, IpAddr, TcpStream};
use std::{thread, io};
use std::sync::{Arc, Mutex};
use failure::_core::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::io::{Write, Read};

pub struct EquipmentShell(pub Shell<Arc<Mutex<Equipment>>>);

impl EquipmentShell {
    pub fn new(eq: Equipment) -> EquipmentShell {
        let mut shell = Shell::new(Arc::new(Mutex::new(eq)));
        shell.new_command("infos", "Display equipment infos", 0, infos);
        shell.new_command("clear", "Clear shell", 0, clear);
        shell.new_command("listen", "Start a connection as server", 0, listen);
        shell.new_command("connect", "Start a connection as client (ex: connect 127.0.0.1:3202)", 1, connect);
        EquipmentShell(shell)
    }
}

fn infos(_io: &mut ShellIO, ref_eq: &mut std::sync::Arc<std::sync::Mutex<Equipment>>, _args: &[&str]) -> ExecResult {
    let eq = ref_eq.lock().unwrap();
    println!("\n{}", eq);
    Ok(())
}

fn clear(_io: &mut ShellIO, _ref_eq: &mut std::sync::Arc<std::sync::Mutex<Equipment>>, _args: &[&str]) -> ExecResult {
    print!("\x1B[2J");
    Ok(())
}

fn listen(_io: &mut ShellIO, ref_eq: &mut std::sync::Arc<std::sync::Mutex<Equipment>>, _args: &[&str]) -> ExecResult {
    let eq = ref_eq.lock().unwrap();

    let address = eq.get_socket_address();
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true).expect("Cannot set non-blocking");

    let stop = Arc::new(AtomicBool::new(false)); // stop signal from stdin

    drop(eq); // unlock eq

    println!("[INFO] Start listening {}", address);
    let ref_eq_thread = ref_eq.clone();
    let stop_thread = stop.clone();

    thread::spawn(move || { // spawn a new thread to be able to read stdin in the same time
        for stream in listener.incoming() {
            match stream {
                Ok(mut s) => {
                    server_handle_connection(&mut s, ref_eq_thread.clone());
//                    println!("Press [ENTER] to continue");
//                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if stop_thread.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => println!("[ERROR] {}", e),
            };
        }
        drop(listener);
    });

    match io::stdin().read_line(&mut String::new()) {
        Ok(_) => {
            stop.store(true, Ordering::Relaxed);
        }
        Err(error) => println!("error: {}", error),
    }

    Ok(())
}

fn connect(_io: &mut ShellIO, ref_eq: &mut std::sync::Arc<std::sync::Mutex<Equipment>>, args: &[&str]) -> ExecResult {
    let eq = ref_eq.lock().unwrap();

    let socket: SocketAddr = match args[0].parse() {
        Ok(s) => s,
        Err(_) => {
            println!("{}", SSLNetworkError::InvalidAddress { address: args[0].to_string() });
            return Ok(());
        }
    };
    let mut stream = match TcpStream::connect(socket) {
        Ok(s) => s,
        Err(e) => {
            println!("[ERROR] {}", e);
            return Ok(());
        }
    };

    drop(eq);
    client_connection(&mut stream, ref_eq.clone());
    Ok(())
}

fn server_handle_connection(stream: &mut TcpStream, ref_eq: Arc<Mutex<Equipment>>) {
    let eq = ref_eq.lock().unwrap();

    let mut res = vec![];
    while let Err(err) = stream.read_to_end(&mut res) {
        if err.kind() != io::ErrorKind::WouldBlock {
            panic!("stream error: {:?}", err);
        }
    }

    println!("receive connection and access equipment {}", eq.get_socket_address());
    println!("{}", String::from_utf8_lossy(&res));
}

fn client_connection(stream: &mut TcpStream, ref_eq: Arc<Mutex<Equipment>>) {
    let eq = ref_eq.lock().unwrap();
    send(stream, serde_json::to_string(&payloads::Connect { name: eq.to_string(), pub_key: eq.get_public_key_pem() }).unwrap());
}

fn send(stream: &mut TcpStream, payload: String) {
    while let Err(err) = stream.write_all(payload.clone().as_bytes()) {
        if err.kind() != io::ErrorKind::WouldBlock {
            panic!("error: {:?}", err);
        }
    }
    stream.flush().unwrap();
}