use crate::equipment::Equipment;
use crate::{payloads, network};
use crate::payloads::{Packet, PacketType};
use crate::errors::SSLNetworkError;
use shrust::{Shell, ShellIO, ExecResult};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::{thread, io};
use std::sync::{Arc, Mutex};
use failure::_core::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::io::{Write, BufReader, BufRead, BufWriter, stdin, stdout};

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
                Ok(s) => {
                    match server_handle_connection(s, ref_eq_thread.clone()) {
                        Err(e) => println!("{}", e),
                        _ => {}
                    }
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
    let stream = match TcpStream::connect(socket) {
        Ok(s) => s,
        Err(e) => {
            println!("[ERROR] {}", e);
            return Ok(());
        }
    };

    drop(eq);
    match client_connection(stream, ref_eq.clone()) {
        Err(e) => println!("{}", e),
        _ => {}
    }
    Ok(())
}

fn server_handle_connection(stream: TcpStream, ref_eq: Arc<Mutex<Equipment>>) -> Result<(), SSLNetworkError> {
    let mut eq = ref_eq.lock().unwrap();

    let packet: Packet = serde_json::from_str(receive(&stream).as_str()).unwrap();
    match packet.packet_type {
        PacketType::CONNECT => {
            let payload: payloads::Connect = serde_json::from_str(packet.payload.as_str()).unwrap();
            // test exist
            if eq.get_network().contains(&payload.pub_key) {
                send(stream.try_clone().unwrap(), Packet::allowed(eq.get_name().clone(), eq.get_public_key().clone()));
            } else {
                if allow_certify_new_equipment() {
                    // add equipment
                    eq.get_network().add_equipment(network::Equipment::new(payload.name.clone(), payload.pub_key.clone()));

                    // NEW_CERTIFICATE
                    let certificate = eq.certify(payload.name, payload.pub_key.clone());
                    let issuer_pub_key = eq.get_public_key().clone();
                    eq.get_network().add_certification(
                        payload.pub_key.clone(),
                        issuer_pub_key,
                        certificate.0.to_pem().unwrap()
                    );

                    send(stream.try_clone().unwrap(), Packet::new_certificate(eq.get_name(), eq.get_public_key(), certificate.0.to_pem().unwrap()));
                } else {
                    send(stream.try_clone().unwrap(), Packet::refused());
                }
            }
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProcessViolation {});
        }
    };

    Ok(())
}

fn client_connection(stream: TcpStream, ref_eq: Arc<Mutex<Equipment>>) -> Result<(), SSLNetworkError> {
    let eq = ref_eq.lock().unwrap();

    // CONNECT
    send(stream.try_clone().unwrap(), Packet::connect(eq.get_name(), eq.get_public_key()));

    // CONNECT response
    let packet: Packet = serde_json::from_str(receive(&stream).as_str()).unwrap();
    match packet.packet_type {
        PacketType::ALLOWED => {
            println!("[INFO] Allowed to connect");
        }
        PacketType::NEW_CERTIFICATE => {
            let payload: payloads::NewCertificate = serde_json::from_str(packet.payload.as_str()).unwrap();
            println!("[INFO] New certificate from {}", stream.peer_addr().unwrap());
            println!("[INFO] Allowed to connect");
        }
        PacketType::REFUSED => {
            return Err(SSLNetworkError::ConnectionRefused {});
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProcessViolation {});
        }
    };

    Ok(())
}

fn send(stream: TcpStream, packet: Packet) {
    let packet = serde_json::to_string(&packet).unwrap() + "\n";
    let mut writer = BufWriter::new(&stream);
    writer.write_all(packet.as_bytes()).unwrap();
    writer.flush().unwrap();
    println!("[INFO] Packet send to {} as {}", stream.peer_addr().unwrap(), stream.local_addr().unwrap());
}

fn receive(stream: &TcpStream) -> String {
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();
    println!("[INFO] Packet receive from {} : {}", stream.peer_addr().unwrap(), response.clone());
    response
}

fn allow_certify_new_equipment() -> bool {
    print!("Add new equipment to network (y/N) ? ");
//    stdout().flush();
    let mut reader = BufReader::new(stdin());
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();
    println!("response {}", response);
    response.trim() == "y"
}