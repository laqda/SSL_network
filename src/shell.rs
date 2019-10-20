use crate::equipment::Equipment;
use crate::{payloads, network};
use crate::payloads::{Packet, PacketType};
use crate::errors::SSLNetworkError;
use shrust::{Shell, ShellIO, ExecResult};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::io;
use std::sync::{Arc, Mutex};
use std::io::{Write, BufReader, BufRead, BufWriter, stdout};

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

    drop(eq); // unlock eq

    println!("[INFO] Start listening {}", address);

    let stream = listener.accept();
    match stream {
        Ok(s) => {
            match server_handle_connection(s.0, ref_eq.clone()) {
                Err(e) => println!("{}", e),
                _ => {}
            }
        }
        Err(e) => println!("[ERROR] {}", e),
    };
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

    let packet: Packet = receive(&stream)?;
    match packet.packet_type {
        PacketType::CONNECT => {
            let payload: payloads::Connect = serde_json::from_str(packet.payload.as_str()).unwrap();
            // test exist
            if eq.get_network().is_verified(payload.pub_key.clone()) {
                println!("[INFO] Client is already certified");
                send(stream.try_clone().unwrap(), Packet::allowed(eq.get_name().clone(), eq.get_public_key().clone()))?;
            } else {
                println!("[INFO] Client is not already certified");
                let allow_client = allow_certify_new_equipment()?;
                if allow_client {
                    // add equipment
                    println!("[INFO] Add client to network");
                    eq.get_network().add_equipment(network::Equipment::new(payload.name.clone(), payload.pub_key.clone()));

                    // NEW_CERTIFICATE
                    let certificate = eq.certify(payload.name.clone(), payload.pub_key.clone());
                    let issuer_name = eq.get_name().clone();
                    let issuer_pub_key = eq.get_public_key().clone();
                    eq.get_network().add_certification(
                        payload.name.clone(),
                        payload.pub_key.clone(),
                        issuer_name,
                        issuer_pub_key,
                        certificate.0.to_pem().unwrap(),
                    );

                    println!("[INFO] Send back new certificate");
                    send(stream.try_clone().unwrap(), Packet::new_certificate(eq.get_name(), eq.get_public_key(), certificate.0.to_pem().unwrap()))?;
                } else {
                    send(stream.try_clone().unwrap(), Packet::refused())?;
                    return Err(SSLNetworkError::ConnectionRefused {});
                }
            }
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProcessViolation {});
        }
    };

    // IMPLICIT CONNECT FROM SERVER RESPONSE
    let packet = receive(&stream)?;

    match packet.packet_type {
        PacketType::CONNECTED => {
            println!("[INFO] Allowed to connect");
        }
        PacketType::NEW_CERTIFICATE => {
            let payload: payloads::NewCertificate = serde_json::from_str(packet.payload.as_str()).unwrap();
            println!("[INFO] New certificate from {}", stream.peer_addr().unwrap());
            let certificate = payload.certificate;
            let subject_name = eq.get_name().clone();
            let subject_pub_key = eq.get_public_key().clone();
            eq.get_network().add_certification(subject_name, subject_pub_key, payload.name, payload.pub_key.clone(), certificate);
            println!("[INFO] Allowed to connect");
        }
        PacketType::REFUSED => {
            return Err(SSLNetworkError::ConnectionRefused {});
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProcessViolation {});
        }
    };

    println!("[INFO] Connected");
    Ok(())
}

fn client_connection(stream: TcpStream, ref_eq: Arc<Mutex<Equipment>>) -> Result<(), SSLNetworkError> {
    let mut eq = ref_eq.lock().unwrap();

    // CONNECT
    send(stream.try_clone().unwrap(), Packet::connect(eq.get_name(), eq.get_public_key()))?;

    // CONNECT response
    let packet: Packet = receive(&stream)?;

    let name: String;
    let pub_key: Vec<u8>;

    match packet.packet_type {
        PacketType::ALLOWED => {
            let payload: payloads::Allowed = serde_json::from_str(packet.payload.as_str()).unwrap();
            name = payload.name.clone();
            pub_key = payload.pub_key.clone();
            println!("[INFO] Allowed to connect");
        }
        PacketType::NEW_CERTIFICATE => {
            let payload: payloads::NewCertificate = serde_json::from_str(packet.payload.as_str()).unwrap();
            name = payload.name.clone();
            pub_key = payload.pub_key.clone();
            println!("[INFO] New certificate from {}", stream.peer_addr().unwrap());
            let certificate = payload.certificate;
            let subject_name = eq.get_name().clone();
            let subject_pub_key = eq.get_public_key().clone();
            eq.get_network().add_certification(subject_name, subject_pub_key, payload.name.clone(), pub_key.clone(), certificate);
            println!("[INFO] Allowed to connect");
        }
        PacketType::REFUSED => {
            return Err(SSLNetworkError::ConnectionRefused {});
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProcessViolation {});
        }
    };

    if eq.get_network().is_verified(pub_key.clone()) {
        println!("[INFO] Server is already certified");
        send(stream.try_clone().unwrap(), Packet::connected())?;
    } else {
        println!("[INFO] Server is not already certified");
        let allow_server = allow_certify_new_equipment()?;
        if allow_server {
            // add equipment
            println!("[INFO] Add server to network");
            eq.get_network().add_equipment(network::Equipment::new(name.clone(), pub_key.clone()));

            // NEW_CERTIFICATE
            let certificate = eq.certify(name.clone(), pub_key.clone());
            let issuer_name = eq.get_name().clone();
            let issuer_pub_key = eq.get_public_key().clone();
            eq.get_network().add_certification(
                name.clone(),
                pub_key.clone(),
                issuer_name,
                issuer_pub_key,
                certificate.0.to_pem().unwrap(),
            );

            println!("[INFO] Send back new certificate");
            send(stream.try_clone().unwrap(), Packet::new_certificate(eq.get_name(), eq.get_public_key(), certificate.0.to_pem().unwrap()))?;
        } else {
            send(stream.try_clone().unwrap(), Packet::refused())?;
            return Err(SSLNetworkError::ConnectionRefused {});
        }
    }

    println!("[INFO] Connected");
    Ok(())
}

fn send(stream: TcpStream, packet: Packet) -> Result<(), SSLNetworkError> {
    let packet = serde_json::to_string(&packet).unwrap() + "\n";
    let mut writer = BufWriter::new(&stream);
    match writer.write_all(packet.as_bytes()) {
        Err(_) => {
            return Err(SSLNetworkError::NoConnection {});
        }
        _ => {}
    };
    match writer.flush() {
        Err(_) => {
            return Err(SSLNetworkError::NoConnection {});
        }
        _ => {}
    }
    Ok(())
}

fn receive(stream: &TcpStream) -> Result<Packet, SSLNetworkError> {
    let mut reader = BufReader::new(stream);
    let mut packet = String::new();
    match reader.read_line(&mut packet) {
        Err(_) => {
            return Err(SSLNetworkError::NoConnection {});
        }
        _ => {}
    };
    let packet: Packet = match serde_json::from_str(packet.as_str()) {
        Ok(p) => p,
        Err(_) => {
            return Err(SSLNetworkError::NoConnection {});
        }
    };
    Ok(packet)
}

fn allow_certify_new_equipment() -> Result<bool, SSLNetworkError> {
    print!("Add new equipment to network (y/N) ? ");
    match stdout().flush() {
        Err(_) => {
            return Err(SSLNetworkError::NoConnection {});
        }
        _ => {}
    }
    let mut response = String::new();
    match io::stdin().read_line(&mut response) {
        Err(_) => {
            return Err(SSLNetworkError::NoConnection {});
        }
        _ => {}
    }
    let response = response.trim();
    Ok(response == "y")
}