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

fn server_handle_connection(mut stream: TcpStream, ref_eq: Arc<Mutex<Equipment>>) -> Result<(), SSLNetworkError> {
    let mut eq = ref_eq.lock().unwrap();

    let packet: Packet = receive(&stream)?;
    match packet.packet_type {
        PacketType::CONNECT => {
            let payload: payloads::Connect = serde_json::from_str(packet.payload.as_str()).unwrap();
            try_to_connect(&mut stream, &mut eq, payload.name, payload.pub_key, PacketType::ALLOWED)?;
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProcessViolation {});
        }
    };

    // IMPLICIT CONNECT FROM SERVER RESPONSE
    let packet = receive(&stream)?;

    match packet.packet_type {
        PacketType::CONNECTED => {
            receive_connected();
        }
        PacketType::NEW_CERTIFICATE => {
            let payload: payloads::NewCertificate = serde_json::from_str(packet.payload.as_str()).unwrap();
            receive_new_certificate(payload, &mut eq);
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

fn client_connection(mut stream: TcpStream, ref_eq: Arc<Mutex<Equipment>>) -> Result<(), SSLNetworkError> {
    let mut eq = ref_eq.lock().unwrap();

    // CONNECT
    send(stream.try_clone().unwrap(), Packet::connect(eq.get_name(), eq.get_public_key()))?;

    // CONNECT response
    let packet: Packet = receive(&stream)?;

    // save name and pub_key to allow verify then later
    let name: String;
    let pub_key: Vec<u8>;

    match packet.packet_type {
        PacketType::ALLOWED => {
            let payload: payloads::Allowed = serde_json::from_str(packet.payload.as_str()).unwrap();
            name = payload.name.clone();
            pub_key = payload.pub_key.clone();
            receive_allowed();
        }
        PacketType::NEW_CERTIFICATE => {
            let payload: payloads::NewCertificate = serde_json::from_str(packet.payload.as_str()).unwrap();
            name = payload.name.clone();
            pub_key = payload.pub_key.clone();
            // stream.peer_addr().unwrap().to_string()
            receive_new_certificate(payload, &mut eq);
        }
        PacketType::REFUSED => {
            return Err(SSLNetworkError::ConnectionRefused {});
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProcessViolation {});
        }
    };

    try_to_connect(&mut stream, &mut eq, name, pub_key, PacketType::CONNECTED)?;

    println!("[INFO] Connected");
    Ok(())
}

// actions

fn receive_allowed() {
    println!("[INFO] Allowed to connect");
}

fn receive_new_certificate(payload: payloads::NewCertificate, eq: &mut Equipment) {
    println!("[INFO] New certificate");
    let certificate = payload.certificate;
    let subject_name = eq.get_name().clone();
    let subject_pub_key = eq.get_public_key().clone();
    eq.get_network().add_certification(subject_name, subject_pub_key, payload.name, payload.pub_key, certificate);
    println!("[INFO] Allowed to connect");
}

fn receive_connected() {
    println!("[INFO] Allowed to connect");
}

fn try_to_connect(stream: &mut TcpStream, eq: &mut Equipment, name: String, pub_key: Vec<u8>, packet_type_to_return_if_already_certified: PacketType) -> Result<(), SSLNetworkError> {
    if eq.get_network().is_verified(pub_key.clone()) {
        println!("[INFO] Distant equipment is already certified");
        match packet_type_to_return_if_already_certified {
            PacketType::ALLOWED => { send(stream.try_clone().unwrap(), Packet::allowed(eq.get_name().clone(), eq.get_public_key().clone()))?; }
            PacketType::CONNECTED => { send(stream.try_clone().unwrap(), Packet::connected())?; }
            _ => { return Err(SSLNetworkError::ConnectionProcessViolation {}); }
        }
    } else {
        println!("[INFO] Distant equipment is not already certified");
        if allow_certify_new_equipment()? {
            println!("[INFO] Add distant equipment to network");
            eq.get_network().add_equipment(network::Equipment::new(name.clone(), pub_key.clone()));
            // generate new certificate
            let certificate = eq.certify(name.clone(), pub_key.clone());
            let issuer_name = eq.get_name().clone();
            let issuer_pub_key = eq.get_public_key().clone();
            eq.get_network().add_certification(
                name,
                pub_key,
                issuer_name,
                issuer_pub_key,
                certificate.0.to_pem().unwrap(),
            );

            println!("[INFO] Send back new certificate to distant equipment");
            send(stream.try_clone().unwrap(), Packet::new_certificate(eq.get_name(), eq.get_public_key(), certificate.0.to_pem().unwrap()))?;
        } else {
            send(stream.try_clone().unwrap(), Packet::refused())?;
            return Err(SSLNetworkError::ConnectionRefused {});
        }
    }
    Ok(())
}

// tools

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