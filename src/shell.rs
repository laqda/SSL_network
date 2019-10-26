use crate::equipment::SimulatedEquipment;
use crate::payloads::{ConnectionPacket, ConnectionPacketTypes, Nonce, gen_nonce};
use crate::errors::{SSLNetworkError, ResultSSL};
use shrust::{Shell, ShellIO, ExecResult};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::io;
use std::sync::{Arc, Mutex};
use std::io::{Write, BufReader, BufRead, BufWriter, stdout};
use std::hash::Hash;
use std::collections::hash_map::DefaultHasher;
use crate::network::Network;
use crate::certification::{Equipment, CertificationChain};

pub struct EquipmentShell(pub Shell<Arc<Mutex<SimulatedEquipment>>>);

impl EquipmentShell {
    pub fn new(eq: SimulatedEquipment) -> EquipmentShell {
        let mut shell = Shell::new(Arc::new(Mutex::new(eq)));
        shell.new_command("infos", "Display equipment infos", 0, infos);
        shell.new_command("clear", "Clear shell", 0, clear);
        shell.new_command("certified", "Display certified equipments", 0, certified);
        shell.new_command("listen", "Start a connection as server", 0, listen);
        shell.new_command("connect", "Start a connection as client (ex: connect 127.0.0.1:3202)", 1, connect);
        EquipmentShell(shell)
    }
}

fn infos(_io: &mut ShellIO, ref_eq: &mut std::sync::Arc<std::sync::Mutex<SimulatedEquipment>>, _args: &[&str]) -> ExecResult {
    let eq = ref_eq.lock().unwrap();
    println!("\n{}", eq);
    Ok(())
}

fn clear(_io: &mut ShellIO, _ref_eq: &mut std::sync::Arc<std::sync::Mutex<SimulatedEquipment>>, _args: &[&str]) -> ExecResult {
    print!("\x1B[2J");
    Ok(())
}

fn certified(_io: &mut ShellIO, ref_eq: &mut std::sync::Arc<std::sync::Mutex<SimulatedEquipment>>, _args: &[&str]) -> ExecResult {
    let mut eq = ref_eq.lock().unwrap();
    let chains = eq.get_network().get_chains_certifications().unwrap();
    for chain in chains {
        println!("{}", chain);
    }
    Ok(())
}

fn listen(_io: &mut ShellIO, ref_eq: &mut std::sync::Arc<std::sync::Mutex<SimulatedEquipment>>, _args: &[&str]) -> ExecResult {
    let eq = ref_eq.lock().unwrap();

    let address = eq.get_socket_address();
    let listener = TcpListener::bind(address)?;

    drop(eq); // unlock eq

    println!("[INFO] Start listening {}", address);

    let stream = listener.accept();
    match stream {
        Ok(s) => {
            match connection_server(s.0, ref_eq.clone()) {
                Err(e) => println!("{}", e),
                _ => {}
            }
        }
        Err(e) => println!("[ERROR] {}", e),
    };
    Ok(())
}

fn connect(_io: &mut ShellIO, ref_eq: &mut std::sync::Arc<std::sync::Mutex<SimulatedEquipment>>, args: &[&str]) -> ExecResult {
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
    match connection_client(stream, ref_eq.clone()) {
        Err(e) => println!("{}", e),
        _ => {}
    }
    Ok(())
}

// Inter-connections

#[derive(Hash)]
struct ConnectionIdentifier {
    client_nonce: Nonce,
    server_nonce: Nonce,
}

// CONNECTION

fn connection_server(stream: TcpStream, ref_eq: Arc<Mutex<SimulatedEquipment>>) -> ResultSSL<()> {
    let mut eq = ref_eq.lock().unwrap();
    let local_addr = stream.local_addr().unwrap().to_string();
    let peer_addr = stream.peer_addr().unwrap().to_string();

    let eq_name = eq.get_name();
    let eq_pub_key = eq.get_public_key().clone();
    let eq_pri_key = eq.get_private_key().clone();

    let peer_name;
    let peer_pub_key;
    let peer_nonce: Nonce;

    let packet = connection_receive(&stream)?;
    let payload = packet.get_payload()?;
    match payload {
        ConnectionPacketTypes::DISCOVER_SYN { name, pub_key, nonce } => {
            println!("[INFO] DISCOVER from {} as {}", peer_addr, local_addr);
            peer_name = name.clone();
            peer_pub_key = pub_key.clone();
            peer_nonce = nonce.clone();
        }
        ConnectionPacketTypes::REFUSED => {
            return Err(SSLNetworkError::ConnectionRefused {});
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProtocolViolation {});
        }
    }

    let local_nonce: Nonce = gen_nonce();

    let packet = ConnectionPacket::generate_discover_syn_ack(&eq_name, &eq_pub_key, local_nonce);
    let packet = packet.sign(&local_nonce, &peer_nonce, &eq_pri_key);
    connection_send(&stream, packet)?;

    let packet = connection_receive(&stream)?;
    packet.verify(&local_nonce, &peer_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        ConnectionPacketTypes::DISCOVER_ACK => {}
        ConnectionPacketTypes::REFUSED => {
            return Err(SSLNetworkError::ConnectionRefused {});
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProtocolViolation {});
        }
    }

    let should_generate_new_certificate = match eq.get_network().is_equipment_certified(&Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() })? { // test if peer belongs to local knowledge
        true => {
            println!("[INFO] Peer equipment is already certified");
            false
        }
        false => {
            let connection_identifier = ConnectionIdentifier { client_nonce: peer_nonce.clone(), server_nonce: local_nonce.clone() };
            println!("[INFO] Connection identifier : {:#?}", connection_identifier.hash(&mut DefaultHasher::new()));
            if !allow_certify_new_equipment()? { // ask user to validate connection
                let packet = ConnectionPacket::generate_refused();
                let packet = packet.sign(&local_nonce, &peer_nonce, &eq_pri_key);
                connection_send(&stream, packet)?;
                return Err(SSLNetworkError::ConnectionRefused {});
            }
            true
        }
    };

    let generated_new_certificate = match should_generate_new_certificate {
        true => Some(eq.certify(&Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() })),
        false => None,
    };

    let knowledge = eq.get_network().get_chains_certifications()?.clone();
    let packet = ConnectionPacket::generate_allowed_syn(generated_new_certificate.clone(), &knowledge);
    let packet = packet.sign(&local_nonce, &peer_nonce, &eq_pri_key);
    connection_send(&stream, packet)?;

    let received_new_certificate;

    let packet = connection_receive(&stream)?;
    packet.verify(&local_nonce, &peer_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        ConnectionPacketTypes::ALLOWED_SYN_ACK { new_certificate, knowledge } => {
            received_new_certificate = new_certificate;
            let verified_knowledge = verify_chains(knowledge, Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() });
            eq.get_network().add_chains_certifications(verified_knowledge)?;
        }
        ConnectionPacketTypes::REFUSED => {
            return Err(SSLNetworkError::ConnectionRefused {});
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProtocolViolation {});
        }
    }

    println!("[INFO] Connection allowed by peer");

    let packet = ConnectionPacket::generate_allowed_ack();
    let packet = packet.sign(&local_nonce, &peer_nonce, &eq_pri_key);
    connection_send(&stream, packet)?;

    if let Some(certificate) = generated_new_certificate {
        println!("[INFO] Save new certificate generated for peer");
        eq.get_network().add_certificate(&certificate)?;
    }

    if let Some(certificate) = received_new_certificate {
        println!("[INFO] Save new certificate generated by peer");
        eq.get_network().add_certificate(&certificate)?;
    }

    println!("[INFO] Connection successful");

    Ok(())
}

fn connection_client(stream: TcpStream, ref_eq: Arc<Mutex<SimulatedEquipment>>) -> ResultSSL<()> {
    let mut eq = ref_eq.lock().unwrap();
    let local_addr = stream.local_addr().unwrap().to_string();
    let peer_addr = stream.peer_addr().unwrap().to_string();

    let eq_name = eq.get_name();
    let eq_pub_key = eq.get_public_key().clone();
    let eq_pri_key = eq.get_private_key().clone();

    let peer_name;
    let peer_pub_key;
    let peer_nonce: Nonce;

    let local_nonce: Nonce = gen_nonce();

    let packet = ConnectionPacket::generate_discover_syn(eq_name.clone(), &eq_pub_key, local_nonce.clone());
    connection_send(&stream, packet)?;

    let packet = connection_receive(&stream)?;
    let payload = packet.get_payload()?;
    match payload {
        ConnectionPacketTypes::DISCOVER_SYN_ACK { name, pub_key, nonce } => {
            println!("[INFO] DISCOVER from {} as {}", peer_addr, local_addr);
            peer_name = name.clone();
            peer_pub_key = pub_key.clone();
            peer_nonce = nonce.clone();
        }
        ConnectionPacketTypes::REFUSED => {
            return Err(SSLNetworkError::ConnectionRefused {});
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProtocolViolation {});
        }
    }

    let packet = ConnectionPacket::generate_discover_ack();
    let packet = packet.sign(&peer_nonce, &local_nonce, &eq_pri_key);
    connection_send(&stream, packet)?;

    let received_new_certificate;

    let packet = connection_receive(&stream)?;
    packet.verify(&peer_nonce, &local_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        ConnectionPacketTypes::ALLOWED_SYN { new_certificate, knowledge } => {
            received_new_certificate = new_certificate;
            let verified_knowledge = verify_chains(knowledge, Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() });
            eq.get_network().add_chains_certifications(verified_knowledge)?;
        }
        ConnectionPacketTypes::REFUSED => {
            return Err(SSLNetworkError::ConnectionRefused {});
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProtocolViolation {});
        }
    }

    let should_generate_new_certificate = match eq.get_network().is_equipment_certified(&Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() })? { // test if peer belongs to local knowledge
        true => {
            println!("[INFO] Peer equipment is already certified");
            false
        }
        false => {
            let connection_identifier = ConnectionIdentifier { client_nonce: peer_nonce.clone(), server_nonce: local_nonce.clone() };
            println!("[INFO] Connection identifier : {:#?}", connection_identifier.hash(&mut DefaultHasher::new()));
            if !allow_certify_new_equipment()? { // ask user to validate connection
                let packet = ConnectionPacket::generate_refused();
                let packet = packet.sign(&peer_nonce, &local_nonce, &eq_pri_key);
                connection_send(&stream, packet)?;
                return Err(SSLNetworkError::ConnectionRefused {});
            }
            true
        }
    };

    let generated_new_certificate = match should_generate_new_certificate {
        true => Some(eq.certify(&Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() })),
        false => None,
    };

    let knowledge = eq.get_network().get_chains_certifications()?.clone();
    let packet = ConnectionPacket::generate_allowed_syn_ack(generated_new_certificate.clone(), &knowledge);
    let packet = packet.sign(&peer_nonce, &local_nonce, &eq_pri_key);
    connection_send(&stream, packet)?;

    let packet = connection_receive(&stream)?;
    packet.verify(&peer_nonce, &local_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        ConnectionPacketTypes::ALLOWED_ACK => {}
        ConnectionPacketTypes::REFUSED => {
            return Err(SSLNetworkError::ConnectionRefused {});
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProtocolViolation {});
        }
    }

    println!("[INFO] Connection allowed by peer");

    let packet = ConnectionPacket::generate_allowed_ack();
    let packet = packet.sign(&peer_nonce, &local_nonce, &eq_pri_key);
    connection_send(&stream, packet)?;

    if let Some(certificate) = generated_new_certificate {
        println!("[INFO] Save new certificate generated for peer");
        eq.get_network().add_certificate(&certificate)?;
    }

    if let Some(certificate) = received_new_certificate {
        println!("[INFO] Save new certificate generated by peer");
        eq.get_network().add_certificate(&certificate)?;
    }

    println!("[INFO] Connection successful");

    Ok(())
}

fn connection_send(stream: &TcpStream, packet: ConnectionPacket) -> ResultSSL<()> {
    let packet = serde_json::to_string(&packet).unwrap();
    send(stream, packet)
}

fn connection_receive(stream: &TcpStream) -> ResultSSL<ConnectionPacket> {
    let packet = receive(stream)?;
    let packet = serde_json::from_str(packet.as_str()).map_err(|_| SSLNetworkError::InvalidPayload {}).unwrap();
    Ok(packet)
}

// tools

fn send(stream: &TcpStream, packet: String) -> ResultSSL<()> {
    let packet = packet + "\n"; // end of line <-> end of sending data
    let mut writer = BufWriter::new(stream);
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

fn receive(stream: &TcpStream) -> ResultSSL<String> {
    let mut reader = BufReader::new(stream);
    let mut packet = String::new();
    match reader.read_line(&mut packet) {
        Err(_) => {
            return Err(SSLNetworkError::NoConnection {});
        }
        _ => {}
    };
    Ok(packet)
}

fn allow_certify_new_equipment() -> ResultSSL<bool> {
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

fn verify_chains(knowledge: Vec<CertificationChain>, certifier: Equipment) -> Vec<CertificationChain> {
    knowledge.into_iter().filter(|chain| {
        let certifier = certifier.clone();
        let chain_certifier = match chain.chain_certifier() {
            Some(certifier) => certifier.clone(),
            None => return false, // ignore empty chains
        };
        if certifier != chain_certifier {
            return false;
        }
        chain.is_valid().unwrap()
    }).collect()
}