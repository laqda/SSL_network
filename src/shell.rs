use crate::equipment::SimulatedEquipment;
use crate::payloads::{Packet, PacketTypes, Nonce, gen_nonce};
use crate::errors::{SSLNetworkError, ResultSSL};
use shrust::{Shell, ShellIO, ExecResult};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::io;
use std::sync::{Arc, Mutex};
use std::io::{Write, BufReader, BufRead, BufWriter, stdout};
use std::hash::{Hash, Hasher};
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
        shell.new_command("con:server", "Start a connection as server", 0, con_server);
        shell.new_command("con:client", "Start a connection as client (ex: con:client 127.0.0.1:3202)", 1, con_client);
        shell.new_command("syn:server", "Start a synchronization as server", 0, syn_server);
        shell.new_command("syn:client", "Start a synchronization as client (ex: syn:client 127.0.0.1:3202)", 1, syn_client);
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

#[derive(Hash)]
struct ConnectionIdentifier {
    client_nonce: Nonce,
    server_nonce: Nonce,
}

// CONNECTION

fn con_server(_io: &mut ShellIO, ref_eq: &mut std::sync::Arc<std::sync::Mutex<SimulatedEquipment>>, _args: &[&str]) -> ExecResult {
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

fn con_client(_io: &mut ShellIO, ref_eq: &mut std::sync::Arc<std::sync::Mutex<SimulatedEquipment>>, args: &[&str]) -> ExecResult {
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

fn connection_server(stream: TcpStream, ref_eq: Arc<Mutex<SimulatedEquipment>>) -> ResultSSL<()> {
    let mut eq = ref_eq.lock().unwrap();
    let local_addr = stream.local_addr().unwrap().to_string();
    let peer_addr = stream.peer_addr().unwrap().to_string();

    let peer_name;
    let peer_pub_key;
    let peer_nonce: Nonce;

    let packet = receive_packet(&stream)?;
    let payload = packet.get_payload()?;
    match payload {
        PacketTypes::DISCOVER_SYN { name, pub_key, nonce } => {
            println!("[INFO] DISCOVER from {} as {}", peer_addr, local_addr);
            peer_name = name.clone();
            peer_pub_key = pub_key.clone();
            peer_nonce = nonce.clone();
        }
        PacketTypes::REFUSED => {
            return Err(SSLNetworkError::Refused {});
        }
        _ => {
            return Err(SSLNetworkError::ProtocolViolation {});
        }
    }

    let local_nonce: Nonce = gen_nonce();

    let packet = Packet::generate_discover_syn_ack(&eq.get_name(), &eq.get_public_key(), local_nonce);
    let packet = packet.sign(&local_nonce, &peer_nonce, &eq.get_private_key());
    send_packet(&stream, packet)?;

    let packet = receive_packet(&stream)?;
    packet.verify(&local_nonce, &peer_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        PacketTypes::DISCOVER_ACK => {}
        PacketTypes::REFUSED => {
            return Err(SSLNetworkError::Refused {});
        }
        _ => {
            return Err(SSLNetworkError::ProtocolViolation {});
        }
    }

    let mut hasher = DefaultHasher::new();
    let connection_identifier = ConnectionIdentifier { client_nonce: peer_nonce.clone(), server_nonce: local_nonce.clone() };
    connection_identifier.hash(&mut hasher);
    let connection_identifier = hasher.finish();
    println!("[INFO] Connection identifier : {}", connection_identifier);

    let peer_eq = Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() };
    let should_generate_new_certificate = match eq.get_network().is_equipment_certified(&peer_eq)? { // test if peer belongs to local knowledge
        true => {
            println!("[INFO] Peer equipment is already certified");
            !eq.get_network().is_equipment_directly_certified(&peer_eq)?
        }
        false => {
            if !allow_certify_new_equipment()? { // ask user to validate connection
                let packet = Packet::generate_refused();
                let packet = packet.sign(&local_nonce, &peer_nonce, &eq.get_private_key());
                send_packet(&stream, packet)?;
                return Err(SSLNetworkError::Refused {});
            }
            true
        }
    };

    let generated_new_certificate = match should_generate_new_certificate {
        true => Some(eq.certify(&Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() })),
        false => None,
    };

    let knowledge = eq.get_network().get_chains_certifications()?.clone();
    let packet = Packet::generate_connection_allowed_syn(generated_new_certificate.clone(), &knowledge);
    let packet = packet.sign(&local_nonce, &peer_nonce, &eq.get_private_key());
    send_packet(&stream, packet)?;

    let received_new_certificate;

    let packet = receive_packet(&stream)?;
    packet.verify(&local_nonce, &peer_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        PacketTypes::CONNECTION_ALLOWED_SYN_ACK { new_certificate, knowledge } => {
            received_new_certificate = new_certificate;
            let verified_knowledge = verify_chains(knowledge, Equipment { name: eq.get_name().clone().to_string(), pub_key: eq.get_public_key().clone() }, Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() });
            eq.get_network().add_chains_certifications(verified_knowledge)?;
        }
        PacketTypes::REFUSED => {
            return Err(SSLNetworkError::Refused {});
        }
        _ => {
            return Err(SSLNetworkError::ProtocolViolation {});
        }
    }

    println!("[INFO] Connection allowed by peer");

    let packet = Packet::generate_connection_allowed_ack();
    let packet = packet.sign(&local_nonce, &peer_nonce, &eq.get_private_key());
    send_packet(&stream, packet)?;

    if let Some(certificate) = generated_new_certificate {
        if certificate.is_valid()? {
            println!("[INFO] Save new certificate generated for peer");
            eq.get_network().add_certificate(&certificate)?;
        } else {
            return Err(SSLNetworkError::InvalidCertificate {});
        }
    }

    if let Some(certificate) = received_new_certificate {
        if certificate.is_valid()? {
            println!("[INFO] Save new certificate generated by peer");
            eq.get_network().add_certificate(&certificate)?;
        } else {
            return Err(SSLNetworkError::InvalidCertificate {});
        }
    }

    println!("[INFO] Connection successful");

    Ok(())
}

fn connection_client(stream: TcpStream, ref_eq: Arc<Mutex<SimulatedEquipment>>) -> ResultSSL<()> {
    let mut eq = ref_eq.lock().unwrap();
    let local_addr = stream.local_addr().unwrap().to_string();
    let peer_addr = stream.peer_addr().unwrap().to_string();

    let peer_name;
    let peer_pub_key;
    let peer_nonce: Nonce;

    let local_nonce: Nonce = gen_nonce();

    let packet = Packet::generate_discover_syn(eq.get_name().clone(), &eq.get_public_key(), local_nonce.clone());
    send_packet(&stream, packet)?;

    let packet = receive_packet(&stream)?;
    let payload = packet.get_payload()?;
    match payload {
        PacketTypes::DISCOVER_SYN_ACK { name, pub_key, nonce } => {
            println!("[INFO] DISCOVER from {} as {}", peer_addr, local_addr);
            peer_name = name.clone();
            peer_pub_key = pub_key.clone();
            peer_nonce = nonce.clone();
        }
        PacketTypes::REFUSED => {
            return Err(SSLNetworkError::Refused {});
        }
        _ => {
            return Err(SSLNetworkError::ProtocolViolation {});
        }
    }

    let packet = Packet::generate_discover_ack();
    let packet = packet.sign(&peer_nonce, &local_nonce, &eq.get_private_key());
    send_packet(&stream, packet)?;

    let mut hasher = DefaultHasher::new();
    let connection_identifier = ConnectionIdentifier { client_nonce: local_nonce.clone(), server_nonce: peer_nonce.clone() };
    connection_identifier.hash(&mut hasher);
    let connection_identifier = hasher.finish();
    println!("[INFO] Connection identifier : {}", connection_identifier);

    let received_new_certificate;

    let packet = receive_packet(&stream)?;
    packet.verify(&peer_nonce, &local_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        PacketTypes::CONNECTION_ALLOWED_SYN { new_certificate, knowledge } => {
            received_new_certificate = new_certificate;
            let verified_knowledge = verify_chains(knowledge, Equipment { name: eq.get_name().clone().to_string(), pub_key: eq.get_public_key().clone() }, Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() });
            eq.get_network().add_chains_certifications(verified_knowledge)?;
        }
        PacketTypes::REFUSED => {
            return Err(SSLNetworkError::Refused {});
        }
        _ => {
            return Err(SSLNetworkError::ProtocolViolation {});
        }
    }

    let peer_eq = Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() };
    let should_generate_new_certificate = match eq.get_network().is_equipment_certified(&peer_eq)? { // test if peer belongs to local knowledge
        true => {
            println!("[INFO] Peer equipment is already certified");
            !eq.get_network().is_equipment_directly_certified(&peer_eq)?
        }
        false => {
            if !allow_certify_new_equipment()? { // ask user to validate connection
                let packet = Packet::generate_refused();
                let packet = packet.sign(&peer_nonce, &local_nonce, &eq.get_private_key());
                send_packet(&stream, packet)?;
                return Err(SSLNetworkError::Refused {});
            }
            true
        }
    };

    let generated_new_certificate = match should_generate_new_certificate {
        true => Some(eq.certify(&Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() })),
        false => None,
    };

    let knowledge = eq.get_network().get_chains_certifications()?.clone();
    let packet = Packet::generate_connection_allowed_syn_ack(generated_new_certificate.clone(), &knowledge);
    let packet = packet.sign(&peer_nonce, &local_nonce, &eq.get_private_key());
    send_packet(&stream, packet)?;

    let packet = receive_packet(&stream)?;
    packet.verify(&peer_nonce, &local_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        PacketTypes::CONNECTION_ALLOWED_ACK => {}
        PacketTypes::REFUSED => {
            return Err(SSLNetworkError::Refused {});
        }
        _ => {
            return Err(SSLNetworkError::ProtocolViolation {});
        }
    }

    println!("[INFO] Connection allowed by peer");

    let packet = Packet::generate_connection_allowed_ack();
    let packet = packet.sign(&peer_nonce, &local_nonce, &eq.get_private_key());
    send_packet(&stream, packet)?;

    if let Some(certificate) = generated_new_certificate {
        if certificate.is_valid()? {
            println!("[INFO] Save new certificate generated for peer");
            eq.get_network().add_certificate(&certificate)?;
        } else {
            return Err(SSLNetworkError::InvalidCertificate {});
        }
    }

    if let Some(certificate) = received_new_certificate {
        if certificate.is_valid()? {
            println!("[INFO] Save new certificate generated by peer");
            eq.get_network().add_certificate(&certificate)?;
        } else {
            return Err(SSLNetworkError::InvalidCertificate {});
        }
    }

    println!("[INFO] Connection successful");

    Ok(())
}

// SYNCHRONIZATION

fn syn_server(_io: &mut ShellIO, ref_eq: &mut std::sync::Arc<std::sync::Mutex<SimulatedEquipment>>, _args: &[&str]) -> ExecResult {
    let eq = ref_eq.lock().unwrap();

    let address = eq.get_socket_address();
    let listener = TcpListener::bind(address)?;

    drop(eq); // unlock eq

    println!("[INFO] Start listening {}", address);

    let stream = listener.accept();
    match stream {
        Ok(s) => {
            match synchronization_server(s.0, ref_eq.clone()) {
                Err(e) => println!("{}", e),
                _ => {}
            }
        }
        Err(e) => println!("[ERROR] {}", e),
    };
    Ok(())
}

fn syn_client(_io: &mut ShellIO, ref_eq: &mut std::sync::Arc<std::sync::Mutex<SimulatedEquipment>>, args: &[&str]) -> ExecResult {
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
    match synchronization_client(stream, ref_eq.clone()) {
        Err(e) => println!("{}", e),
        _ => {}
    }
    Ok(())
}

fn synchronization_server(stream: TcpStream, ref_eq: Arc<Mutex<SimulatedEquipment>>) -> ResultSSL<()> {
    let mut eq = ref_eq.lock().unwrap();
    let local_addr = stream.local_addr().unwrap().to_string();
    let peer_addr = stream.peer_addr().unwrap().to_string();

    let peer_name;
    let peer_pub_key;
    let peer_nonce: Nonce;

    let packet = receive_packet(&stream)?;
    let payload = packet.get_payload()?;
    match payload {
        PacketTypes::DISCOVER_SYN { name, pub_key, nonce } => {
            println!("[INFO] DISCOVER from {} as {}", peer_addr, local_addr);
            peer_name = name.clone();
            peer_pub_key = pub_key.clone();
            peer_nonce = nonce.clone();
        }
        PacketTypes::REFUSED => {
            return Err(SSLNetworkError::Refused {});
        }
        _ => {
            return Err(SSLNetworkError::ProtocolViolation {});
        }
    }

    let local_nonce: Nonce = gen_nonce();

    let packet = Packet::generate_discover_syn_ack(&eq.get_name(), &eq.get_public_key(), local_nonce);
    let packet = packet.sign(&local_nonce, &peer_nonce, &eq.get_private_key());
    send_packet(&stream, packet)?;

    let packet = receive_packet(&stream)?;
    packet.verify(&local_nonce, &peer_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        PacketTypes::DISCOVER_ACK => {}
        PacketTypes::REFUSED => {
            return Err(SSLNetworkError::Refused {});
        }
        _ => {
            return Err(SSLNetworkError::ProtocolViolation {});
        }
    }

    match eq.get_network().is_equipment_certified(&Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() })? { // test if peer belongs to local knowledge
        true => {
            println!("[INFO] Peer equipment is certified");
        }
        false => {
            let packet = Packet::generate_refused();
            let packet = packet.sign(&local_nonce, &peer_nonce, &eq.get_private_key());
            send_packet(&stream, packet)?;
            return Err(SSLNetworkError::Refused {});
        }
    };

    let peer_eq = Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() };
    let should_generate_new_certificate = eq.get_network().is_equipment_directly_certified(&peer_eq)?;

    let generated_new_certificate = match should_generate_new_certificate {
        true => Some(eq.certify(&Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() })),
        false => None,
    };

    let knowledge = eq.get_network().get_chains_certifications()?.clone();
    let packet = Packet::generate_synchronization_send_knowledge_syn(generated_new_certificate.clone(), &knowledge);
    let packet = packet.sign(&local_nonce, &peer_nonce, &eq.get_private_key());
    send_packet(&stream, packet)?;

    let received_new_certificate;

    let packet = receive_packet(&stream)?;
    packet.verify(&local_nonce, &peer_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        PacketTypes::SYNCHRONIZATION_SEND_KNOWLEDGE_SYN_ACK { new_certificate, knowledge } => {
            let verified_knowledge = verify_chains(knowledge, Equipment { name: eq.get_name().clone().to_string(), pub_key: eq.get_public_key().clone() }, Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() });
            eq.get_network().add_chains_certifications(verified_knowledge)?;
            received_new_certificate = new_certificate;
        }
        PacketTypes::REFUSED => {
            return Err(SSLNetworkError::Refused {});
        }
        _ => {
            return Err(SSLNetworkError::ProtocolViolation {});
        }
    }

    println!("[INFO] Synchronization allowed by peer");

    let packet = Packet::generate_synchronization_send_knowledge_ack();
    let packet = packet.sign(&local_nonce, &peer_nonce, &eq.get_private_key());
    send_packet(&stream, packet)?;

    if let Some(certificate) = generated_new_certificate {
        if certificate.is_valid()? {
            println!("[INFO] Save new certificate generated for peer");
            eq.get_network().add_certificate(&certificate)?;
        } else {
            return Err(SSLNetworkError::InvalidCertificate {});
        }
    }

    if let Some(certificate) = received_new_certificate {
        if certificate.is_valid()? {
            println!("[INFO] Save new certificate generated by peer");
            eq.get_network().add_certificate(&certificate)?;
        } else {
            return Err(SSLNetworkError::InvalidCertificate {});
        }
    }

    println!("[INFO] Synchronization successful");

    Ok(())
}

fn synchronization_client(stream: TcpStream, ref_eq: Arc<Mutex<SimulatedEquipment>>) -> ResultSSL<()> {
    let mut eq = ref_eq.lock().unwrap();
    let local_addr = stream.local_addr().unwrap().to_string();
    let peer_addr = stream.peer_addr().unwrap().to_string();

    let peer_name;
    let peer_pub_key;
    let peer_nonce: Nonce;

    let local_nonce: Nonce = gen_nonce();

    let packet = Packet::generate_discover_syn(eq.get_name().clone(), &eq.get_public_key(), local_nonce.clone());
    send_packet(&stream, packet)?;

    let packet = receive_packet(&stream)?;
    let payload = packet.get_payload()?;
    match payload {
        PacketTypes::DISCOVER_SYN_ACK { name, pub_key, nonce } => {
            println!("[INFO] DISCOVER from {} as {}", peer_addr, local_addr);
            peer_name = name.clone();
            peer_pub_key = pub_key.clone();
            peer_nonce = nonce.clone();
        }
        PacketTypes::REFUSED => {
            return Err(SSLNetworkError::Refused {});
        }
        _ => {
            return Err(SSLNetworkError::ProtocolViolation {});
        }
    }

    let packet = Packet::generate_discover_ack();
    let packet = packet.sign(&peer_nonce, &local_nonce, &eq.get_private_key());
    send_packet(&stream, packet)?;

    let received_new_certificate;

    let packet = receive_packet(&stream)?;
    packet.verify(&peer_nonce, &local_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        PacketTypes::SYNCHRONIZATION_SEND_KNOWLEDGE_SYN { new_certificate, knowledge } => {
            let verified_knowledge = verify_chains(knowledge, Equipment { name: eq.get_name().clone().to_string(), pub_key: eq.get_public_key().clone() }, Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() });
            eq.get_network().add_chains_certifications(verified_knowledge)?;
            received_new_certificate = new_certificate;
        }
        PacketTypes::REFUSED => {
            return Err(SSLNetworkError::Refused {});
        }
        _ => {
            return Err(SSLNetworkError::ProtocolViolation {});
        }
    }

    match eq.get_network().is_equipment_certified(&Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() })? { // test if peer belongs to local knowledge
        true => {
            println!("[INFO] Peer equipment is certified");
        }
        false => {
            let packet = Packet::generate_refused();
            let packet = packet.sign(&peer_nonce, &local_nonce, &eq.get_private_key());
            send_packet(&stream, packet)?;
            return Err(SSLNetworkError::Refused {});
        }
    };

    let peer_eq = Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() };
    let should_generate_new_certificate = eq.get_network().is_equipment_directly_certified(&peer_eq)?;

    let generated_new_certificate = match should_generate_new_certificate {
        true => Some(eq.certify(&Equipment { name: peer_name.clone(), pub_key: peer_pub_key.clone() })),
        false => None,
    };

    let knowledge = eq.get_network().get_chains_certifications()?.clone();
    let packet = Packet::generate_synchronization_send_knowledge_syn_ack(generated_new_certificate.clone(), &knowledge);
    let packet = packet.sign(&peer_nonce, &local_nonce, &eq.get_private_key());
    send_packet(&stream, packet)?;

    let packet = receive_packet(&stream)?;
    packet.verify(&peer_nonce, &local_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        PacketTypes::SYNCHRONIZATION_SEND_KNOWLEDGE_ACK => {
            println!("[INFO] Synchronization allowed by peer");
        }
        PacketTypes::REFUSED => {
            return Err(SSLNetworkError::Refused {});
        }
        _ => {
            return Err(SSLNetworkError::ProtocolViolation {});
        }
    }

    if let Some(certificate) = generated_new_certificate {
        if certificate.is_valid()? {
            println!("[INFO] Save new certificate generated for peer");
            eq.get_network().add_certificate(&certificate)?;
        } else {
            return Err(SSLNetworkError::InvalidCertificate {});
        }
    }

    if let Some(certificate) = received_new_certificate {
        if certificate.is_valid()? {
            println!("[INFO] Save new certificate generated by peer");
            eq.get_network().add_certificate(&certificate)?;
        } else {
            return Err(SSLNetworkError::InvalidCertificate {});
        }
    }

    println!("[INFO] Synchronization successful");

    Ok(())
}

// tools

fn send_packet(stream: &TcpStream, packet: Packet) -> ResultSSL<()> {
    let packet = serde_json::to_string(&packet).unwrap();
    send(stream, packet)
}

fn receive_packet(stream: &TcpStream) -> ResultSSL<Packet> {
    let packet = receive(stream)?;
    let packet = serde_json::from_str(packet.as_str()).map_err(|_| SSLNetworkError::InvalidPayload {}).unwrap();
    Ok(packet)
}

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

fn verify_chains(knowledge: Vec<CertificationChain>, certified: Equipment, certifier: Equipment) -> Vec<CertificationChain> {
    knowledge.into_iter().filter(|chain| {
        let certifier = certifier.clone();
        match chain.chain_certifier() {
            Some(chain_certifier) => {
                if certifier != chain_certifier.clone() {
                    return false;
                }
            }
            None => return false, // ignore empty chains
        };
        let certified = certified.clone();
        match chain.chain_certified() {
            Some(chain_certified) => {
                if certified != chain_certified.clone() {
                    return false;
                }
            }
            None => return false, // ignore empty chains
        };
        chain.is_valid().unwrap()
    }).collect()
}