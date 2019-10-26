use crate::equipment::Equipment;
use crate::payloads::{ConnectionPacket, ConnectionPacketTypes, Nonce, gen_nonce};
use crate::errors::{SSLNetworkError, ResultSSL};
use shrust::{Shell, ShellIO, ExecResult};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::io;
use std::sync::{Arc, Mutex};
use std::io::{Write, BufReader, BufRead, BufWriter, stdout};
use std::hash::Hash;
use std::collections::hash_map::DefaultHasher;
use openssl::x509::X509;
use crate::network::ChainCertification;
use crate::shared_types::PublicKey;
use openssl::pkey::PKey;

pub struct EquipmentShell(pub Shell<Arc<Mutex<Equipment>>>);

impl EquipmentShell {
    pub fn new(eq: Equipment) -> EquipmentShell {
        let mut shell = Shell::new(Arc::new(Mutex::new(eq)));
        shell.new_command("infos", "Display equipment infos", 0, infos);
        shell.new_command("clear", "Clear shell", 0, clear);
        shell.new_command("certified", "Display certified equipments", 0, certified);
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

fn certified(_io: &mut ShellIO, ref_eq: &mut std::sync::Arc<std::sync::Mutex<Equipment>>, _args: &[&str]) -> ExecResult {
    let mut eq = ref_eq.lock().unwrap();
    let certified_equipments = eq.get_network().get_certified_equipments();
    println!();
    for (index, chain) in certified_equipments.iter().enumerate() {
        let pub_key = String::from_utf8(chain.public_key.clone()).unwrap();
        println!("[{}] {}\n\n{}\n", index, chain.name.clone(), pub_key);
        for ((name, public_key), certificate) in chain.chain.clone() {
            println!("[*] {}", name);
            let x509 = X509::from_pem(&certificate).unwrap();
            let _: Vec<_> = x509.issuer_name().entries().map(|issuer| println!("(issuer) {}", issuer.data().as_utf8().unwrap())).collect();
            let _: Vec<_> = x509.subject_name().entries().map(|subject| println!("(subject) {}", subject.data().as_utf8().unwrap())).collect();
            println!("\n{}", String::from_utf8(public_key.clone()).unwrap());
            println!("\n{}", String::from_utf8(certificate.clone()).unwrap());
        }
    }
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
            match connection_server(s.0, ref_eq.clone()) {
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

fn connection_server(stream: TcpStream, ref_eq: Arc<Mutex<Equipment>>) -> ResultSSL<()> {
    let mut eq = ref_eq.lock().unwrap();
    let local_addr = stream.local_addr().unwrap().to_string();
    let peer_addr = stream.peer_addr().unwrap().to_string();

    let eq_name = &eq.get_name();
    let eq_pub_key = &eq.get_public_key();
    let eq_pri_key = &eq.get_private_key();
    let eq_network = eq.get_network();

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

    let packet = ConnectionPacket::generate_discover_syn_ack(eq_name.clone(), eq_pub_key.clone(), local_nonce.clone());
    let packet = packet.sign(&local_nonce, &peer_nonce, eq_pri_key);
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

    let should_generate_new_certificate = match eq_network.is_verified(&peer_pub_key) { // test if peer belongs to local knowledge
        true => {
            println!("[INFO] Peer equipment is already certified");
            false
        }
        false => {
            let connection_identifier = ConnectionIdentifier { client_nonce: peer_nonce.clone(), server_nonce: local_nonce.clone() };
            println!("[INFO] Connection identifier : {:#?}", connection_identifier.hash(&mut DefaultHasher::new()));
            if !allow_certify_new_equipment()? { // ask user to validate connection
                let packet = ConnectionPacket::generate_refused();
                let packet = packet.sign(&local_nonce, &peer_nonce, eq_pri_key);
                connection_send(&stream, packet)?;
                return Err(SSLNetworkError::ConnectionRefused {});
            }
            true
        }
    };

    let generated_new_certificate = match should_generate_new_certificate {
        true => Some(eq.certify(peer_name.clone(), peer_pub_key.clone()).to_pem().unwrap()),
        false => None,
    };

    let packet = ConnectionPacket::generate_allowed_syn(generated_new_certificate.clone(), eq.get_network().get_certified_equipments().clone());
    let packet = packet.sign(&local_nonce, &peer_nonce, eq_pri_key);
    connection_send(&stream, packet)?;

    let received_new_certificate;

    let packet = connection_receive(&stream)?;
    packet.verify(&local_nonce, &peer_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        ConnectionPacketTypes::ALLOWED_SYN_ACK { new_certificate, knowledge } => {
            received_new_certificate = new_certificate;
            let verified_knowledge = verify_chains(knowledge, peer_pub_key.clone());
            eq.get_network().add_chains(verified_knowledge);
        }
        ConnectionPacketTypes::REFUSED => {
            return Err(SSLNetworkError::ConnectionRefused {});
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProtocolViolation {});
        }
    }

    println!("[INFO] Connection allowed by peer");

    let eq_network = eq.get_network();

    let packet = ConnectionPacket::generate_allowed_ack();
    let packet = packet.sign(&local_nonce, &peer_nonce, eq_pri_key);
    connection_send(&stream, packet)?;

    if let Some(certificate) = generated_new_certificate {
        println!("[INFO] Save new certificate generated for peer");
        eq_network.add_certification(
            peer_name.clone(),
            peer_pub_key.clone(),
            eq_name.clone(),
            eq_pub_key.clone(),
            certificate.clone(),
        );
    }

    if let Some(certificate) = received_new_certificate {
        println!("[INFO] Save new certificate generated by peer");
        eq_network.add_certification(
            eq_name.clone(),
            eq_pub_key.clone(),
            peer_name.clone(),
            peer_pub_key.clone(),
            certificate.clone(),
        );
    }

    println!("[INFO] Connection successful");

    Ok(())
}

fn connection_client(stream: TcpStream, ref_eq: Arc<Mutex<Equipment>>) -> ResultSSL<()> {
    let mut eq = ref_eq.lock().unwrap();
    let local_addr = stream.local_addr().unwrap().to_string();
    let peer_addr = stream.peer_addr().unwrap().to_string();

    let eq_name = &eq.get_name();
    let eq_pub_key = &eq.get_public_key();
    let eq_pri_key = &eq.get_private_key();

    let peer_name;
    let peer_pub_key;
    let peer_nonce: Nonce;

    let local_nonce: Nonce = gen_nonce();

    let packet = ConnectionPacket::generate_discover_syn(eq_name.clone(), eq_pub_key.clone(), local_nonce.clone());
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
    let packet = packet.sign(&peer_nonce, &local_nonce, eq_pri_key);
    connection_send(&stream, packet)?;

    let received_new_certificate;

    let packet = connection_receive(&stream)?;
    packet.verify(&peer_nonce, &local_nonce, &peer_pub_key)?;
    let payload = packet.get_payload()?;
    match payload {
        ConnectionPacketTypes::ALLOWED_SYN { new_certificate, knowledge } => {
            received_new_certificate = new_certificate;
            let verified_knowledge = verify_chains(knowledge, peer_pub_key.clone());
            eq.get_network().add_chains(verified_knowledge);
        }
        ConnectionPacketTypes::REFUSED => {
            return Err(SSLNetworkError::ConnectionRefused {});
        }
        _ => {
            return Err(SSLNetworkError::ConnectionProtocolViolation {});
        }
    }

    let should_generate_new_certificate = match eq.get_network().is_verified(&peer_pub_key) { // test if peer belongs to local knowledge
        true => {
            println!("[INFO] Peer equipment is already certified");
            false
        }
        false => {
            let connection_identifier = ConnectionIdentifier { client_nonce: peer_nonce.clone(), server_nonce: local_nonce.clone() };
            println!("[INFO] Connection identifier : {:#?}", connection_identifier.hash(&mut DefaultHasher::new()));
            if !allow_certify_new_equipment()? { // ask user to validate connection
                let packet = ConnectionPacket::generate_refused();
                let packet = packet.sign(&peer_nonce, &local_nonce, eq_pri_key);
                connection_send(&stream, packet)?;
                return Err(SSLNetworkError::ConnectionRefused {});
            }
            true
        }
    };

    let generated_new_certificate = match should_generate_new_certificate {
        true => Some(eq.certify(peer_name.clone(), peer_pub_key.clone()).to_pem().unwrap()),
        false => None,
    };

    let knowledge = eq.get_network().get_certified_equipments().clone();
    let packet = ConnectionPacket::generate_allowed_syn_ack(generated_new_certificate.clone(), knowledge);
    let packet = packet.sign(&peer_nonce, &local_nonce, eq_pri_key);
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

    let eq_network = eq.get_network();

    let packet = ConnectionPacket::generate_allowed_ack();
    let packet = packet.sign(&peer_nonce, &local_nonce, eq_pri_key);
    connection_send(&stream, packet)?;

    if let Some(certificate) = generated_new_certificate {
        println!("[INFO] Save new certificate generated for peer");
        eq_network.add_certification(
            peer_name.clone(),
            peer_pub_key.clone(),
            eq_name.clone(),
            eq_pub_key.clone(),
            certificate.clone(),
        );
    }

    if let Some(certificate) = received_new_certificate {
        println!("[INFO] Save new certificate generated by peer");
        eq_network.add_certification(
            eq_name.clone(),
            eq_pub_key.clone(),
            peer_name.clone(),
            peer_pub_key.clone(),
            certificate.clone(),
        );
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

fn verify_chains(knowledge: Vec<ChainCertification>, root_pub_key: PublicKey) -> Vec<ChainCertification> {
    knowledge.into_iter().filter(|chain| {
        let node_certified_pub_key = chain.public_key.clone();
        let chain = chain.chain.clone();

        let mut pred_pub_key = node_certified_pub_key;
        for ((name, pub_key), cert) in chain {
            println!("name : {}", name.clone());
            println!("pub_key : {}", String::from_utf8(pub_key.clone()).unwrap());
            println!("pub_key : {}", String::from_utf8(pred_pub_key.clone()).unwrap());
            let cert = match X509::from_pem(&cert) {
                Ok(c) => c,
                Err(_) => return false,
            };
            let cert_pub_key = cert.public_key().unwrap().public_key_to_pem().unwrap();
            println!("cert_pub_key : {}", String::from_utf8(pred_pub_key.clone()).unwrap());
            if cert_pub_key != pred_pub_key {
                println!("false 1");
                return false;
            }
            if !cert.verify(&PKey::public_key_from_pem(&pub_key).unwrap()).unwrap() {
                println!("false 2");
                return false;
            }
            pred_pub_key = pub_key;
        }
        if root_pub_key.clone() != pred_pub_key {
            return false;
        }
        true
    }).collect()
}