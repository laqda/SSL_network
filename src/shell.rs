use shrust::Shell;
use crate::equipment::Equipment;
use std::net::{SocketAddr, TcpListener, IpAddr, TcpStream};
use crate::errors::SSLNetworkError;
use std::thread;
use std::sync::{Arc, Mutex};

pub struct EquipmentShell(pub Shell<Equipment>);

impl EquipmentShell {
    pub fn new(eq: Equipment) -> EquipmentShell {
        let mut shell = Shell::new(eq);
        shell.new_command("i", "Display equipment infos", 0, |_, eq, _args| {
            println!("\n{}", eq);
            Ok(())
        });
        shell.new_command("c", "Clear shell", 0, |_, _eq, _args| {
            print!("\x1B[2J");
            Ok(())
        });
        shell.new_command("listen", "Start a connection as server", 0, |_, eq, _args| {
            let address = eq.get_socket_address();
            let listener = TcpListener::bind(address)?;
            println!("[INFO] Start listening {}", address);
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => handle_connection(s, eq),
                    Err(e) => println!("[ERROR] {}", e)
                };
            }
            Ok(())
        });
        shell.new_command("connect", "Start a connection as client (ex: connect 127.0.0.1:3202)", 1, |_, eq, args| {
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
            Ok(())
        });

        EquipmentShell(shell)
    }
}

fn handle_connection(stream: TcpStream, eq: &mut Equipment) {
    println!("ok {}", eq.get_socket_address());
}