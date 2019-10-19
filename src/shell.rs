use shrust::Shell;
use crate::equipment::Equipment;
use std::net::{SocketAddr, TcpListener, IpAddr, TcpStream};
use crate::errors::SSLNetworkError;
use std::{thread, io};
use std::sync::{Arc, Mutex};
use failure::_core::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

pub struct EquipmentShell(pub Shell<Arc<Mutex<Equipment>>>);

impl EquipmentShell {
    pub fn new(eq: Equipment) -> EquipmentShell {
        let mut shell = Shell::new(Arc::new(Mutex::new(eq)));
        shell.new_command("i", "Display equipment infos", 0, |_, ref_eq, _args| {
            let eq = ref_eq.lock().unwrap();

            println!("\n{}", eq);
            Ok(())
        });
        shell.new_command("c", "Clear shell", 0, |_, _ref_eq, _args| {
            print!("\x1B[2J");
            Ok(())
        });
        shell.new_command("listen", "Start a connection as server", 0, |_, ref_eq, _args| {
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
                            handle_connection(s, ref_eq_thread.clone());
                            println!("Press [ENTER] to continue");
                            break;
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
        });
        shell.new_command("connect", "Start a connection as client (ex: connect 127.0.0.1:3202)", 1, |_, ref_eq, args| {
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
            Ok(())
        });

        EquipmentShell(shell)
    }
}

fn handle_connection(stream: TcpStream, ref_eq: Arc<Mutex<Equipment>>) {
    let eq = ref_eq.lock().unwrap();
    println!("receive connection and access equipment {}", eq.get_socket_address());
}