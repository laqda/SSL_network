extern crate clap;
#[macro_use]
extern crate failure;

use crate::shell::EquipmentShell;
use crate::errors::SSLNetworkError;
use std::process;
use clap::{App, Arg, ArgMatches};
use std::str::FromStr;
use shrust::ShellIO;
use std::net::{IpAddr, Ipv4Addr};

mod equipment;
mod errors;
mod shell;
mod payloads;

fn main() {
    let matches = App::new("ssl_network")
        .about("Simulate a network to play with chained certifications")
        .version("1.0.0")
        .author("Quentin Michel <quentinmichel69110@gmail.com>")
        .arg(Arg::with_name("port")
            .help("Port used during communications with others equipments")
            .short("p")
            .long("port")
            .takes_value(true)
            .multiple(false)
            .empty_values(false)
            .required(true))
        .arg(Arg::with_name("address")
            .help("IP used during communications with others equipments")
            .short("a")
            .long("address")
            .takes_value(true)
            .multiple(false)
            .empty_values(false)
            .required(false)
            .default_value("127.0.0.1")
        ).get_matches();
    if let Err(e) = start(matches) {
        println!("{}", e);
        process::exit(1);
    }
}

fn start(matches: ArgMatches) -> Result<(), SSLNetworkError> {
    let arg_address = matches.value_of("address").unwrap();
    let address: Ipv4Addr = match arg_address.parse() {
        Ok(a) => a,
        Err(_) => {
            return Err(SSLNetworkError::InvalidAddress { address: arg_address.to_string() });
        }
    };

    let arg_port = matches.value_of("port").unwrap();
    let port = match u16::from_str(arg_port) {
        Ok(port) => port,
        Err(_) => {
            return Err(SSLNetworkError::InvalidPort { port: arg_port.to_string() });
        }
    };

    let eq = equipment::Equipment::new(address, port)?;
    let mut shell = EquipmentShell::new(eq);
    shell.0.run_loop(&mut ShellIO::default());
    Ok(())
}
