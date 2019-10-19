extern crate clap;
#[macro_use] extern crate failure;

use crate::errors::SSLNetworkError;
use std::process;
use clap::{App, Arg, ArgMatches};
use std::str::FromStr;

mod equipment;
mod errors;

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
            .required(true)
        ).get_matches();
    if let Err(e) = start(matches) {
        println!("{}", e);
        process::exit(1);
    }
}

fn start(matches: ArgMatches) -> Result<(), SSLNetworkError> {
    let arg_port = matches.value_of("port").unwrap();
    let port = match u32::from_str(arg_port) {
        Ok(port) => port,
        Err(_) => {
            return Err(SSLNetworkError::InvalidPort {port: String::from_str(arg_port).unwrap()})
        },
    };
    let eq = equipment::Equipment::new(port);
    Ok(())
}
