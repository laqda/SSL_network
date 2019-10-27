# SSL_network

School project at CentraleSupélec. The goal is to build a network with the authentication rule "friends of my friends are my friends".

Each node of the network is named "Equipment". Each launch of the binary simulates a new equipment.

```shell script
ssl_network -a 127.0.0.1 -p 3201 -n Equipment1
```

When the simulated equipment is generated, a shell starts. The available commands are :

```
certified  :  Display certified equipments
clear      :  Clear shell
con:c      :  Start a connection as client (ex: con:c 127.0.0.1:3202)
con:l      :  Start a connection as server
help       :  Print this help
history    :  Print commands history or run a command from it
infos      :  Display equipment infos
quit       :  Quit
syn:c      :  Start a synchronization as client (ex: syn:c 127.0.0.1:3202)
syn:l      :  Start a synchronization as server
```

## Build

To build this project you need to install [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html).

```shell script
git clone git@github.com:quentm74/SSL_network.git
cd ./SSL_network
cargo build
./target/release/ssl_nework -h
```

## Example

Follow those simple commands to see in action a "friends of my friends are my friends" network.

Equipment1 and Equipment3 will be able to connect automatically even without connecting before. 

* Launch three equipments in different terminals

```shell script
ssl_network -a 127.0.0.1 -p 3201 -n Equipment1
```

```shell script
ssl_network -a 127.0.0.1 -p 3202 -n Equipment2
```

```shell script
ssl_network -a 127.0.0.1 -p 3203 -n Equipment3
```

* Connect 1 with 2

The user should approve the insertion of the peer equipment in each terminal.

(shell Equipment1)
```
> con:l
```

(shell Equipment2)
```
> con:c 127.0.0.1:3201
```

* Connect 2 with 3

The user should approve the insertion of the peer equipment in each terminal.

(shell Equipment2)
```
> con:l
```

(shell Equipment3)
```
> con:c 127.0.0.1:3202
```

* Synchronize 1 with 2

(shell Equipment1)
```
> syn:l
```

(shell Equipment2)
```
> syn:c 127.0.0.1:3201
```

* Connect 1 with 3

The user does not have to approve the insertion of the peer equipment in each terminal because Equipment1 has a certification chain to Equipment3 and Equipment3 has a certification chain to Equipment1.

At this step you should also see that they automatically exchange new certificates.

(shell Equipment1)
```
> con:l
```

(shell Equipment3)
```
> con:c 127.0.0.1:3201
```
