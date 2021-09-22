# SSHNOC Controller Server

## Description
SSHNOC Controller is a SSH-based RMM solution, it is a custom asyncio SSH Server for managing SSH tunnels with a database backend. It was developed for connecting various nodes from BSD firewalls to embedded IoT devices to a central controller in the most simple way. Only standard SSH is needed on the client side to connect the node to the controller. A tipical use case is a Teltonika RUT router with a simple Dropbear SSH client. Even that kind of device should connect to the controller with ease.

## License
LGPL v3 (see LICENSE.txt)

## Controller Server
Controller should have at least one public IP address. To start using the most basic and low-end cloud instance is enough (eg. Azure B1S).

### Install Server
Prepare directories:
```bash
sudo mkdir -p /opt/sshnoc
sudo setfacl -m u:${USER}:rwX /opt/sshnoc
```

Clone the repositoy:
```bash
git clone https://github.com/sshnoc/controller.git
```

Run the install scripts. Currently Python 3.8 is supported.
```bash
cd /opt/sshnoc/controller
./mkvenv && ./install
```

At this point you should be able to run the controller although it will fail since there are no ssh keys and there is no database present. Test run the controller:
```bash
./sshserver
```

### Start Server
Each controller server has a unique id (Controller Id) that you should decide now. In the folowing exmaples we use 'test' as the Controller Id. In order to use the controller server you need to generte SSH keys. There is small utility script to generate SSH keys:

```bash
cd /opt/sshnoc/controller
mkdir ./ssh
./genkey --id "test" -t rsa -b 2048
./genkey --id "test" -t ecdsa
./genkey --id "test" -t ed25519
```

Next, you need a MongoDB database. Spin up a dockerized Mongo on the local machine:

```bash
cd /opt/sshnoc/controller/mongo
docker-compose up
```

First, initialize the database then start the controller:
```bash
./sshserver --id test --mongo_uri mongodb://root:root@localhost:27019 --mongo_db sshnoc --init_db
./sshserver --id test --mongo_uri mongodb://root:root@localhost:27019 --mongo_db sshnoc --debug --ssh_port 2322 --http_admin_port 2380
```

### Test Client
Each client node has a unique id (Node Id) that you should decide now. In the folowing exmaples we use 'client' as the Node Id. This Id is the SSH username.

```bash
cd /opt/sshnoc/controller/ssh
ssh-keygen -N "" -f client
cat ssh/client.pub
<PUBKEY>
```

Start admin shell in a different terminal
```bash
./adminshell --id test --mongo_uri mongodb://root:root@localhost:27019 --mongo_db sshnoc 
```

Run the folowing command with the public key above:
```bash
add-ssh-node --id client --pubkey "<PUBKEY>"
exit
```

Run the the test client
```bash
ssh -o UserKnownHostsFile=./ssh/known_hosts -R ./nodes/client/8000.sock:localhost:8000 -i ./ssh/client -p 2322 client@localhost
```

You should see the following output:
```bash
...
[test] Connection established at: 2021-09-21 11:00:16.911176+00:00
[test] Your Client: client SSH-2.0-OpenSSH_7.9 chacha20-poly1305@openssh.com chacha20-poly1305@openssh.com
[test] Press Ctrl+C to abort the connection...
```

Now your SSH client is successfully connected to the controller server and TCP port 8000 is reverse forwarded from the socket file above. Please mind that due to a simple implementation of the socket file forwarding it is mandatory to name socket files on the server as `./nodes/<Node Id>/<Port>.sock`

### Production
In production you need a server with a public interface. Start a Mongo database. Select a free port and a Server Id. Install and start the server on that port like above. Open that port in the firewall. Select a Node Id. Generate SSH keys on the clients and create the node with the public key in the admin shell. Now you can connect with a simple SSH command. Probably you also need automation. On the server side you can use supervisor or systemd to start the server in the background. On the client side use autossh or a simple shell script with nohup.
