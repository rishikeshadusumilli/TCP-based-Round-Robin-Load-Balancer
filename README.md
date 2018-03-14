# TCP-based-Round-Robin-Load-Balancer

Inventory:

1. SDN Ryu Controller
2. Ubuntu virtual machine containing mininet
3. Xquartz application to use xterm in Mac OS

Topology:

                                   Ryu Controller (IP: 10.0.0.100)
                                              |
                                              |   
                                              |          |————————————————— Host 1 (IP: 10.0.0.4)
H1/Server 1 (IP: 10.0.0.1) ————————— Open vSwitch (TCP Load Balancer)———————Host 2 (IP: 10.0.0.5)
H2/Server 2 (IP: 10.0.0.2) ——————————|
H3/Server 3 (IP: 10.0.0.3)—————————— |

Pre-Requisites:

1. Ryu installation - Pip install ryu
2. Mininet installation - 
	1. sudo apt-get update
	2. sudo apt-get install -y git
	3. git clone git://github.com/mininet/mininet
	4. cd mininet
	5. git checkout -b 2.2.0 2.2.0
	6. util/install.sh -nfv
3. Build topology using mininet in Ubuntu OS and Ryu SDN controller
	Commands:
	1. Ryu run <load balancer program name>
	2. Sudo mn –topo=single,6 –mac –controller=remote, ip=<controller IP> —switch=ovsk, protocols=OpenFlow13
	3. Xterm h1 h2 h3 h4 h5 h6 (Creates GUI of individual hosts using Xquartz in Mac OS)

Execution Steps:

1. Use xterm terminal for H1 (Server 1-10.0.0.1), H2 (Server 2-10.0.0.2), and H3 (Server 3-10.0.0.3) to run induvidual TCP application (iperf) on port 5555
	Command: iperf –s –p 5555 –i 1 
2. Use xterm terminal for H4 (Host 1-10.0.0.4) or H5 (Host 2-10.0.0.5) to initiate a TCP connection request to Ryu controller (IP: 10.0.0.100) on port 5555
	Command: iperf –c 10.0.0.100 –p 5555 –t 15

Explanation: 

1. When a client initiates a TCP connection request to Ryu controller over IP: 10.0.0.100 and Port: 5555, TCP connection will be established between the controller and the client. 
2. Ryu controller will then establish a TCP connection with the respective server (H1/Server1, H2/Server2, or H3/Server3) based on the server count in my program (H1/Server1=1, H2/Server2=2, H3/Server3=3).
3. Server count will increment automatically by 1 to represent the next server immediately after the first TCP connection request from the controller to the server in the above step.
4. Multiple clients can be handled simultaneously by different TCP application running servers depending on the server count (H1/Server1=1, H2/Server2=2, H3/Server3=3).
5. TCP connections between the client and the controller and the controller and the server will be removed after complete transfer of data from the client to the controller. 
6. Hence, when TCP session is established between the client and the controller and the controller and the server, this connection remains active till the data transfer is completed. During this period, other TCP connections can also be established by other clients to other servers based on the server count value. 

