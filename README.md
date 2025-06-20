Rate limit for DDoS mitigation
1.Run controller
1.1For testing detection module

Run controller in file controller.py

ryu-manager controller.py

1.2.For testing mitigation module

Run controller in file mitigation_module.py

ryu-manager mitigation_module.py

2.Run mininet topology by

sudo python3 topology.py

simulation benign flow : example h1 ping h3, ...

simulation ddos flow : example h1 hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood h2

python3.9 should be used for ryu 

contact: minhnguyen27823@gmail.com (if you want our dataset)
