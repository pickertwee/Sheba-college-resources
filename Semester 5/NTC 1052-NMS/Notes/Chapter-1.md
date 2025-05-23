# Chapter 1: Network Management Architecture and Application

## What is a Data Network? 
- A system that connects multiple devices to share information.
- e.g : withdraw money > ATM connects to bank's computer > Bank check balance > Approve the transactions. 

## Role of a Network Engineer
- Ensure smooth data flow and fix problems when needed. 

### What they do??
| Stage | Description                         |
|------| -------------------------|
| **Plan** | Decide how to connect devices (LAN/WAN, hardware, software)
| **Build** | Set up the network (install routes, cables, servers)
| **Maintain** | Upgrade old devices or software |
| **Expand** | Adjust the network when more users/devices are added. |
| **Optimize** | Improve speed and performance |
| **Troubleshoot** | Fix network issue | 

## What is Network Management???
- Just like maintaining a highway system.
- Ensures data moves smoothly without crashes (errors) or traffic jam (slow speed).

### 5 Main Functions of Network Management (ISO Standard)
1. **Fault Management** 
    - Detects and fixes network issues. 
    - Steps: Find the problems > Isolate it > Fix it > Test the Network

2. **Configuration Management**  
    - Manages devices settings and keep track of all network devices.
    - Update software and replace outdated hardware. 

3. **Security Management**  
    - Protects data from hackers. 
    - Controls who can access the network.
    - Uses passwords, firewalls, and encryptio.

4. **Performance Management**  
    - Monitors speed and efficiency. 
    - Suggests upgrades if needed.

5. **Accounting Management** 
    - Tracks usage of network resources. 
    - Monitors how much data each user consumes.

## Network Management Protocols (How Networks Communicate)
- SNMP (Simple Network Management Protocol) -- most common protocol to monitor network devices
- CMIS/CMIP (Common Management Information Services/Protocol) -- Network management method.
- Both of this are use to checkup network devices, it checks if the devices all good and reports any problem. 

## Network Management Architectures
- Network Management = a set of software, each managing one specific set of data network components.
- Network Management Platform = Software packages that provide the essential network management functionality for many

### Differen Ways to Organize Network Management

| Architectures | Description | Example | Pros | Cons |
|---------------|-------------|---------|------|------|
|**Centralized Architecture (Single Control Center)**| - One main computer controls everything <br> - Simple but risky | A city's traffic system is controlled from a single headquarters. | Easy to manage, all data in one place | If the central system crashes, the entire network fails. | 
|**Hierarchical Architecture (Multiple Levels of Control)**| - A main servers manages several client systems <br> - More reliable | A banking network where a central system manages diff branches, but each branch has local bandwidth | Tasks are distributed, saving bandwidth | Harder to set up, requires manual configurations |
|**Distributed Architecture (Multiple Peer Systems Working Together)**| - Tasks are shared among multiple systems <br> - More flexible and fault-tolerant | Cloud computing networks | No single point of failure, better scalability| More complex. requires synchronization.| 

> **How to Choose a Network Management System???**
> - Consider on organization size, budget and security needs.
> - Large companies : Often use **distributed or hierarchical**
> - Small companies : **centralized**

