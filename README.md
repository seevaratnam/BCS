## Final Project

In this project, we were acting as a security engineer supporting an organization's SOC infrastructure. The SOC analysts have noticed some discrepancies with alerting in the Kibana system and the manager has asked the security engineering team to investigate and confirm that newly created alerts are working. 

If the alerts are working, we were asked to monitor live traffic on the wire to detect any abnormalities that aren't reflected in the alerting system. Here are our findings with appropriate analysis that we will be submitting to our manager.


### Environment


We were using a new Web Vulns lab environment located in Windows Azure Lab Services. This is a diagram of the network and the machines that was used during our analysis:

![](defensive/images/defensive/network_topology.png)



**ELK machine:** It holds the Kibana dashboards.

- IP Address: `192.168.1.100`

**Kali:** A standard Kali Linux machine. 

- IP Address: `192.168.1.90`

**Capstone:** Filebeat and Metricbeat are installed and will forward logs to the ELK machine. 
- IP Address: `192.168.1.105`
   - This VM is in the network solely for the purpose of testing alerts.

**Target 1:** Exposes a vulnerable WordPress server.
- IP Address: `192.168.1.110`



### Final Reports

Here are our findings that we will be submitting to both the SOC manager and the Engineering Manager with appropriate analysis.

* [Defensive Report](defensive/README.md)
* [Offensive Report](offensive/README.md)
* [Network Report](network/README.md)

