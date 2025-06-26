# Suricata Network IDS Integration with Wazuh SIEM

## Overview

This documentation provides a comprehensive guide for integrating Suricata Network Intrusion Detection System (NIDS) with Wazuh Security Information and Event Management (SIEM) platform. I successfully implemented this integration to create a powerful security monitoring solution that combines real-time network threat detection with centralized security event management. This setup enables security teams to monitor network traffic patterns, detect malicious activities, and correlate network events with host-based security data through a unified dashboard interface.
![image](https://github.com/user-attachments/assets/51d3ea45-5bad-4a07-88ca-a453c0715d81)


## Architecture

### Infrastructure Components
During the deployment, I configured distributed security components running across virtualized environments. The Wazuh Manager serves as the central SIEM server collecting and processing security events from multiple agents.

- **Wazuh Manager**: Ubuntu 22.04 (192.168.64.17) - Central SIEM server that processes security events and provides web dashboard interface
- **Wazuh Agent + Suricata**: Parrot OS (192.168.64.11) - Monitored endpoint running both network monitoring and log forwarding services  
- **Virtualization**: UTM hypervisor on macOS host providing isolated network environment for security testing

### Data Flow Architecture
The security data flows through multiple processing stages from network packet capture to dashboard visualization. Each stage adds intelligence and context to raw network data before presenting actionable security insights.

```
Network Traffic → Suricata Engine → EVE JSON Logs → Wazuh Agent → Wazuh Manager → Security Dashboard
```

## Prerequisites

### System Requirements
The deployment requires adequate system resources to handle continuous network monitoring and log processing. Insufficient resources can lead to packet drops and missed security events.

- Ubuntu 22.04+ for Wazuh Manager with minimum 4GB RAM for log processing and indexing
- Parrot OS or Debian-based system for monitored endpoint with network interface access
- Network connectivity between all components with proper firewall rules configured
- Administrative privileges on both systems for service configuration and management


## Installation Process

### Phase 1: Suricata Network IDS Installation

The installation process begins with deploying Suricata on the monitored endpoint. Suricata will analyze all network traffic passing through the designated interface and generate security alerts based on threat intelligence rules.

**1. Update System Packages and Install Suricata**
```bash
sudo apt update && sudo apt install suricata -y
```

![image](https://github.com/user-attachments/assets/2d5f37ef-bb62-4ff2-918a-4e8d5f9a2c71)

*Updates package repositories and installs Suricata IDS with all required dependencies for network monitoring*

**2. Download Community Threat Intelligence Rules**
```bash
sudo suricata-update
```
![image](https://github.com/user-attachments/assets/bd8ec575-fc11-4bc8-88ea-7ce27647f44e)

*Downloads and installs the Emerging Threats Open ruleset containing over 44,000 network-based attack signatures and indicators of compromise*

### Phase 2: Network Interface Configuration

Network interface configuration is critical for proper traffic monitoring. Suricata must be configured to monitor the correct network interface where target traffic flows to ensure comprehensive network visibility.

**3. Identify Active Network Interface**
```bash
ip addr
```
![image](https://github.com/user-attachments/assets/7bc85711-3063-46e6-97c2-fd0833d1feac)

*Lists all network interfaces and their configurations to identify the primary interface for monitoring (typically enp0s1, eth0, or similar)*

**4. Configure Suricata Network Monitoring Interface**
```bash
sudo nano /etc/suricata/suricata.yaml
```

**Modify the af-packet section to specify your network interface:**
```yaml
af-packet:
  - interface: enp0s1  # Replace with your actual interface name from step 3
```
![image](https://github.com/user-attachments/assets/5b91009f-bbc0-4af1-96b1-9b7ed6437da1)

*Configures Suricata to capture packets from the specified network interface using AF_PACKET for high-performance monitoring*

**5. Update Rule Path Configuration for Downloaded Rules**

Suricata needs to know where to find the threat detection rules downloaded by suricata-update. The default configuration may point to an incorrect directory location.

**Locate and modify the rule path settings:**
```yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
```
![image](https://github.com/user-attachments/assets/c849516b-620c-4b9a-948a-1cecd03b7f3d)

*Points Suricata to the correct location where suricata-update stores the community threat intelligence rules*

### Phase 3: Wazuh Agent Integration Configuration

The Wazuh agent must be configured to collect and forward Suricata's JSON-formatted security events. This creates the bridge between network-level detection and centralized SIEM analysis.

**6. Configure Suricata Log Collection in Wazuh Agent**
```bash
sudo nano /var/ossec/etc/ossec.conf
```
![image](https://github.com/user-attachments/assets/15808d09-4875-493f-8846-62e19d31e555)

**Add the following configuration before the closing `</ossec_config>` tag:**
```xml
  <!-- Suricata network security integration -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>

  <!-- System journal logs for correlation -->
  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>

  <!-- Active response execution logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <!-- Package management activity logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>
```
![image](https://github.com/user-attachments/assets/015a6a97-d5e0-49c7-8cc7-7cb8bfe53f7d)

*Configures Wazuh agent to read Suricata's EVE JSON logs and forward them to the central manager for processing and correlation*

### Phase 4: Service Management and Activation

Service restart is required to apply all configuration changes. Both Suricata and Wazuh agent must be restarted in the correct sequence to ensure proper integration.

**7. Apply Configuration Changes with Service Restart**
```bash
# Restart Suricata with updated network interface and rule configuration
sudo systemctl restart suricata

# Restart Wazuh agent to begin collecting Suricata logs
sudo systemctl restart wazuh-agent
```
*Applies all configuration changes and initializes the monitoring pipeline from network capture to SIEM integration*

**8. Verify All Services Are Running Correctly**
```bash
# Confirm Suricata is actively monitoring network traffic
sudo systemctl status suricata

# Confirm Wazuh agent is collecting and forwarding logs
sudo systemctl status wazuh-agent
```
![image](https://github.com/user-attachments/assets/410becd6-67a4-4db7-b48b-af034d0913fc)

*Validates that both services are operational and ready to process network security events*

## Validation and Testing

### Functional Integration Testing

Testing validates that the entire security monitoring pipeline works correctly from network event generation through dashboard display. These tests use known malicious patterns to trigger alerts safely.

**9. Generate Test Network Traffic to Trigger Alerts**
```bash
# Trigger Suricata rule 2100498 designed for testing GPL ATTACK_RESPONSE detection
curl "http://testmynids.org/uid/index.html"
```
![image](https://github.com/user-attachments/assets/d4baa4d8-b597-4dcd-a2b0-ff2d5caa8ab2)


**Expected Response from Test Site:**
```
uid=0(root) gid=0(root) groups=0(root)
```
*This response simulates command execution output that attackers might extract from compromised systems*

**10. Verify Suricata Successfully Detected the Test Traffic**
```bash
# Examine recent Suricata events and statistics
sudo tail -10 /var/log/suricata/eve.json
```
![image](https://github.com/user-attachments/assets/d2ef217a-c7fb-493f-b58c-aa0fdc88844a)

**Look for these key performance indicators:**
- `"rules_loaded": 44188` - Confirms all threat detection rules are loaded and active
- `"alert": 1` - Indicates successful alert generation from the test traffic

### Dashboard Integration Verification

The Wazuh dashboard should display network security events alongside other system events. Proper filtering helps isolate network-specific alerts from general system activity.

**11. Access Wazuh Security Dashboard**
Navigate to the Wazuh Manager web interface and access the Threat Hunting module for security event analysis. Apply specific filters to isolate Suricata-generated network security alerts from other system events.

**Apply the following filters for Suricata events:**
- `agent.name:"parrot"` - Shows events only from your monitored endpoint
- `location:"/var/log/suricata/eve.json"` - Displays only network security events from Suricata

![image](https://github.com/user-attachments/assets/debff0e9-cc58-4058-8af3-0ff6ea451cd8)


**Expected Dashboard Results:**
- **Rule ID**: 86601 - Wazuh's internal rule for processing Suricata alerts
- **Description**: "Suricata: Alert - GPL ATTACK_RESPONSE id check returned root" - Detailed alert information
- **Category**: "Potentially Bad Traffic" - Threat classification for security analysts
- **Source**: `/var/log/suricata/eve.json` - Confirms the alert originated from network monitoring

![image](https://github.com/user-attachments/assets/c2c8fb57-9686-491b-bd04-bb04738f6e2a)

## Advanced Testing Scenarios

### Comprehensive Network Security Testing

Additional testing scenarios validate detection capabilities across different attack vectors. These tests demonstrate the breadth of network security monitoring coverage.

```bash
# Generate network reconnaissance activity for detection testing
sudo nmap -sS 127.0.0.1

# Test malware communication detection capabilities
curl http://www.malware.testcategory.com

# Trigger additional network-based detection rules
curl http://testmynids.com
```
*These commands simulate various attack patterns including port scanning, malware communication, and suspicious web traffic*


## Architecture Diagram

```
                    Network Security Monitoring Architecture
                           
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                            UTM Hypervisor (macOS Host)                  │
    │                                                                         │
    │  ┌─────────────────────────────┐    ┌─────────────────────────────────┐ │
    │  │     Wazuh Manager           │    │     Parrot OS Endpoint          │ │
    │  │     (Ubuntu 22.04)          │    │     (192.168.64.11)             │ │
    │  │   192.168.64.17             │    │                                 │ │
    │  │                             │    │  ┌─────────────────────────────┐ │ │
    │  │  ┌───────────────────────┐  │    │  │        Suricata IDS         │ │ │
    │  │  │   Wazuh Indexer       │  │    │  │                             │ │ │
    │  │  │   (Elasticsearch)     │  │    │  │  • 44,188 Detection Rules   │ │ │
    │  │  └───────────────────────┘  │    │  │  • AF_PACKET Monitoring     │ │ │
    │  │                             │    │  │  • Interface: enp0s1        │ │ │
    │  │  ┌───────────────────────┐  │    │  │  • EVE JSON Logging         │ │ │
    │  │  │   Wazuh Server        │  │◄───────┤                            │ │ │
    │  │  │   (Event Processing)  │  │    │  └─────────────────────────────┘ │ │
    │  │  └───────────────────────┘  │    │               │                  │ │
    │  │                             │    │               ▼                  │ │
    │  │  ┌───────────────────────┐  │    │  ┌─────────────────────────────┐ │ │
    │  │  │   Wazuh Dashboard     │  │    │  │       Wazuh Agent           │ │ │
    │  │  │   (Web Interface)     │  │    │  │                             │ │ │
    │  │  └───────────────────────┘  │    │  │  • Log Collection           │ │ │
    │  └─────────────────────────────┘    │  │  • Event Forwarding         │ │ │
    └─────────────────────────────────────│  │  • JSON Processing          │ │ │
                                          │  └─────────────────────────────┘ │ │
                                          └─────────────────────────────────┘ 

    ┌─────────────────────────────────────────────────────────────────────────┤
    │                              Data Flow Pipeline                         │
    └─────────────────────────────────────────────────────────────────────────┘
              │                    │                    │                    │
              ▼                    ▼                    ▼                    ▼
    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
    │ Network Traffic │  │ Suricata Engine │  │ Wazuh Agent     │  │ Security        │
    │                 │  │                 │  │                 │  │ Dashboard       │
    │ • HTTP/HTTPS    │  │ • Packet        │  │ • Log           │  │                 │
    │ • DNS Queries   │──┤   Inspection    │──┤   Collection    │──┤ • Real-time     │
    │ • TCP/UDP       │  │ • Rule          │  │ • JSON          │  │   Alerts        │
    │ • Port Scans    │  │   Matching      │  │   Processing    │  │ • Event         │
    │ • Malware C2    │  │ • Alert         │  │ • Secure        │  │   Correlation   │
    │                 │  │   Generation    │  │   Forwarding    │  │ • Threat        │
    └─────────────────┘  └─────────────────┘  └─────────────────┘  │   Hunting       │
                                                                   └─────────────────┘

    Communication Protocols:
    ═══════════════════════
    Agent → Manager: TCP/1514 (Event Forwarding)
    Manager → Agent: TCP/1515 (Agent Registration & Commands)
    Dashboard Access: HTTPS/443 (Web Interface)
    
    Security Event Types Detected:
    ═════════════════════════════
    • Network Reconnaissance (Port Scans, Service Enumeration)
    • Malware Communication (C2 Traffic, Data Exfiltration)  
    • Web Application Attacks (SQL Injection, XSS, Directory Traversal)
    • Protocol Violations (Malformed Packets, Unusual Patterns)
    • Suspicious Traffic Patterns (Abnormal Data Flows, Timing Attacks)
```

## Technical Challenges and Solutions

### Challenge 1: XML Configuration Parsing Error
**Problem Encountered**: During initial setup, I encountered a critical issue where the Wazuh agent service failed to restart, displaying "XML configuration error" message in system logs.

**Root Cause Analysis**: Through investigation, I discovered the ossec.conf file contained multiple `<ossec_config>` root-level XML elements, violating XML parsing standards and preventing proper configuration loading.

**Solution Implementation**: I resolved this by consolidating all configuration sections into a single `<ossec_config>` block while maintaining proper XML hierarchy and element nesting to ensure valid configuration structure.

### Challenge 2: Zero Threat Detection Rules Loaded
**Problem Encountered**: After initial deployment, I noticed Suricata statistics showed `"rules_loaded": 0`, preventing any threat detection or alert generation despite proper traffic flow.

**Root Cause Analysis**: I identified a configuration path mismatch between Suricata's expected rule location (`/etc/suricata/rules`) and the actual storage location used by suricata-update (`/var/lib/suricata/rules`).

**Solution Implementation**: I corrected this by updating the `default-rule-path` configuration parameter to point to the correct directory where suricata-update stores downloaded threat intelligence rules.

### Challenge 3: Network Events Not Appearing in SIEM Dashboard
**Problem Encountered**: Initially, network traffic was being monitored and logged by Suricata, but no corresponding alerts appeared in the Wazuh security dashboard.

**Root Cause Analysis**: I determined that Suricata was generating log entries but threat detection rules were not properly loaded due to incorrect path configuration, preventing alert generation.

**Solution Implementation**: I verified rule loading status through Suricata statistics monitoring and corrected the configuration path to ensure all 44,000+ threat detection rules were properly loaded and active.

## Performance Metrics and Capabilities

### System Resource Utilization
The monitoring solution operates efficiently with minimal system overhead while providing comprehensive security coverage. Resource usage remains stable under normal operational conditions.

- **Memory Usage**: Approximately 914MB for the Suricata process during active monitoring
- **CPU Usage**: Less than 1% under normal network load conditions
- **Threat Intelligence**: 44,188 network-based attack signatures and detection rules
- **Detection Latency**: Less than 1 second from network event occurrence to dashboard display

### Network Security Detection Capabilities
The integrated solution provides comprehensive network security monitoring across multiple protocol layers and attack vectors. Detection capabilities cover both automated threats and manual attack activities.

- **Protocol Analysis**: Deep packet inspection for HTTP, HTTPS, DNS, TCP, UDP, and other network protocols
- **Malware Detection**: Command and control communication patterns and malicious payload identification
- **Reconnaissance Detection**: Port scanning, network enumeration, and information gathering activities
- **Traffic Analysis**: Suspicious communication patterns, abnormal data flows, and behavioral anomalies
- **Real-time Correlation**: Network events automatically correlated with host-based security activities

## Operational Benefits for Security Teams

### Security Operations Center (SOC) Enhancement
This integration provides enterprise-grade security monitoring capabilities suitable for professional security operations. The solution scales from small networks to enterprise environments.

1. **Centralized Security Monitoring**: Single dashboard interface for both network and host-based security events
2. **Automated Threat Intelligence**: Continuous updates from community-driven threat intelligence feeds
3. **Event Correlation Engine**: Network activities automatically correlated with system-level security events
4. **Horizontal Scalability**: Architecture supports deployment across multiple endpoints and network segments
5. **Compliance Support**: Comprehensive security event logging meets audit and regulatory requirements

### Network Security Posture Improvement
The deployment significantly enhances organizational network security through automated monitoring and threat detection. Continuous monitoring provides visibility into previously unmonitored network activities.

- **Real-time Network IDS**: Continuous monitoring of all network traffic passing through monitored interfaces
- **Community Threat Intelligence**: Access to over 44,000 network-based attack signatures from security researchers
- **Structured Event Logging**: JSON-formatted security events enable advanced analytics and automated processing
- **Zero-Touch Detection**: Automated threat identification requires no manual intervention or signature updates

## Future Enhancement Opportunities

### Intrusion Prevention System (IPS) Deployment
The current deployment operates in detection-only mode for safety and learning purposes. Production environments may benefit from active threat blocking capabilities.

```bash
# Configuration changes to enable active threat blocking
sudo nano /etc/suricata/suricata.yaml
# Configure nfqueue mode for real-time packet dropping and threat prevention
```

### Custom Security Rule Development
Organizations can develop specific detection rules tailored to their unique network environment and threat landscape. Custom rules complement community intelligence with organization-specific indicators.

```bash
# Create and maintain organization-specific detection rules
sudo nano /var/lib/suricata/rules/local.rules
# Add custom signatures for internal applications and specific threat indicators
```

### Enhanced Threat Intelligence Integration
Premium threat intelligence feeds and commercial security services can be integrated to provide additional detection capabilities and threat context for security analysts.

- **Commercial Threat Feeds**: Integration with vendor-specific threat intelligence sources
- **Custom IOC Integration**: Automated ingestion of organization-specific indicators of compromise
- **Dynamic Rule Updates**: Automated threat signature updates based on current threat landscape


## Conclusion

Through this project, I successfully demonstrated enterprise-level security monitoring capabilities by integrating Suricata's advanced network intrusion detection with Wazuh's comprehensive SIEM platform. The solution I implemented provides complete network visibility, real-time threat detection, and centralized security event management suitable for production environments requiring robust security monitoring.

**Final Result**: I delivered a fully operational network security monitoring system featuring 44,000+ threat detection rules, sub-second alert response times, and comprehensive dashboard visibility for proactive threat hunting and incident response activities.
