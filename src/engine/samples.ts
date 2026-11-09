// Three synthetic devices. Every address is RFC 1918 or RFC 5737 documentation space; every
// secret is fake. They are labelled synthetic everywhere they appear in the app.

export interface Sample { id: string; name: string; blurb: string; files: { name: string; text: string }[]; previous?: { name: string; text: string }[] }

export const BRANCH = `Building configuration...

Current configuration : 4211 bytes
!
! Synthetic sample config for Config Audit. Not a real device.
!
version 15.7
service timestamps debug datetime msec
service timestamps log uptime
no service password-encryption
!
hostname BR-RTR-01
!
boot-start-marker
boot-end-marker
!
logging buffered 16384
enable password 7 0822455D0A16
!
no aaa new-model
clock timezone EST -5 0
!
ip domain name branch.example.net
ip dhcp excluded-address 10.10.10.1 10.10.10.20
!
ip dhcp pool USERS
 network 10.10.10.0 255.255.255.0
 default-router 10.10.10.1
 dns-server 192.0.2.53
!
username netadmin privilege 15 password 7 13061E010803
username helpdesk password 0 Branch123
!
interface GigabitEthernet0/0
 description ISP uplink (Metro Ethernet)
 ip address 203.0.113.2 255.255.255.252
 ip nat outside
 duplex auto
 speed auto
!
interface GigabitEthernet0/1
 description LAN users
 ip address 10.10.10.1 255.255.255.0
 ip nat inside
 ip directed-broadcast
!
interface GigabitEthernet0/2
 no ip address
!
interface GigabitEthernet0/3
 no ip address
 shutdown
!
ip forward-protocol nd
ip http server
ip http secure-server
!
ip nat inside source list NAT-USERS interface GigabitEthernet0/0 overload
ip route 0.0.0.0 0.0.0.0 203.0.113.1
!
ip access-list standard NAT-USERS
 permit 10.10.10.0 0.0.0.255
!
ip access-list extended OLD-GUEST
 permit tcp 10.10.99.0 0.0.0.255 any eq www
 permit tcp 10.10.99.0 0.0.0.255 any eq 443
 deny   ip any any
!
snmp-server community public RO
snmp-server community br4nchRW RW
snmp-server location Branch 12, 2nd floor IDF
!
banner motd ^C
Welcome to BR-RTR-01
^C
!
line con 0
 exec-timeout 0 0
 password 7 104D000A0618
 login
line aux 0
line vty 0 4
 password 7 02050D480809
 login
 transport input telnet ssh
line vty 5 15
 password 7 02050D480809
 login
!
end
`

export const CORE = `!
! Synthetic sample config for Config Audit. Not a real device.
!
version 17.9
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service password-encryption
no service pad
!
hostname CORE-SW-01
!
logging buffered 64000 informational
logging trap informational
logging host 10.0.50.20
enable secret 5 $1$Xq7e$Wb2HnY1mJz2rQk3pA6vLs1
!
aaa new-model
aaa authentication login default group tacacs+ local
aaa authentication enable default group tacacs+ enable
aaa authorization exec default group tacacs+ local if-authenticated
aaa accounting exec default start-stop group tacacs+
aaa accounting commands 15 default start-stop group tacacs+
!
clock timezone EST -5 0
ip domain name core.example.net
ip name-server 10.0.50.53
no ip source-route
!
login block-for 120 attempts 5 within 60
!
username breakglass privilege 15 secret 9 $9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM
!
vlan 10
 name USERS
vlan 20
 name VOICE
vlan 30
 name SERVERS
vlan 99
 name MGMT
!
interface Port-channel1
 description Uplink to EDGE-RTR-01
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30,99
!
interface TenGigabitEthernet1/0/1
 description Uplink to EDGE-RTR-01 member 1
 switchport mode trunk
 channel-group 1 mode active
!
interface TenGigabitEthernet1/0/2
 description Uplink to EDGE-RTR-01 member 2
 switchport mode trunk
 channel-group 1 mode active
!
interface GigabitEthernet1/0/1
 description Server farm A
 switchport access vlan 30
 switchport mode access
!
interface GigabitEthernet1/0/2
 description Printer room
 switchport mode access
!
interface GigabitEthernet1/0/3
!
interface GigabitEthernet1/0/4
 shutdown
!
interface Vlan10
 description Users SVI
 ip address 10.20.10.1 255.255.255.0
 no ip proxy-arp
!
interface Vlan30
 description Servers SVI
 ip address 10.30.1.1 255.255.255.0
 ip access-group SERVERS-IN out
 no ip proxy-arp
!
interface Vlan99
 description Management
 ip address 10.0.99.2 255.255.255.0
 no ip proxy-arp
!
router ospf 10
 router-id 10.0.99.2
 network 10.20.10.0 0.0.0.255 area 0
 network 10.30.1.0 0.0.0.255 area 0
 network 10.0.99.0 0.0.0.255 area 0
 passive-interface Vlan10
!
object-group network APP-SERVERS
 host 10.30.1.10
 host 10.30.1.11
!
object-group network LEGACY-NMS
 host 10.0.50.99
!
ip access-list standard MGMT-VTY
 permit 10.0.99.0 0.0.0.255
 deny   any log
ip access-list standard SNMP-RO
 permit 10.0.50.0 0.0.0.255
!
ip access-list extended SERVERS-IN
 10 permit tcp 10.20.0.0 0.0.255.255 host 10.30.1.10 eq 443
 20 deny tcp 10.20.5.0 0.0.0.255 host 10.30.1.10 eq 443
 30 permit tcp 10.20.0.0 0.0.127.255 10.30.1.0 0.0.0.255 eq 22
 40 permit tcp 10.20.128.0 0.0.127.255 10.30.1.0 0.0.0.255 eq 22
 50 deny tcp 10.20.0.0 0.0.255.255 host 10.30.1.20 eq 22
 60 permit udp any host 10.30.1.53 eq domain
 70 permit udp 10.0.0.0 0.255.255.255 host 10.30.1.53 eq 53
 80 permit tcp any object-group APP-SERVERS range 8000 8099
 90 permit icmp any any echo
 100 deny ip any any log
!
ip access-list extended TEMP-MIGRATION
 10 permit ip any any
!
ip http secure-server
ip http access-class ipv4 MGMT-VTY
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
snmp-server community c0re-R0-n8vG2 RO SNMP-RO
!
tacacs server ISE-1
 address ipv4 10.0.50.10
 key 7 060506324F41584B56
!
ntp server 10.0.50.123
ntp server 10.0.50.124
!
banner login ^C
Authorized access only. Activity on this device is logged and monitored.
^C
!
line con 0
 exec-timeout 0 0
line vty 0 4
 access-class MGMT-VTY in
 exec-timeout 10 0
 transport input ssh
line vty 5 15
 access-class MGMT-VTY in
 exec-timeout 10 0
 transport input ssh
!
end
`

export const EDGE = `!
! Synthetic sample config for Config Audit. Not a real device.
!
version 17.12
service tcp-keepalives-in
service tcp-keepalives-out
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service password-encryption
no service pad
!
hostname EDGE-RTR-01
!
logging buffered 64000 informational
logging trap informational
logging host 10.0.50.20
logging host 10.0.50.21
enable secret 9 $9$4Ksk1Y0Jw9mJ8U$vMBY6EHmDbMtM1zA0R1Q.8yQx3dz5r9TG8sVKpXK5bE
!
aaa new-model
aaa authentication login default group tacacs+ local
aaa authentication enable default group tacacs+ enable
aaa authorization exec default group tacacs+ local if-authenticated
aaa accounting exec default start-stop group tacacs+
aaa accounting commands 15 default start-stop group tacacs+
!
clock timezone EST -5 0
ip domain name core.example.net
ip name-server 10.0.50.53
no ip source-route
no ip bootp server
!
login block-for 120 attempts 5 within 60
login on-failure log
!
username breakglass privilege 15 secret 9 $9$3Fq9VbKx0mT2pL$GZ4rJ1uX8YnHq0aWc5eS7dV2kQ9pL3mN6bT1rY8xC0Z
!
archive
 log config
  logging enable
  notify syslog contenttype plaintext
  hidekeys
!
interface Loopback0
 ip address 10.0.0.1 255.255.255.255
!
interface GigabitEthernet0/0/0
 description Transit: ISP-A (circuit 7781)
 ip address 198.51.100.2 255.255.255.252
 ip access-group EDGE-IN in
 no ip redirects
 no ip unreachables
 no ip proxy-arp
 ip verify unicast source reachable-via rx
 no cdp enable
!
interface GigabitEthernet0/0/1
 description Transit: ISP-B (circuit 4410)
 ip address 192.0.2.2 255.255.255.252
 ip access-group EDGE-IN in
 no ip redirects
 no ip unreachables
 no ip proxy-arp
 no cdp enable
!
interface GigabitEthernet0/0/2
 description Downlink to CORE-SW-01
 ip address 10.0.1.1 255.255.255.252
 no ip proxy-arp
 ip ospf message-digest-key 1 md5 7 0822455D0A165C0A1B
!
interface GigabitEthernet0/0/3
 description UNUSED
 no ip address
 shutdown
!
router ospf 10
 router-id 10.0.0.1
 area 0 authentication message-digest
 network 10.0.1.0 0.0.0.3 area 0
 default-information originate
!
router bgp 64512
 bgp log-neighbor-changes
 neighbor 198.51.100.1 remote-as 64496
 neighbor 198.51.100.1 password 7 1511021F07257A767B
 neighbor 192.0.2.1 remote-as 64497
 !
 address-family ipv4
  network 10.0.0.0 mask 255.255.0.0
  neighbor 198.51.100.1 activate
  neighbor 192.0.2.1 activate
 exit-address-family
!
ip route 10.0.0.0 255.255.0.0 Null0
!
ip access-list standard MGMT-VTY
 permit 10.0.99.0 0.0.0.255
 deny   any log
!
ip access-list extended EDGE-IN
 10 deny ip 10.0.0.0 0.255.255.255 any
 20 deny ip 172.16.0.0 0.15.255.255 any
 30 deny ip 192.168.0.0 0.0.255.255 any
 40 deny ip 127.0.0.0 0.255.255.255 any
 50 permit tcp host 198.51.100.1 host 198.51.100.2 eq bgp
 60 permit tcp host 192.0.2.1 host 192.0.2.2 eq bgp
 70 permit tcp any any established
 80 permit icmp any any unreachable
 90 permit icmp any any time-exceeded
 100 deny ip any any log
!
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
snmp-server group NETOPS v3 priv access MGMT-VTY
!
tacacs server ISE-1
 address ipv4 10.0.50.10
 key 6 FHCReZcGgSAKaJSYQKAOHJZNbBCRKJAAB
!
ntp authentication-key 1 md5 104D000A061843595F 7
ntp authenticate
ntp trusted-key 1
ntp server 10.0.50.123 key 1
ntp server 10.0.50.124 key 1
ntp access-group peer NTP-PEERS
!
ip access-list standard NTP-PEERS
 permit host 10.0.50.123
 permit host 10.0.50.124
!
banner login ^C
Authorized access only. Activity on this device is logged and monitored.
^C
!
line con 0
 exec-timeout 5 0
 logging synchronous
line aux 0
 no exec
 transport input none
line vty 0 4
 access-class MGMT-VTY in
 exec-timeout 10 0
 transport input ssh
line vty 5 15
 access-class MGMT-VTY in
 exec-timeout 10 0
 transport input ssh
!
end
`

/** An older capture of the branch router, so the History tab has something to compare against. */
export const BRANCH_OLD = BRANCH
  .replace('logging buffered 16384\n', '')
  .replace(' transport input telnet ssh\n', ' transport input all\n')
  .replace('ip http server\n', 'ip http server\nservice tcp-small-servers\n')

export const SAMPLES: Sample[] = [
  {
    id: 'fleet', name: 'Three-device fleet', blurb: 'A branch router with telnet and type 7 passwords, a core switch with a shadowed ACL, and a mostly hardened edge router.',
    files: [{ name: 'BR-RTR-01.cfg', text: BRANCH }, { name: 'CORE-SW-01.cfg', text: CORE }, { name: 'EDGE-RTR-01.cfg', text: EDGE }],
    previous: [{ name: 'BR-RTR-01.cfg', text: BRANCH_OLD }, { name: 'CORE-SW-01.cfg', text: CORE.replace(' 70 permit udp 10.0.0.0 0.255.255.255 host 10.30.1.53 eq 53\n', '') }, { name: 'EDGE-RTR-01.cfg', text: EDGE.replace(' neighbor 198.51.100.1 password 7 1511021F07257A767B\n', '') }],
  },
]
