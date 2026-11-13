// Public sample: the example network from the Batfish project (github.com/batfish/batfish,
// networks/example/live/configs), licensed by the Batfish authors under the
// Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0). Included unmodified, fetched November 2026.
// These are real lab configs from a public dataset, not synthetic, and contain no secrets.

export const BATFISH_SOURCE = 'https://github.com/batfish/batfish/tree/master/networks/example/live/configs'

export const BATFISH_FILES: { name: string; text: string }[] = [
  { name: 'as1border1.cfg', text: `
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname as1border1
!
boot-start-marker
boot-end-marker
!
!
!
no aaa new-model
no ip icmp rate-limit unreachable
ip cef
!
!
!
!
!
!
no ip domain lookup
ip domain name lab.local
no ipv6 cef
!
!
multilink bundle-name authenticated
!
!
!
!
!
!
!
!
!
ip tcp synwait-time 5
! 
!
!
!
!
!
!
!
!
!
!
!
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
!
interface Ethernet0/0
 no ip address
 shutdown
 duplex auto
!
interface GigabitEthernet0/0
 ip address 1.0.1.1 255.255.255.0
 media-type gbic
 speed 1000
 duplex full
 negotiation auto
!
interface GigabitEthernet1/0
 ip address 10.12.11.1 255.255.255.0
 negotiation auto
!
router ospf 1
 router-id 1.1.1.1
 redistribute connected subnets
 passive-interface Loopback0
 network 1.0.0.0 0.255.255.255 area 1
!
router bgp 1
 bgp router-id 1.1.1.1
 bgp log-neighbor-changes
 neighbor as1 peer-group
 neighbor as1 remote-as 1
 neighbor as2 peer-group
 neighbor as2 remote-as 2
 neighbor as3 peer-group
 neighbor as3 remote-as 3
 neighbor xanadu peer-group
 neighbor xanadu remote-as 555
 neighbor bad-ebgp peer-group
 neighbor bad-ebgp remote-as 666
 neighbor 1.10.1.1 peer-group as1
 neighbor 1.10.1.1 update-source Loopback0
 neighbor 3.2.2.2 peer-group bad-ebgp
 neighbor 5.6.7.8 peer-group xanadu
 neighbor 10.12.11.2 peer-group as2
 !
 address-family ipv4
  bgp dampening
  bgp additional-paths select all
  bgp additional-paths send receive
  network 1.0.1.0 mask 255.255.255.0
  network 1.0.2.0 mask 255.255.255.0
  neighbor as1 send-community
  neighbor as1 advertise additional-paths all
  neighbor as2 send-community
  neighbor as2 route-map as2_to_as1 in
  neighbor as2 route-map as1_to_as2 out
  neighbor as3 send-community
  neighbor as3 route-map as3_to_as1 in
  neighbor as3 route-map as1_to_as3 out
  neighbor 1.10.1.1 activate
  neighbor 3.2.2.2 activate
  neighbor 5.6.7.8 activate
  neighbor 10.12.11.2 activate
  maximum-paths eibgp 5
 exit-address-family
!
ip forward-protocol nd
!
ip bgp-community new-format
ip community-list expanded as1_community permit _1:
ip community-list expanded as2_community permit _2:
ip community-list expanded as3_community permit _3:
!
no ip http server
no ip http secure-server
!
!
ip prefix-list default_list seq 5 permit 0.0.0.0/0
!
ip prefix-list inbound_route_filter seq 5 deny 1.0.0.0/8 le 32
ip prefix-list inbound_route_filter seq 10 permit 0.0.0.0/0 le 32
access-list 101 permit ip host 1.0.1.0 host 255.255.255.0
access-list 101 permit ip host 1.0.2.0 host 255.255.255.0
access-list 102 permit ip host 2.0.0.0 host 255.0.0.0
access-list 102 permit ip host 2.128.0.0 host 255.255.0.0
access-list 103 permit ip host 3.0.1.0 host 255.255.255.0
access-list 103 permit ip host 3.0.2.0 host 255.255.255.0
!
route-map as1_to_as2 permit 1
 match ip address 101
 set metric 50
 set community 1:2 additive
!
route-map as1_to_as2 permit 3
 match ip address 103
 set metric 50
 set community 1:2 additive
!
route-map as1_to_as2 permit 5
 match ip address prefix-list default_list
 set metric 50
 set community 1:2 additive
!
route-map as2_to_as1 permit 100
 match community as2_community
 set local-preference 350
!
route-map as1_to_as3 permit 1
 match ip address 101
 set metric 50
 set community 1:3 additive
!
route-map as1_to_as3 permit 2
 match ip address 102
 set metric 50
 set community 1:3 additive
!
route-map as3_to_as1 permit 100
 match community as3_community
 set local-preference 350
!
!
!
control-plane
!
!
line con 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line aux 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line vty 0 4
 login
!
!
end
` },
  { name: 'as2border1.cfg', text: `
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname as2border1
!
boot-start-marker
boot-end-marker
!
!
ntp server 18.18.18.18
ntp server 23.23.23.23
!
!
no aaa new-model
no ip icmp rate-limit unreachable
ip cef
!
!
!
!
!
!
no ip domain lookup
ip domain name lab.local
no ipv6 cef
!
aaa new-model
aaa authentication login privilege-mode
!
multilink bundle-name authenticated
!
!
!
!
!
!
!
!
!
ip tcp synwait-time 5
! 
!
!
!
!
!
!
!
!
!
!
!
interface Loopback0
 ip address 2.1.1.1 255.255.255.255
!
interface Ethernet0/0
 no ip address
 shutdown
 duplex auto
!
interface GigabitEthernet0/0
 ip address 10.12.11.2 255.255.255.0
 ip access-group OUTSIDE_TO_INSIDE in
 ip access-group INSIDE_TO_AS1 out
 media-type gbic
 speed 1000
 duplex full
 negotiation auto
!
interface GigabitEthernet1/0
 ip address 2.12.11.1 255.255.255.0
 negotiation auto
!
interface GigabitEthernet2/0
 ip address 2.12.12.1 255.255.255.0
 negotiation auto
!
router ospf 1
 router-id 2.1.1.1
 redistribute connected subnets
 network 2.0.0.0 0.255.255.255 area 1
!
router bgp 2
 bgp router-id 2.1.1.1
 bgp log-neighbor-changes
 neighbor as1 peer-group
 neighbor as1 remote-as 1
 neighbor as2 peer-group
 neighbor as2 remote-as 2
 neighbor as3 peer-group
 neighbor as3 remote-as 3
 neighbor 2.1.2.1 peer-group as2
 neighbor 2.1.2.1 update-source Loopback0
 neighbor 2.1.2.2 peer-group as2
 neighbor 2.1.2.2 update-source Loopback0
 neighbor 10.12.11.1 peer-group as1
 !
 address-family ipv4
  bgp dampening
  bgp additional-paths select all
  bgp additional-paths send receive
  aggregate-address 2.128.0.0 255.255.0.0 summary-only
  neighbor as1 send-community
  neighbor as1 route-map as1_to_as2 in
  neighbor as1 route-map as2_to_as1 out
  neighbor as2 send-community
  neighbor as2 advertise additional-paths all
  neighbor as3 send-community
  neighbor as3 route-map as3_to_as2 in
  neighbor as3 route-map as2_to_as3 out
  neighbor 2.1.2.1 activate
  neighbor 2.1.2.2 activate
  neighbor 10.12.11.1 activate
  maximum-paths eibgp 5
 exit-address-family
!
ip forward-protocol nd
!
ip bgp-community new-format
ip community-list expanded as1_community permit _1:
ip community-list expanded as2_community permit _2:
ip community-list expanded as3_community permit _3:
!
no ip http server
no ip http secure-server
!
ip access-list extended INSIDE_TO_AS1
 permit ip 2.0.0.0 0.255.255.255 1.0.0.0 0.255.255.255
 permit ip 10.12.11.2 0.0.0.0 10.12.11.1 0.0.0.0 
 deny   ip any any
ip access-list extended OUTSIDE_TO_INSIDE
 deny   ip 2.0.0.0 0.255.255.255 any
 deny   ip any host 2.128.1.101
 permit ip any any
!
!
ip prefix-list inbound_route_filter seq 5 deny 2.0.0.0/8 le 32
ip prefix-list inbound_route_filter seq 10 permit 0.0.0.0/0 le 32
!
ip prefix-list outbound_routes seq 5 permit 2.128.0.0/9 ge 16
access-list 101 permit ip host 1.0.1.0 host 255.255.255.0
access-list 101 permit ip host 1.0.2.0 host 255.255.255.0
access-list 103 permit ip host 3.0.1.0 host 255.255.255.0
access-list 103 permit ip host 3.0.2.0 host 255.255.255.0
!
route-map as2_to_as1 permit 2
 match ip address prefix-list outbound_routes
 set metric 50
 set community 2:1 additive
!
route-map as2_to_as1 permit 3
 match ip address 103
 set metric 50
 set community 2:1 additive
!
route-map as1_to_as2 permit 100
 match community as1_community
 set local-preference 350
 set community 1:2 additive
!
route-map as2_to_as3 permit 1
 match ip address 101
 set metric 50
 set community 2:3 additive
!
route-map as2_to_as3 permit 2
 match ip address prefix-list outbound_routes
 set metric 50
 set community 2:3 additive
!
route-map as3_to_as2 permit 100
 match community as3_community
 set local-preference 350
 set community 3:2 additive
!
!
!
control-plane
!
!
line con 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line aux 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line vty 0 4
 login
!
!
end
` },
  { name: 'as2core1.cfg', text: `
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname as2core1
!
boot-start-marker
boot-end-marker
!
!
logging host 1.1.1.1
logging host 2.1.2.2
!
!
no aaa new-model
no ip icmp rate-limit unreachable
ip cef
!
!
!
!
!
!
no ip domain lookup
ip domain name lab.local
no ipv6 cef
!
!
multilink bundle-name authenticated
!
!
!
!
!
!
!
!
!
ip tcp synwait-time 5
! 
!
!
!
!
!
!
!
!
!
!
!
interface Loopback0
 ip address 2.1.2.1 255.255.255.255
!
interface Ethernet0/0
 no ip address
 shutdown
 duplex auto
!
interface GigabitEthernet0/0
 ip address 2.12.11.2 255.255.255.0
 media-type gbic
 speed 1000
 duplex full
 negotiation auto
!
interface GigabitEthernet1/0
 ip address 2.12.21.2 255.255.255.0
 negotiation auto
!
interface GigabitEthernet2/0
 ip address 2.23.11.2 255.255.255.0
 ip access-group blocktelnet in
 negotiation auto
!
interface GigabitEthernet3/0
 ip address 2.23.12.2 255.255.255.0
 ip access-group blocktelnet in
 negotiation auto
!
router ospf 1
 router-id 2.1.2.1
 network 2.0.0.0 0.255.255.255 area 1
!
router bgp 2
 bgp router-id 2.1.2.1
 bgp log-neighbor-changes
 neighbor as2 peer-group
 neighbor as2 remote-as 2
 neighbor 2.1.1.1 peer-group as2
 neighbor 2.1.1.1 update-source Loopback0
 neighbor 2.1.1.2 peer-group as2
 neighbor 2.1.1.2 update-source Loopback0
 neighbor 2.1.3.1 peer-group as2
 neighbor 2.1.3.1 update-source Loopback0
 neighbor 2.1.3.2 peer-group as2
 neighbor 2.1.3.2 update-source Loopback0
 !
 address-family ipv4
  bgp dampening
  bgp additional-paths select all
  bgp additional-paths send receive
  neighbor as2 send-community
  neighbor as2 route-reflector-client
  neighbor as2 advertise additional-paths all
  neighbor 2.1.1.1 activate
  neighbor 2.1.1.2 activate
  neighbor 2.1.3.1 activate
  neighbor 2.1.3.2 activate
  maximum-paths eibgp 5
 exit-address-family
!
ip forward-protocol nd
!
!
no ip http server
no ip http secure-server
!
ip access-list extended blocktelnet
 deny   tcp any any eq telnet
 permit ip any any
!
!
!
!
control-plane
!
!
line con 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line aux 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line vty 0 4
 login
!
!
end
` },
  { name: 'as2dept1.cfg', text: `
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname as2dept1
!
boot-start-marker
boot-end-marker
!
!
!
no aaa new-model
no ip icmp rate-limit unreachable
ip cef
!
!
!
!
!
!
no ip domain lookup
ip domain name lab.local
no ipv6 cef
!
!
multilink bundle-name authenticated
!
!
!
!
!
!
!
!
!
ip tcp synwait-time 5
! 
!
!
!
!
!
!
!
!
!
!
!
interface Loopback0
 ip address 2.1.1.2 255.255.255.255
!
interface Ethernet0/0
 no ip address
 shutdown
 duplex auto
!
interface GigabitEthernet0/0
 ip address 2.34.101.4 255.255.255.0
 media-type gbic
 speed 1000
 duplex full
 negotiation auto
!
interface GigabitEthernet1/0
 ip address 2.34.201.4 255.255.255.0
 negotiation auto
!
interface GigabitEthernet2/0
 ip address 2.128.0.1 255.255.255.0
 ip access-group RESTRICT_HOST_TRAFFIC_IN in
 negotiation auto
!
interface GigabitEthernet3/0
 ip address 2.128.1.1 255.255.255.0
 ip access-group RESTRICT_HOST_TRAFFIC_IN in
 negotiation auto
!
router bgp 65001
 bgp router-id 2.1.4.1
 bgp log-neighbor-changes
 neighbor as2 peer-group
 neighbor as2 remote-as 2
 neighbor 2.34.101.3 peer-group as2
 neighbor 2.34.201.3 peer-group as2
 !
 address-family ipv4
  bgp dampening
  bgp additional-paths select all
  bgp additional-paths send receive
  network 2.128.0.0 mask 255.255.255.0
  network 2.128.1.0 mask 255.255.255.0
  neighbor as2 send-community
  neighbor as2 route-map as2_to_dept in
  neighbor as2 route-map dept_to_as2 out
  neighbor 2.34.101.3 activate
  neighbor 2.34.201.3 activate
  maximum-paths eibgp 5
 exit-address-family
!
ip forward-protocol nd
!
ip bgp-community new-format
ip community-list expanded as2_community permit _2:
!
no ip http server
no ip http secure-server
!
ip access-list extended RESTRICT_HOST_TRAFFIC_IN
 permit ip 2.128.0.0 0.0.255.255 any
 deny   ip any any
 permit icmp any any
ip access-list extended RESTRICT_HOST_TRAFFIC_OUT
 permit ip any 2.128.0.0 0.0.255.255
 deny   ip 1.128.0.0 0.0.255.255 2.128.0.0 0.0.255.255
 deny   ip any any
!
access-list 102 permit ip host 2.128.0.0 host 255.255.255.0
access-list 102 permit ip host 2.128.1.0 host 255.255.255.0
access-list 105 permit ip host 1.0.1.0 host 255.255.255.0
access-list 105 permit ip host 1.0.2.0 host 255.255.255.0
access-list 105 permit ip host 3.0.1.0 host 255.255.255.0
access-list 105 permit ip host 3.0.2.0 host 255.255.255.0
!
route-map dept_to_as2 permit 100
 match ip address 102
 set metric 50
 set community 65001:2 additive
!
route-map as2_to_dept permit 100
 match community as2_community
 set local-preference 350
!
!
!
control-plane
!
!
line con 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line aux 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line vty 0 4
 login
!
!
end
` },
  { name: 'as2dist1.cfg', text: `
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname as2dist1
!
boot-start-marker
boot-end-marker
!
!
!
no aaa new-model
no ip icmp rate-limit unreachable
ip cef
!
!
!
!
!
!
no ip domain lookup
ip domain name lab.local
no ipv6 cef
!
!
multilink bundle-name authenticated
!
!
!
!
!
!
!
!
!
ip tcp synwait-time 5
! 
!
!
!
!
!
!
!
!
!
!
!
interface Loopback0
 ip address 2.1.3.1 255.255.255.255
!
interface Ethernet0/0
 no ip address
 shutdown
 duplex auto
!
interface GigabitEthernet0/0
 ip address 2.23.11.3 255.255.255.0
 media-type gbic
 speed 1000
 duplex full
 negotiation auto
!
interface GigabitEthernet1/0
 ip address 2.23.21.3 255.255.255.0
 negotiation auto
!
interface GigabitEthernet2/0
 ip address 2.34.101.3 255.255.255.0
 negotiation auto
!
router ospf 1
 router-id 2.1.3.1
 redistribute connected subnets
 network 2.1.0.0 0.0.255.255 area 1
 network 2.23.0.0 0.0.255.255 area 1
!
router bgp 2
 bgp router-id 2.1.3.1
 bgp log-neighbor-changes
 neighbor as2 peer-group
 neighbor as2 remote-as 2
 neighbor dept peer-group
 neighbor dept remote-as 65001
 neighbor 2.1.2.1 peer-group as2
 neighbor 2.1.2.1 update-source Loopback0
 neighbor 2.1.2.2 peer-group as2
 neighbor 2.1.2.2 update-source Loopback0
 neighbor 2.34.101.4 peer-group dept
 !
 address-family ipv4
  bgp dampening
  bgp additional-paths select all
  bgp additional-paths send receive
  neighbor as2 send-community
  neighbor as2 advertise additional-paths all
  neighbor dept send-community
  neighbor dept route-map dept_to_as2dist in
  neighbor dept route-map as2dist_to_dept out
  neighbor 2.1.2.1 activate
  neighbor 2.1.2.2 activate
  neighbor 2.34.101.4 activate
  maximum-paths eibgp 5
 exit-address-family
!
ip forward-protocol nd
!
ip bgp-community new-format
ip community-list expanded dept_community permit _65001:
!
no ip http server
no ip http secure-server
!
access-list 102 permit ip host 2.128.0.0 host 255.255.0.0
access-list 105 permit ip host 1.0.1.0 host 255.255.255.0
access-list 105 permit ip host 1.0.2.0 host 255.255.255.0
access-list 105 permit ip host 3.0.1.0 host 255.255.255.0
access-list 105 permit ip host 3.0.2.0 host 255.255.255.0
!
route-map as2dist_to_dept permit 100
 match ip address 105
 set metric 50
 set community 2:65001 additive
!
route-map dept_to_as2dist permit 100
 match community dept_community
 set local-preference 350
!
!
!
control-plane
!
!
line con 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line aux 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line vty 0 4
 login
!
!
end
` },
  { name: 'as3border1.cfg', text: `
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname as3border1
!
boot-start-marker
boot-end-marker
!
!
ntp server 18.18.18.18
ntp server 23.23.23.23
!
!
no aaa new-model
no ip icmp rate-limit unreachable
ip cef
!
!
!
!
!
!
no ip domain lookup
ip domain name lab.local
no ipv6 cef
!
!
multilink bundle-name authenticated
!
!
!
!
!
!
!
!
!
ip tcp synwait-time 5
! 
!
!
!
!
!
!
!
!
!
!
!
interface Loopback0
 ip address 3.1.1.1 255.255.255.255
!
interface Ethernet0/0
 no ip address
 shutdown
 duplex auto
!
interface GigabitEthernet0/0
 ip address 3.0.1.1 255.255.255.0
 media-type gbic
 speed 1000
 duplex full
 negotiation auto
!
interface GigabitEthernet1/0
 ip address 10.23.21.3 255.255.255.0
 negotiation auto
!
router ospf 1
 router-id 3.1.1.1
 redistribute connected subnets
 network 3.0.0.0 0.255.255.255 area 1
!
router bgp 3
 bgp router-id 3.1.1.1
 bgp log-neighbor-changes
 neighbor as1 peer-group
 neighbor as1 remote-as 1
 neighbor as2 peer-group
 neighbor as2 remote-as 2
 neighbor as3 peer-group
 neighbor as3 remote-as 3
 neighbor 3.10.1.1 peer-group as3
 neighbor 3.10.1.1 update-source Loopback0
 neighbor 10.23.21.2 peer-group as2
 !
 address-family ipv4
  bgp dampening
  bgp additional-paths select all
  bgp additional-paths send receive
  network 3.0.1.0 mask 255.255.255.0
  network 3.0.2.0 mask 255.255.255.0
  neighbor as1 send-community
  neighbor as1 route-map as1_to_as3 in
  neighbor as1 route-map as3_to_as1 out
  neighbor as2 send-community
  neighbor as2 route-map as2_to_as3 in
  neighbor as2 route-map as3_to_as2 out
  neighbor as3 send-community
  neighbor as3 advertise additional-paths all
  neighbor 3.10.1.1 activate
  neighbor 10.23.21.2 activate
  maximum-paths eibgp 5
 exit-address-family
!
ip forward-protocol nd
!
ip bgp-community new-format
ip community-list expanded as1_community permit _1:
ip community-list expanded as2_community permit _2:
ip community-list expanded as3_community permit _3:
!
no ip http server
no ip http secure-server
!
!
ip prefix-list default_list seq 5 permit 0.0.0.0/0
!
ip prefix-list inbound_route_filter seq 5 deny 3.0.0.0/8 le 32
ip prefix-list inbound_route_filter seq 10 permit 0.0.0.0/0 le 32
access-list 101 permit ip host 1.0.1.0 host 255.255.255.0
access-list 101 permit ip host 1.0.2.0 host 255.255.255.0
access-list 102 permit ip host 2.0.0.0 host 255.0.0.0
access-list 102 permit ip host 2.128.0.0 host 255.255.0.0
access-list 103 permit ip host 3.0.1.0 host 255.255.255.0
access-list 103 permit ip host 3.0.2.0 host 255.255.255.0
!
route-map as3_to_as1 permit 2
 match ip address 102
 set metric 50
 set community 3:1 additive
!
route-map as3_to_as1 permit 3
 match ip address 103
 set metric 50
 set community 3:1 additive
!
route-map as1_to_as3 permit 100
 match community as1_community
 set local-preference 350
!
route-map as3_to_as2 permit 1
 match ip address 101
 set metric 50
 set community 3:2 additive
!
route-map as3_to_as2 permit 3
 match ip address 103
 set metric 50
 set community 3:2 additive
!
route-map as3_to_as2 permit 5
 match ip address prefix-list default_list
 set metric 50
 set community 3:2 additive
!
route-map as2_to_as3 permit 100
 match community as2_community
 set local-preference 350
!
!
!
control-plane
!
!
line con 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line aux 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
 stopbits 1
line vty 0 4
 login
!
!
end
` },
]
