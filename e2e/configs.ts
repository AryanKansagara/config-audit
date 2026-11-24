// Synthetic configs for the import tests (RFC 5737 / RFC 1918 addresses, made-up hostnames).
// Every secret value contains "Sentinel" or is listed in SECRETS so tests can prove it is never stored or shown.

export const pasted = (host: string, tag: string) => `Building configuration...

Current configuration : 1432 bytes
!
version 15.7
service timestamps log datetime msec
!
hostname ${host}
!
enable secret 5 $1$e2e0$Sentinel${tag}EnableHash
username e2eadmin privilege 15 password 0 Sentinel${tag}UserPass
username e2eops privilege 7 password 7 0822455D0A16
!
aaa new-model
tacacs-server host 192.0.2.10 key Sentinel${tag}TacacsKey
!
interface GigabitEthernet0/0
 description uplink
 ip address 192.0.2.2 255.255.255.0
!
ip http server
!
snmp-server community Sentinel${tag}Community RO
!
line con 0
 exec-timeout 0 0
line vty 0 4
 password Sentinel${tag}VtyPass
 login
 transport input telnet
!
end
`

/** Values that must never appear in stored data, page text or downloads after import. */
export const secretsOf = (tag: string) => [`Sentinel${tag}EnableHash`, `Sentinel${tag}UserPass`, `Sentinel${tag}TacacsKey`, `Sentinel${tag}Community`, `Sentinel${tag}VtyPass`, '0822455D0A16']
