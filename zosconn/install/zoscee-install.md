### IBM z/OS Connect Enterprise Edition installation and configuration.
z/OS CEE installation reference page is [IBM Documentation](https://www.ibm.com/docs/en/zosconnect/3.0?topic=installing)<br>

To install z/OS CEE create installation directory, update permissions and extract z/OS CEE tarball into installation directory.<br>

z/OS CEE configuration consits of z/OS configuration and server.xml file configuration for the Liberty Application Server.<br>
Liberty Application server configuration is modular, each aspect is be configured in it's on configuration file and then included in the main configuration file server.xml.<br>

Create z/OS CEE server, Configure z/OS TLS connection, user authentication, and services for specific subsystems (CICS, MQ, DB2).

#### Create z/OS CEE server.

#### TLS configuration.

- [API Provider Confidentiality and Integrity](https://www.ibm.com/docs/en/zosconnect/3.0?topic=resources-api-provider-confidentiality-integrity)

z/OS
- create RACF keyring [IBM Docs](https://www.ibm.com/docs/en/zosconnect/3.0?topic=integrity-how-configure-tls-connection-racf-key-rings)
- Enterprise trust already in place. Connect enterprise root CA cert to the keyring [IBM Docs](https://www.ibm.com/docs/en/zosconnect/3.0?topic=integrity-how-configure-tls-connection-racf-key-rings)
- create z/OS CEE personal certificate signed by enterprise root CA. [IBM Docs](https://www.ibm.com/docs/en/zosconnect/3.0?topic=integrity-how-configure-tls-connection-racf-key-rings)
- connect z/OS CEE certificate to the keyring. [IBM Docs](https://www.ibm.com/docs/en/zosconnect/3.0?topic=integrity-how-configure-tls-connection-racf-key-rings)

Create JKS keystore to share root ca. This step is optional if enterirpse trust is already in place.
- export z/os Root CA cert to z/OS sequential file [IBM Docs](https://www.ibm.com/docs/en/zosconnect/3.0?topic=integrity-how-configure-tls-connection-racf-key-rings)
- use JKS `keytool` to import CA cert into the jks keystore [IBM Docs](https://www.ibm.com/docs/en/zosconnect/3.0?topic=integrity-how-configure-tls-connection-racf-key-rings)
> `keytool import cert -file ca.pem -alias zosConnectCA -keypass password -keystore clientTrust.jks -storetype jks -storepass password`

HTTP TLS for z/OS CEE:
- set requireSecure attribute to true on the `<zosconnect_zosConnectManager/>`
  >      <zosconnect_zosConnectManager requireSecure="true"/>
- configure keystore and set location to the RACF keyring.
  >      <keyStore id="safkeyringKeyStore" 
  >             location="safkeyring:///Keyring.ZOSCONN"
  >             password="notused" 
  >             type="JCERACFKS"
  >             fileBased="false"
  >             readOnly="true">
  >      </keystore>
- create ssl configuration.
  >       <ssl id="safSSLConfig"
  >           keyStoreRef = "safkeyringKeyStore"
  >           clientAuthentication="false"
  >           securityLevel="HIGH">
  >       </ssl>
- create https endpoint.
  >       <httpEndpoint id="defaultHttpEndpoint" enabled="true" host="*" httpsPort="443">
  >            <sslOptions sslRef="safSSLConfig" sslSessionTimeout="86400s">
  >       </httpEndpoint>
- include TLS configuration in the main server.xml file.

See *http-tls.xml* file for example configuration.

    <?xml version="1.0"?>
    <server>
        <featureManager>
            <feature>zosconnect:zosConnect-2.0</feature>
            <feature>transportSecurity-1.0</feature>
        </featureManager>

        <!--
        requireSecrure - If true, require that requests are sent over HTTPS.
        -->
        <zosconnect_zosConnectManager requireSecure="true"/>

        <!--
        host - IP address, domain name server (DNS) host name with domain name suffix, 
            or just the DNS host name, used by a client to request a resource. 
            Use '*' for all available network interfaces.

        httpsPort - port for client HTTPS connections
        -->
        <httpEndpoint id="defaultHttpEndpoint" enabled="true" host="*" httpsPort="443">
            <!-- 
            sslRef - ssl configuration reference
            sslSessionTimeout - Amount of time to wait for a read or write request to complete on a socket. 
            -->
            <sslOptions sslRef="safSSLConfig" sslSessionTimeout="86400s"/>
        </httpEndpoint>

        <!--
        keyStoreRef - reference to a key store

        clientAuthentication - Whether client authentication is enabled. 

        SecurityLevel - The cipher suite group used by the SSL handshake. 
            HIGH are 3DES and 128 bit and higher ciphers, 
            MEDIUM are DES and 40 bit ciphers, 
            LOW are ciphers without encryption.
        -->
        <ssl id="safSSLConfig"
            keyStoreRef = "safkeyringKeyStore"
            clientAuthentication="false"
            securityLevel="HIGH"
        />

        <!--
        location - point to RACF keyring.
        password - password is required but not used.
        type - keystore type
        -->
        <keyStore id="safkeyringKeyStore"
            location="safkeyring:///Keyring.ZOSCONN"
            password="notused" 
            type="JCERACFKS"
            fileBased="false" 
            readOnly="true">
        </keyStore>
    </server>


#### User authentication with RACF.
Users are authenticated with HTTP basic auth against `RACF`.<br>

- [API Provider Authentication and Identificataion](https://www.ibm.com/docs/en/zosconnect/3.0?topic=resources-api-provider-authentication-identification)
- [Activating and configuring SAF user registry](https://www.ibm.com/docs/en/zosconnect/3.0?topic=resources-api-provider-authentication-identification)

z/OS.
- Configure angel process to enable z/OS CEE access to authorized services. [Configuring the Liberty Angel Process and z/OS authorized processes](https://www.ibm.com/docs/en/zosconnect/3.0?topic=resources-api-provider-authentication-identification)
- Configure `RACF` unauthenticated user id. z/OS CEE default is *WSGUEST*. [SAF unathenticated user id](https://www.ibm.com/docs/en/zosconnect/3.0?topic=registry-saf-unauthenticated-user-id#saf_unauthenticated_id))
- Define the `RACF APPL` profile and grant all `RACF` user ids *READ* access to this profile. [Accessing z/OS security resources using WZSSAD](https://www.ibm.com/docs/en/was-liberty/zos?topic=zos-accessing-security-resources-using-wzssad)
- Grant z/OS server id *READ* access to the `RACF SERVER` profile `BBG.SECPFX.<APPLID>`. [Accessing z/OS security resources using WZSSAD](https://www.ibm.com/docs/en/was-liberty/zos?topic=zos-accessing-security-resources-using-wzssad)

z/OS CEE.
Configure saf user registry:
- require http basic authentication.
> `<webAppSecurity overrideHttpAuthMethod="BASIC"/>`
- configure saf user registry
> `<safRegistry id="saf" />`
- configure saf credentials. `<APPLID>` is `RACF APPL` profile. All *RACF* user ids are granted `READ` access to this profile. z/OS CEE server id is granted *READ* access to the `BBG.SECPFX.<APPLID>` `RACF SERVER` profile. `<APPLID>` profile name is defined by the *profilePrefix* attribute of the `<safCredentials>` element. For z/OS CEE default value for the `APPLID` profile is *BBGZDFLT*. Default unauthenticated user is *WSGUEST*.
> `<safCredentials unauthenticatedUser="WSGUEST" profilePrefix="BBGZDFLT"/>`

See *saf-security.xml* file for example configuration.

#### User authorization with RACF.
z/OS:
- Define `RACF EJBROLE` profile `profilePrefix.zos.connect.access.roles.zosConnectAccess`. [API Provider Authorization](https://www.ibm.com/docs/en/zosconnect/3.0?topic=resources-api-provider-authorization)
- grant users and groups *READ* access to this profile. [zosConnectAccess role with SAF user registry](https://www.ibm.com/docs/en/zosconnect/3.0?topic=role-zosconnectaccess-saf-user-registry)

z/OS CEE server:
- Require authorization check.
> `<zosconnect_zosConnectManager requireAuth="true"/>`

- configure server to use SAF authorization. Check if user has *READ* access to the `profilePrefix.zos.connect.access.roles.zosConnectAccess` profile.
> `<safAuthorization id="saf-authorization"/>`

See *saf-security.xml* file for example configuration.

    <?xml version="1.0"?>
    <server>
        <featureManager>
            <feature>appSecurity-2.0</feature>
            <feature>zosSecurity-1.0</feature>
        </featureManager>

        <!--
        requireAuth - if true, authorization check is performed to ensure that authenticated 
            user id is assigned to the zosConnectAccess role.

        authorization interceptors - check if a user is a member of user registry group
            and group is assigned appropriate authorization level.
        -->
        <zosconnect_zosConnectManager requireAuth="true"/>

        <!--webAppSecurity allowFailOverToBasicAuth="true" /-->
        <webAppSecurity overrideHttpAuthMethod="BASIC"/>

        <!-- use saf registry for authentication -->
        <safRegistry id="saf" />

        <!--
        Check if user is assigned to the zosConnectAccess role.
        Check for the user id READ access to the RACF EJBROLE profile
        <profilePrefix>.zos.connect.access.roles.zosConnectAccess
        For <profilePrefix> see safCredentials element.

        racRouteLog - display saf messages for unauthorized access
        -->
        <safAuthorization id="saf-authorization" racRouteLog="ASIS" />

        <!-- 
        unauthenticatedUser - RACF user id that plays a role of unauthenticated user. 
            Default value is "WSGUEST".

        profilePrefix - RACF APPL profile name. Default value is "BBGZDFLT".
            All RACF user ids (to be authenticated and unauthenticated) are granted READ access to this profile. 
            z/OS CEE server id is granted READ access to the RACF SERVER profile BBG.SECPFX.<profilePrefix>.
        -->
        <safCredentials unauthenticatedUser="WSGUEST" profilePrefix="BBGZDFLT"/>
    </server>