### IBM z/OS Connect Enterprise Edition installation and configuration.
[z/OS CEE install](https://www.ibm.com/docs/en/zosconnect/3.0?topic=installing)

Follow [Insalling z/OS CEE](https://www.ibm.com/docs/en/zosconnect/3.0?topic=installing-zos-connect-ee) subsection to install z/OS CEE.

- Create shared directory [IBM Doc](https://www.ibm.com/docs/en/zosconnect/3.0?topic=ee-creating-shared-directory)
- Setup product extensions directory [IBM Doc](https://www.ibm.com/docs/en/zosconnect/3.0?topic=ee-creating-shared-directory)

user directories:
```
  +- /var/zosconnect               wlp.user.dir         User directory, default "/var/zosconnect"`, create this directory.
  |  +- v3r0/extensions                                 zoscee extentions directory, created with `zosconsetup install`
  |  +- shared/
  |  |  +- jvm.options                                  Server JVM options (optional: merged with server specific jvm.options)
  |  |  +- server.env                                   Server script envrionment variables
  |  |  +- apps/                   shared.app.dir       Shared applications
  |  |  +- config/                 shared.config.dir    Shared server configuration files
  |  |  +- resources/              shared.resource.dir  Shared resource definitions: adapters, data sources
  |  +- servers/
  |  |  +- <serverName>         ** server.config.dir    Server configuration directory
  |  |  |                          wlp.server.name      The name of the server is the directory name
  |  |  |  +- bootstrap.properties                      Server bootstrap properties (optional)
  |  |  |  +- jvm.options                               Server JVM options (optional: replaces wlp/etc/jvm.options)
  |  |  |  +- server.env                                Server script environment variables
  |  |  |  +- server.xml                                Server configuration file (required)
  |  |  |  +- apps/                                     Server's configured applications directory
  |  |  |  |  +- <application.type>                     Application directory or archive
  |  |  |  +- dropins                                   Server's default application dropins directory
  |  |  |  |  +- <application.type>                     Application directory or archive
  |  |  +- <serverName>         ** server.output.dir    Server output directory: logs and workarea
  |  |  |  +- logs                                      Server's logs directory (including FFDC logs)
  |  |  |  |  +- state                                  Files that contain information about the runtime state
  |  |  |  +- workarea                                  Server's workarea directory
```

installation directories:
```
  /usr/lpp/IBM/zosconnect/v3r0/    wlp.install.dir      Root of WebSphere Liberty installation
  +- bin/                                               Liberty scripts, "zonsonsetup", "server", etc
  +- clients/                                           Liberty client and thin client libraries
  +- dev/                                               Root for developer resources (APIs, SPIs, specifications, and tools)
  +- etc/                                               User customizations (optional: settings apply to all servers)
  |  +- server.env                                      Default server script environment variables (optional)
  |  +- jvm.options                                     Default JVM options (optional)
  +- lib/                                               Platform runtime (internal)
  +- templates/                                         Runtime customization templates and examples
  |  +- servers/                                        Server configuration templates
  +- wlp/etc/extensions	                                Symlink to "/var/zosconnect/v3r0/extensions"
```

#### Create z/OS CEE server.
[IBM Doc](https://www.ibm.com/docs/en/zosconnect/3.0?topic=configuring-creating-zos-connect-ee-server)

Create zoscee server.<br/>
```
WLP_INSTALL_DIR=/usr/lpp/IBM/zosconnect/v3r0
WLP_USER_DIR=/var/zosconnect
$WLP_INSTALL_DIR/bin/zosconnect create server1 --template=zosconnect:default
Server created in $WLP_USER_DIR/servers/server1
```

### Start z/OS CEE server.
[Starting and Stopping z/OS CEE](https://www.ibm.com/docs/en/zosconnect/3.0?topic=operating-starting-stopping-zos-connect-ee)

Setup a started task to run z/OS CEE.

#### z/OS CEE server configuration.
Z/OS CEE server is Liberty Profile Application Server and allows modular configuration.<br>

Create configuration files for each subsystem and include them into main server.xml file.

    <?xml version="1.0"?>
    <server>
      <featureManager>
        <feature>zosconnect:zosConnect-2.0</feature>
      </featureManager>

      <include location="cors.xml"/>
      <include location="http-tls.xml"/>
      <include location="saf-security.xml"/>
      <include location="cics-ipic.xml"/>
      <include location="mq.xml"/>

    </server>

See server.xml file for example configuration.

### CORS 
- [Enable CORS](https://www.ibm.com/docs/en/zosconnect/3.0?topic=configuring-cors)


    <cors id="defaultCORSConfig"
      domain="/"
      allowedOrigins="*"
      allowedMethods="GET, POST, PUT, DELETE, OPTIONS"
      allowedHeaders="Origin, Content-Type, Authorization, Cache-Control, Expires, Pragma"
      allowCredentials="true"
      maxAge="3600" />

see cors.xml file for example configuration.

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

#### Configuring Services.

- [IBM Doc](https://www.ibm.com/docs/en/zosconnect/3.0?topic=configuring-services)

#### CICS service
Services are defined with the `.sar` archives. The prefered way to build a service archive is to export it from the
toolkit service project. Another way to build a service archive is to use built toolkit.<br>

sar archives require `zosconnect_services` element.
Note that we co-locate `zosconnect_services` element with the cics ipic configuration.

    <!--
        required for services created with .sar archives
    -->
    <zosconnect_services>
        <service name="cics1">
            <!-- transid - A CICS transaction name; the transidUsage parameter specifies how the value is used. -->
            <property name="transid" value="HELO"/>
            <!--
            transidUsage - EIB_ONLY/EIB_AND_MIRROR
            EIB_ONLY - The transid parameter specifies the name of the CICS transaction that appears in the CICS
            exec interface block (EIB); the EIBTRNID field contains the value of the transid parameter.
            The called CICS program runs under the default mirror transaction CSMI.

            EIB_AND_MIRROR - The transid parameter specifies the name of the CICS transaction under which
            the called CICS program runs. The transaction must be defined in the CICS region, and the transaction
            definition must specify the mirror program, DFHMIRS. The value specified by the transid parameter
            is available to the called CICS program for querying the transaction ID. The value of the transid
            parameter also appears in the EIBTRNID field of the CICS EIB.

            value set here overwrites zosconnect_cicsIpicConnection and service archive .sar file.
            -->
            <property name="transidUsage" value="EIB_AND_MIRROR"/>
        </service>
    </zosconnect_services>

see `cics-ipic.xml` file for example configuration.

#### CICS service provider 
CICS service provider connects to CICS using IPIC connection.

- Configure IPIC connection in CICS [IBM Doc](https://www.ibm.com/docs/en/zosconnect/3.0?topic=cics-configuring-ipic-connection-in)
- Configure CICS TCPIPService
- Create predefined or auto-installed IPCONN definition.
- Configure SSL on IPIC connection. [IBM Doc](https://www.ibm.com/docs/en/zosconnect/3.0?topic=connection-configuring-ssl-ipic)

> `IPCONN.APplid` is matched to `zosconnect_cicsIpicConnection.cicsApplid`.  
> `IPCONN.Networkid` is matched to `zosconnect_cicsIpicConnection.cicsNetworkId`.  
> `IPCONN.Userauth = Local|Defaultuser` - no identity propogation. CICS program runs under link id, or default id.  
> `IPCONN.Userauth = Identify` - flow asserted saf userid.  
> `IPCONN.Verify = identity` propogation required, zosconnect-authdata is referenced on ipic connection element.  

IPIC SSL z/OS CEE.
- If SSL is enabled, connect enterprise root CA cert to the z/os cee saf keyring. 
- If client authentication is required create and sign personal certificate for z/os cee and connect it 
to the z/os cee saf keyring. Export z/os cee cert from z/os cee saf keyring and connect it to the cics keyring.

In the example configuration below z/os cee keystore is pointing to the saf keyring.
ipicConnection refs ssl configuration and ssl configuration refs keystore.

See *cics-ipic.xml* file for example configuration

    <?xml version="1.0"?>
    <server>
      <featureManager>
        <feature>zosconnect:zosconnect-2.0</feature>
        <feature>zosconnect:cicsService-1.0</feature>
      </featureManager>

      <!--
        required for services created with .sar archives
      -->
      <zosconnect_services>
        <service name="cics1">
            <!-- transid - A CICS transaction name; the transidUsage parameter specifies how the value is used. -->
            <property name="transid" value="HELO"/>
            <!--
            transidUsage - EIB_ONLY/EIB_AND_MIRROR
            EIB_ONLY - The transid parameter specifies the name of the CICS transaction that appears in the CICS
            exec interface block (EIB); the EIBTRNID field contains the value of the transid parameter.
            The called CICS program runs under the default mirror transaction CSMI.

            EIB_AND_MIRROR - The transid parameter specifies the name of the CICS transaction under which
            the called CICS program runs. The transaction must be defined in the CICS region, and the transaction
            definition must specify the mirror program, DFHMIRS. The value specified by the transid parameter
            is available to the called CICS program for querying the transaction ID. The value of the transid
            parameter also appears in the EIBTRNID field of the CICS EIB.

            value set here overwrites zosconnect_cicsIpicConnection and service archive .sar file.
            -->
            <property name="transidUsage" value="EIB_AND_MIRROR"/>
        </service>
      </zosconnect_services>

      <!--
        id - match the value that is specified for the connectionRef build toolkit property
            that is used to generate the .sar files that use this connection with the CICS
            service provider

        host - host cics region is running on

        port - match the port number of a TCPIPSERVICE definition in the CICS region
                that is configured with the PROTOCOL parameter set to IPIC

        sendSessions - maximum number of simultaneous requests (up to 999) over the connection.
            The actual number of send sessi>ons established depends on the value of sendSessions
            and the value in the RECEIVECOUNT parameter of the IPCONN definition in the CICS region.

        cicsApplid - if this value matches Applid attribute of the IPCONN definition then it is used
            Otherwise the connection is auto installed. 

        cicsNetworkid - if this value matches Networkid attribute of the IPCONN definition
            then it is used. Otherwise the connection is auto installed. Default: 9UNKNOWN

        transid - A CICS transaction name; the transidUsage parameter specifies how the value is used.

        transidUsage - EIB_ONLY/EIB_AND_MIRROR
            EIB_ONLY - The transid parameter specifies the name of the CICS transaction that appears in the CICS 
            exec interface block (EIB); the EIBTRNID field contains the value of the transid parameter. 
            The called CICS program runs under the default mirror transaction CSMI.

            EIB_AND_MIRROR - The transid parameter specifies the name of the CICS transaction under which 
            the called CICS program runs. The transaction must be defined in the CICS region, and the transaction 
            definition must specify the mirror program, DFHMIRS. The value specified by the transid parameter 
            is available to the called CICS program for querying the transaction ID. The value of the transid 
            parameter also appears in the EIBTRNID field of the CICS EIB. 

            Note that this values can be overwritten in .sar, zosconnect_services, an active rule that modifies
            transaction code.

        sslCertsRef -  Reference to an SSL repertoire with an ID, a defined keystore and truststore, 
            or an SSL Default repertoire.

        authDataRef - basic auth data to be used for the connection if no creds are supplied
            on the request.
      -->
      <zosconnect_cicsIpicConnection id="cicsipic" 
        host="9.1.2.345" port="1110" sendSessions="100"
        cicsApplid="applid" cicsNetworkid="netid" 
        transid="HELO" transidUsage="EIB_AND_MIRROR"
        sslCertsRef="ipicssl"/>
      <!--
        uncomment if identity propogation is required.
        authDataRef="authdata"/>
      -->

      <!-- remove sslCertRef and these elements if SSL is not enabled -->
      <ssl id="ipicssl" 
        keyStoreRef = "ipicKeyringKeyStore"
        trustStoreRef = "ipicKeyringKeyStore"
        clientAuthentication = "true"
      />

      <keyStore id="ipicKeyringKeyStore"
        location="safkeyring:///Keyring.ZOSCONN"
        password="notused" 
        type="JCERACFKS"
        fileBased="false" 
        readOnly="true">
      </keyStore>

      <!--
        user - if this element is referenced by the zosconnect_cicsIpicConnection element
            this user will be propogated to the CICS region
        password - encoded password.
      -->
      <zosconnect_authData id="authdata"
        user="user" password="encoded">
      </zosconnect_authData>

    </server>

#### MQ Service Provider.

[Using IBM MQ Service Provider](https://www.ibm.com/docs/en/zosconnect/3.0?topic=configuring-using-mq-service-provider)

When creating MQ service project with the toolkit specify a list of values:
- Connection factory JNDI name
- Request destination JNDI name
- Reply destination JNDI name
- Wait interval

These values can be overwritten with `zosconnect_services` service definition.

see mq.xml configuration file for examples.

    <?xml version="1.0" encoding="utf-8" ?>
    <server>
      <featureManager>
        <feature>zosconnect:zosconnect-2.0</feature>
      </featureManager>

      <!--
      required for services created with .sar archives
      -->
      <zosconnect_services>
        <service name="mq1">
          <!--
            connectionFactory
            destination
            expiry
            mqmdFormat
            password
            persistence
            replyDestination
            replySelection
            selector
            useCallerPrincipal = true - enable identity propogation
            userName - user name for authentication, otherwise use connection factory user.
            waitInterval
            -->
            <property name="connectionFactory" value="jms/ConnectionFactory1"/>
        </service>
      </zosconnect_services>
    </server>
