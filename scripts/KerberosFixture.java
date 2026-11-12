/* Test-only independent Apache Kerby KDC and JDK GSS initiator.
 * Run via Java 21 source launcher with the jars prepared by the PowerShell helper.
 * Protocol: TOKEN <user> <spnego|krb5> <host>, CHECK <id> <reply>, QUIT.
 * Secrets/tickets are written only to the private fixture directory/stdout pipe.
 */
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.PrivilegedExceptionAction;
import java.util.*;
import javax.security.auth.Subject;
import javax.security.auth.login.*;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.ietf.jgss.*;

class KerberosFixture {
    record Session(Subject subject, GSSContext context) {}
    public static void main(String[] args) throws Exception {
        Path directory=Path.of(args[0]).toAbsolutePath();
        Files.createDirectories(directory);
        String realm=args[1];
        int port=Integer.parseInt(args[2]);
        SimpleKdcServer kdc=new SimpleKdcServer();
        kdc.setWorkDir(directory.toFile());
        kdc.setKdcRealm(realm);
        kdc.setKdcHost("127.0.0.1");
        kdc.setAllowUdp(false);
        kdc.setKdcTcpPort(port);
        kdc.getKdcConfig().setString(KdcConfigKey.ENCRYPTION_TYPES,"aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96");
        kdc.init();
        kdc.start();
        try {
            for(String host:List.of("casdog.localhost","other.localhost")) {
                String principal="HTTP/"+host+"@"+realm;
                kdc.createPrincipal(principal);
                kdc.exportPrincipal(principal,directory.resolve(host+".keytab").toFile());
            }
            for(String user:List.of("alice","bob","alice/admin")) {
                String principal=user+"@"+realm;
                kdc.createPrincipal(principal);
                kdc.exportPrincipal(principal,directory.resolve(user.replace('/','_')+".keytab").toFile());
            }
            Path config=directory.resolve("jdk-krb5.conf");
            String settings="[libdefaults]\n default_realm = "+realm+"\n dns_lookup_kdc = false\n dns_lookup_realm = false\n udp_preference_limit = 1\n rdns = false\n[realms]\n "+realm+" = {\n  kdc = 127.0.0.1:"+port+"\n }\n[domain_realm]\n .localhost = "+realm+"\n localhost = "+realm+"\n";
            Files.writeString(config,settings);
            System.setProperty("java.security.krb5.conf",config.toString());
            System.setProperty("sun.security.krb5.disableReferrals","true");
            Map<Integer,Session> sessions=new HashMap<>();
            int next=0;
            System.out.println("READY"); System.out.flush();
            BufferedReader input=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));
            for(String line;(line=input.readLine())!=null;) {
                String[] words=line.split(" ",4);
                if(words[0].equals("QUIT")) break;
                try {
                    if(words[0].equals("TOKEN")) {
                        String user=words[1];
                        if(!List.of("alice","bob","alice/admin").contains(user)) throw new IllegalArgumentException();
                        String mechanism=words[2].startsWith("krb5")?"1.2.840.113554.1.2.2":"1.3.6.1.5.5.2";
                        String cipher=words[2].endsWith("128")?"aes128-cts-hmac-sha1-96":"aes256-cts-hmac-sha1-96";
                        Files.writeString(config,settings.replace("[libdefaults]","[libdefaults]\n default_tkt_enctypes = "+cipher+"\n default_tgs_enctypes = "+cipher+"\n permitted_enctypes = "+cipher));
                        String host=words[3];
                        if(!List.of("casdog.localhost","other.localhost").contains(host)) throw new IllegalArgumentException();
                        Map<String,Object> options=new HashMap<>();
                        options.put("principal",user+"@"+realm);
                        options.put("useKeyTab","true");
                        options.put("keyTab",directory.resolve(user.replace('/','_')+".keytab").toString());
                        options.put("storeKey","true"); options.put("doNotPrompt","true");
                        options.put("refreshKrb5Config","true"); options.put("isInitiator","true");
                        Configuration jaas=new Configuration() {
                            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                                return new AppConfigurationEntry[]{new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,options)};
                            }
                        };
                        LoginContext login=new LoginContext("fixture",null,null,jaas); login.login();
                        Subject subject=login.getSubject();
                        GSSManager manager=GSSManager.getInstance();
                        GSSContext ctx=manager.createContext(manager.createName("HTTP@"+host,GSSName.NT_HOSTBASED_SERVICE),new Oid(mechanism),null,GSSContext.DEFAULT_LIFETIME);
                        ctx.requestMutualAuth(true); ctx.requestCredDeleg(false);
                        byte[] token=Subject.doAs(subject,(PrivilegedExceptionAction<byte[]>)()->ctx.initSecContext(new byte[0],0,0));
                        int id=++next; sessions.put(id,new Session(subject,ctx));
                        System.out.println("TOKEN "+id+" "+Base64.getEncoder().encodeToString(token));
                    } else if(words[0].equals("CHECK")) {
                        Session session=sessions.get(Integer.parseInt(words[1]));
                        byte[] reply=Base64.getDecoder().decode(words[2]);
                        Subject.doAs(session.subject(),(PrivilegedExceptionAction<byte[]>)()->session.context().initSecContext(reply,0,reply.length));
                        if(!session.context().isEstablished()) throw new IllegalStateException("mutual auth incomplete");
                        System.out.println("VERIFIED");
                    } else {throw new IllegalArgumentException();}
                } catch(Exception error) {
                    error.printStackTrace(System.err);
                    System.out.println("ERROR");
                }
                System.out.flush();
            }
            for(Session session:sessions.values()) session.context().dispose();
        } finally { kdc.stop(); }
    }
}
