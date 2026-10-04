package localadmin

import (
 "bytes"
 "crypto/x509"
 "net"
 "os"
 "path/filepath"
 "testing"
)

func TestBrowserCertificatePersistsKeyAndCoversUSBAndWiFi(t *testing.T){
 dir:=t.TempDir();c,err:=Certificate(dir,"test-node",[]net.IP{net.ParseIP("192.168.1.55")});if err!=nil{t.Fatal(err)}
 leaf,err:=x509.ParseCertificate(c.Certificate[0]);if err!=nil{t.Fatal(err)};if leaf.PublicKeyAlgorithm!=x509.ECDSA{t.Fatal("not browser-compatible ECDSA")}
 for _,host:=range []string{"10.55.0.2","192.168.1.55","127.0.0.1","localhost"}{if err=leaf.VerifyHostname(host);err!=nil{t.Fatal(host,err)}}
 again,err:=Certificate(dir,"test-node",[]net.IP{net.ParseIP("192.168.1.55")});if err!=nil||!bytes.Equal(c.Certificate[0],again.Certificate[0]){t.Fatal("unchanged certificate replaced",err)}
 keyBefore,_:=os.ReadFile(filepath.Join(dir,"admin-tls-key.pem"));changed,err:=Certificate(dir,"test-node",[]net.IP{net.ParseIP("192.168.1.56")});if err!=nil{t.Fatal(err)};keyAfter,_:=os.ReadFile(filepath.Join(dir,"admin-tls-key.pem"));if !bytes.Equal(keyBefore,keyAfter){t.Fatal("address change replaced key")};renewed,_:=x509.ParseCertificate(changed.Certificate[0]);if renewed.VerifyHostname("192.168.1.56")!=nil{t.Fatal("new Wi-Fi address not covered")}
 info,_:=os.Stat(filepath.Join(dir,"admin-tls-key.pem"));if info.Mode().Perm()!=0600{t.Fatal("key permissions",info.Mode())}
 _=os.WriteFile(filepath.Join(dir,"admin-tls-key.pem"),[]byte("corrupt"),0600);if _,err=Certificate(dir,"test-node",nil);err==nil{t.Fatal("silently replaced corrupt private key")}
}
