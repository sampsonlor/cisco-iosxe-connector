package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/inventory"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
)

type source struct { evidence device.Evidence; calls int; err error }
func (*source) ApprovedTarget(id string,ip netip.Addr,cred,pin string)bool {return id=="router-a"&&ip.String()=="192.0.2.10"&&cred=="secret://router-a"&&pin=="hostkey://router-a"}
func (s *source) Collect(context.Context,string)(device.Evidence,error){s.calls++;return s.evidence,s.err}
func access() provider.DeviceAccess {return provider.DeviceAccess{DeviceID:"router-a",Device:provider.ManagedDevice{Policy:provider.DevicePolicy{Target:netip.MustParseAddr("192.0.2.10"),ActiveTrustpoint:"HTTPS-LIVE",StagingTrustpoints:[]string{"HTTPS-STAGE-A","HTTPS-OLD"}},CredentialRef:"secret://router-a",HostKeyRef:"hostkey://router-a"}}}
func TestReaderRejectsCrossDeviceAndStaleOwnership(t *testing.T) {
	f:=synthetic(t,true);src:=&source{evidence:f.e};roles:=map[string][]inventory.Assignment{"router-a":f.roles}
	r,err:=inventory.NewReader(src,roles);if err!=nil {t.Fatal(err)}
	// Constructor must copy caller-owned assignments.
	roles["router-a"][0].SHA256=strings.Repeat("0",64)
	s,err:=r.ReadHTTPS(context.Background(),access());if err!=nil||!s.Complete||len(s.Certificates)!=5 {t.Fatalf("reader complete=%v count=%d err=%v",s.Complete,len(s.Certificates),err)}
	for _,c:=range s.Certificates {if c.WithKey {t.Fatal("key presence guessed from tp-keys-generated")}}
	for _,field:=range []string{"id","address","credential","pin","stage-pool","rollback-pool"} {t.Run(field,func(t *testing.T){a:=access();switch field {case "id":a.DeviceID="router-b";case "address":a.Device.Policy.Target=netip.MustParseAddr("192.0.2.11");case "credential":a.Device.CredentialRef="secret://other";case "pin":a.Device.HostKeyRef="hostkey://other";case "stage-pool":a.Device.Policy.StagingTrustpoints=nil;case "rollback-pool":a.Device.Policy.StagingTrustpoints=[]string{"HTTPS-STAGE-A"}}
		before:=src.calls;s,err:=r.ReadHTTPS(context.Background(),a);if err==nil||s.Complete||len(s.Certificates)!=0||src.calls!=before {t.Fatal("policy mismatch reached collector or returned inventory")}
	})}
	src.err=context.DeadlineExceeded;if _,err=r.ReadHTTPS(context.Background(),access());!errors.Is(err,context.DeadlineExceeded) {t.Fatal("timeout classification lost")}
}

func serve(h http.Handler,method,path,body string)*httptest.ResponseRecorder {w:=httptest.NewRecorder();r:=httptest.NewRequest(method,path,strings.NewReader(body));r.Header.Set("Content-Type","application/json");h.ServeHTTP(w,r);return w}
func attr(id,name,value string)string {return `{"uuid":"4c198a4c-0f9a-4b65-a378-1a8996a2`+id+`","name":"`+name+`","version":"v3","content":[{"data":"`+value+`","contentType":"string"}]}`}
func TestInventoryProviderSQLiteIntegration(t *testing.T) {
	f:=synthetic(t,true);src:=&source{evidence:f.e}
	r,err:=inventory.NewReader(src,map[string][]inventory.Assignment{"router-a":f.roles});if err!=nil {t.Fatal(err)}
	store,err:=provider.OpenEntityStore(filepath.Join(t.TempDir(),"entities.sqlite"));if err!=nil {t.Fatal(err)};defer store.Close()
	h,err:=provider.NewReadOnlyHandler(store,provider.ReadOnlyConfig{Devices:map[string]provider.ManagedDevice{"router-a":access().Device}},r);if err!=nil {t.Fatal(err)}
	w:=serve(h,"POST","/v1/entityProvider/entities",`{"name":"synthetic.example.test","kind":"iosxe","attributes":[`+attr("0101","deviceId","router-a")+`,`+attr("0102","targetAddress","192.0.2.10")+`]}`)
	var entity struct {Uuid string `json:"uuid"`};if w.Code!=200||json.Unmarshal(w.Body.Bytes(),&entity)!=nil||entity.Uuid=="" {t.Fatalf("create: %d %s",w.Code,w.Body)}
	location:=provider.HTTPSLocationID(entity.Uuid);path:="/v1/entityProvider/entities/"+entity.Uuid+"/locations";body:=`{"locationAttributes":[`+attr("0103","service","https")+`]}`
	w=serve(h,"POST",path,body)
	var dto struct {Certificates []struct {WithKey bool `json:"withKey"`;Type string `json:"certificateType"`;Metadata []struct {Name string `json:"name"`;Version int `json:"version"`;Schema string `json:"schemaVersion"`;Content []struct{Data string `json:"data"`} `json:"content"`} `json:"metadata"`} `json:"certificates"`;SupportKeyManagement bool `json:"supportKeyManagement"`}
	if w.Code!=200||json.Unmarshal(w.Body.Bytes(),&dto)!=nil||len(dto.Certificates)!=5||dto.SupportKeyManagement {t.Fatalf("location: %d %s",w.Code,w.Body)}
	active,bindings:=0,0
	for _,c:=range dto.Certificates {if c.WithKey||c.Type!="X.509" {t.Fatal("unsupported key proof or type")};unknown:=false
		for _,m:=range c.Metadata {if m.Version!=3||m.Schema!="v3" {t.Fatal("wrong metadata contract")};for _,v:=range m.Content {if m.Name=="trustpointRoles" {bindings++;if strings.HasSuffix(v.Data,"=ACTIVE") {active++}};if m.Name=="keyAssociation"&&v.Data=="UNKNOWN" {unknown=true}}};if !unknown {t.Fatal("unknown key association lost")}}
	if active!=1||bindings!=8 {t.Fatalf("metadata active=%d bindings=%d",active,bindings)}
	src.evidence.Complete=false;w=serve(h,"POST",path,body);if w.Code!=502||strings.Contains(w.Body.String(),"CERTIFICATE") {t.Fatalf("partial inventory: %d %s",w.Code,w.Body)}
	src.err=context.DeadlineExceeded;w=serve(h,"POST",path,body);if w.Code!=504 {t.Fatalf("timeout: %d",w.Code)}
	before:=src.calls;w=serve(h,"POST",path+"/csr",`{}`);if w.Code!=501||src.calls!=before||provider.HTTPSLocationID(entity.Uuid)!=location {t.Fatal("write enabled or service identity changed")}
}
