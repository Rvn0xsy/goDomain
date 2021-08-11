package main

import (
	"flag"
	"fmt"
	"github.com/go-ldap/ldap"
	"os"
)

const (
	LdapConnectTCP = 1
	LdapConnectUDP = 2
	FilterTestQuery = "(objectClass=dnsNode)"
	FilterComputerQuery = "(objectCategory=computer)"
	FilterUnconstrainedDelegationComputerQuery = "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)(objectClass=computer))"
	FilterDelegationComputerQuery = "(&(samAccountType=805306369)(msds-allowedtodelegateto=*)(objectClass=computer))"
)

type FlagStruct struct{
	Username string
	Password string
	BaseDN string
	LDAPHost string
	LDAPPort int
	UDPConnect bool
	GetComputer bool
	GetUnconstrainedDelegationComputer bool
	GetDelegationComputer bool
}



type LdapClient struct {
	ldapCon * ldap.Conn
	bindUsername string
	bindPassword string
	baseDN string
	ldapServerHost string
	ldapServerPort int
	ldapServerConnectProtocol string
	ldapResults * ldap.SearchResult
}

var (
	flagStruct = FlagStruct{}
)

func (ldapClient  * LdapClient )SetBindUserPass(username string,password string){
	ldapClient.bindPassword = password
	ldapClient.bindUsername = username
}

func (ldapClient  * LdapClient )SetLDAPServerConnect(ldapServerHost string,ldapServerPort int,ldapServerConnectProtocol int){
	ldapClient.ldapServerHost = ldapServerHost
	ldapClient.ldapServerPort = ldapServerPort
	if ldapServerConnectProtocol == LdapConnectTCP{
		ldapClient.ldapServerConnectProtocol = "tcp"
	}else{
		ldapClient.ldapServerConnectProtocol = "udp"
	}
}

func (ldapClient  * LdapClient )SetLDAPBaseDN(baseDN string) {
	ldapClient.baseDN = baseDN
}

func (ldapClient  * LdapClient )ConnectLDAP(){
	var err error
	connectAddr := fmt.Sprintf("%s:%d", ldapClient.ldapServerHost, ldapClient.ldapServerPort)
	ldapClient.ldapCon ,err = ldap.Dial(ldapClient.ldapServerConnectProtocol,connectAddr)
	ldapClient.checkErrorPrintExit(err)

	err = ldapClient.ldapCon.Bind(ldapClient.bindUsername, ldapClient.bindPassword)
	ldapClient.checkErrorPrintExit(err)
	fmt.Println("[*]Connect LDAP Server Success")
}


func (ldapClient  * LdapClient )Search(query string)(ldapResults * ldap.SearchResult){
	var err error
	searchRequest := ldap.NewSearchRequest(
		ldapClient.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways, 0, 0, false,
		query,
		nil,
		nil,
	)
	ldapResults, err = ldapClient.ldapCon.Search(searchRequest)
	ldapClient.checkErrorPrintExit(err)
	fmt.Println(fmt.Sprintf("[*]Query: %s get %d entries ", query , len(ldapResults.Entries)))
	return ldapResults
}


func (ldapClient  * LdapClient )checkErrorPrintExit(err error){
	if err != nil {
		ldapClient.ldapCon.Close()
		fmt.Println(err)
		os.Exit(0)
	}
}

func (ldapClient  * LdapClient )checkErrorClose(err error){
	if err != nil {
		ldapClient.ldapCon.Close()
		panic(err)
	}
}


func (ldapClient  * LdapClient )Close(){
	ldapClient.ldapCon.Close()
}


func (ldapClient * LdapClient)GetComputers(ldapResults * ldap.SearchResult)  {
	for _,value := range ldapResults.Entries {
		operatingSystem := value.GetAttributeValue("operatingSystem")
		operatingSystemVersion :=  value.GetAttributeValue("operatingSystemVersion")
		dNSHostName := value.GetAttributeValue("dNSHostName")
		allowedToDelegate := value.GetAttributeValue("msDS-AllowedToDelegateTo")
		if operatingSystem == "" {
			continue
		}

		fmt.Println(fmt.Sprintf("[+]HostName: %s OS: %s  Version: %s",dNSHostName,operatingSystem,operatingSystemVersion ))
		if allowedToDelegate != "" {
			fmt.Println("[+]AllowedToDelegate : ", allowedToDelegate)
		}
	}
}

func (ldapClient  * LdapClient )GetEntries(ldapResults * ldap.SearchResult, attribute string)  {
	for _,value := range ldapResults.Entries {
		value.GetAttributeValues(attribute)

	}
}

func init()  {
	flag.StringVar(&flagStruct.Username,"username","","LDAP Username")
	flag.StringVar(&flagStruct.Password,"password","","LDAP Password")
	flag.StringVar(&flagStruct.BaseDN,"base-dn","","LDAP Base DN")
	flag.IntVar(&flagStruct.LDAPPort,"port",389,"LDAP Port (default:389)")
	flag.StringVar(&flagStruct.LDAPHost,"host","","LDAP Host")
	flag.BoolVar(&flagStruct.UDPConnect,"udp",false,"UDP Connect Method (default: tcp)")
	flag.BoolVar(&flagStruct.GetComputer,"get-computers",false,"Get All Computers")
	flag.BoolVar(&flagStruct.GetUnconstrainedDelegationComputer,"get-unconstrained-delegation-computers",false,"Get Unconstrained Delegation Computers")
	flag.BoolVar(&flagStruct.GetDelegationComputer,"get-delegation-computers",false,"Get Delegation Computers")
	flag.Parse()
	if flagStruct.LDAPHost == "" || flagStruct.Username == "" || flagStruct.Password == ""{
		flag.Usage()
		os.Exit(0)
	}

}

func main() {

	connectPro := LdapConnectTCP

	if flagStruct.UDPConnect {
		connectPro = LdapConnectUDP
	}


	Dumper := LdapClient{}
	Dumper.SetBindUserPass(flagStruct.Username,flagStruct.Password)
	Dumper.SetLDAPBaseDN(flagStruct.BaseDN)

	Dumper.SetLDAPServerConnect(flagStruct.LDAPHost, flagStruct.LDAPPort,connectPro)
	Dumper.ConnectLDAP()
	if flagStruct.GetComputer {
		ldapResult := Dumper.Search(FilterComputerQuery)
		Dumper.GetComputers(ldapResult)
	}

	if flagStruct.GetUnconstrainedDelegationComputer {
		ldapResult := Dumper.Search(FilterUnconstrainedDelegationComputerQuery)
		Dumper.GetComputers(ldapResult)
	}
	if flagStruct.GetDelegationComputer {
		ldapResult := Dumper.Search(FilterDelegationComputerQuery)
		Dumper.GetComputers(ldapResult)
	}

}
