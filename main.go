package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/go-ldap/ldap"
	"github.com/jedib0t/go-pretty/v6/table"
	"math"
	"os"
	"strings"
)

const (
	LdapConnectTCP = 1
	LdapConnectUDP = 2
	FilterTestQuery = "(objectClass=dnsNode)"
	FilterUsersQuery = "(objectClass=user)"
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
	GetUsers bool
	GetUnconstrainedDelegationComputer bool
	GetDelegationComputer bool
	OutputCSV bool
	OutputHtml bool
	OutputMarkdown bool
	Filter string
	Columns string
	TLSConnection bool
	VerifyTLS bool
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

func (ldapClient  * LdapClient )ConnectLDAP(enableTLS bool,skipVerify bool){
	var err error
	connectAddr := fmt.Sprintf("%s:%d", ldapClient.ldapServerHost, ldapClient.ldapServerPort)

	if enableTLS {
		ldapClient.ldapCon, err = ldap.DialTLS(ldapClient.ldapServerConnectProtocol,connectAddr,&tls.Config{InsecureSkipVerify: skipVerify})
	}else{
		ldapClient.ldapCon ,err = ldap.Dial(ldapClient.ldapServerConnectProtocol,connectAddr)
	}

	ldapClient.checkErrorPrintExit(err)

	err = ldapClient.ldapCon.Bind(ldapClient.bindUsername, ldapClient.bindPassword)
	ldapClient.checkErrorPrintExit(err)
	// fmt.Println("[*]Connect LDAP Server Success")
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

	ldapResults, err = ldapClient.ldapCon.SearchWithPaging(searchRequest, math.MaxInt32)
	ldapClient.checkErrorPrintExit(err)
	// fmt.Println(fmt.Sprintf("[*]Query: %s get %d entries ", query , len(ldapResults.Entries)))
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
	count := len(ldapResults.Entries)
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"#", "operatingSystem", "operatingSystemVersion", "dNSHostName", "msDS-AllowedToDelegateTo","sAMAccountName"})

	for index,value := range ldapResults.Entries {
		operatingSystem := value.GetAttributeValue("operatingSystem")
		if operatingSystem == "" {
			operatingSystem = "NULL"
		}
		operatingSystemVersion :=  value.GetAttributeValue("operatingSystemVersion")
		if operatingSystemVersion == "" {
			operatingSystemVersion = "NULL"
		}
		dNSHostName := value.GetAttributeValue("dNSHostName")
		if dNSHostName == "" {
			dNSHostName = "NULL"
		}
		allowedToDelegate := value.GetAttributeValue("msDS-AllowedToDelegateTo")
		if allowedToDelegate == "" {
			allowedToDelegate = "NULL"
		}
		sAMAccountName := string(value.GetRawAttributeValue("sAMAccountName"))
		// fmt.Println(fmt.Sprintf("[+]HostName: %s OS: %s  Version: %s",dNSHostName,operatingSystem,operatingSystemVersion ))
		if sAMAccountName == "" {
			sAMAccountName = "NULL"
		}
		t.AppendRow([]interface{}{index,operatingSystem,operatingSystemVersion,dNSHostName,allowedToDelegate,sAMAccountName})
	}
	t.AppendSeparator()
	t.AppendFooter(table.Row{"Total","", count})
	t.SetStyle(table.StyleColoredBright)
	if flagStruct.OutputCSV{
		t.RenderCSV()
		return
	}

	if flagStruct.OutputHtml{
		t.RenderHTML()
		return
	}
	if flagStruct.OutputMarkdown{
		t.RenderMarkdown()
		return
	}
	t.Render()
}
func (ldapClient * LdapClient)GeneralResult(ldapResults * ldap.SearchResult, columns  []string){
	count := len(ldapResults.Entries)
	if count  == 0{
		return
	}
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	if columns[0] == "" {
		for _, attr := range ldapResults.Entries[0].Attributes {
			// fmt.Println(attr.Name)
			columns = append(columns, attr.Name)
		}
	}
	headers := make([]interface{}, len(columns))
	for i, v := range columns {
		headers[i] = v
	}
	t.AppendHeader(headers)
	for _,value := range ldapResults.Entries {
		// distinguishedName := value.GetAttributeValue("distinguishedName")
		// sAMAccountName :=  value.GetAttributeValue("sAMAccountName")
		rowsValue := make([]interface{}, len(columns))
		for i,c := range columns{
			value := string(value.GetAttributeValue(c))
			rowsValue[i] = value
		}
		t.AppendRow(rowsValue)
	}
	
	ldapClient.OutputRender(t,count)
}

func (LdapClient * LdapClient)OutputRender(t table.Writer, count int)  {
	t.AppendSeparator()
	t.AppendFooter(table.Row{"Total","", count})
	t.SetStyle(table.StyleColoredBright)
	if flagStruct.OutputCSV{
		t.RenderCSV()
		return
	}
	if flagStruct.OutputHtml{
		t.RenderHTML()
		return
	}
	if flagStruct.OutputMarkdown{
		t.RenderMarkdown()
		return
	}
	t.Render()
}

func (ldapClient * LdapClient)GetUsers(ldapResults * ldap.SearchResult)  {
	count := len(ldapResults.Entries)
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"#", "sAMAccountName", "DistinguishedName"})

	for index,value := range ldapResults.Entries {
		distinguishedName := value.GetAttributeValue("distinguishedName")
		sAMAccountName :=  value.GetAttributeValue("sAMAccountName")
		t.AppendRow([]interface{}{index,sAMAccountName,distinguishedName})
	}
	t.AppendSeparator()
	t.AppendFooter(table.Row{"Total","", count})
	t.SetStyle(table.StyleColoredBright)
	if flagStruct.OutputCSV{
		t.RenderCSV()
		return
	}

	if flagStruct.OutputHtml{
		t.RenderHTML()
		return
	}
	if flagStruct.OutputMarkdown{
		t.RenderMarkdown()
		return
	}
	t.Render()
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
	flag.BoolVar(&flagStruct.GetUsers,"get-users",false,"Get All Users")
	flag.BoolVar(&flagStruct.GetUnconstrainedDelegationComputer,"get-unconstrained-delegation-computers",false,"Get Unconstrained Delegation Computers")
	flag.BoolVar(&flagStruct.GetDelegationComputer,"get-delegation-computers",false,"Get Delegation Computers")
	flag.BoolVar(&flagStruct.OutputCSV,"csv",false,"Output CSV Format")
	flag.BoolVar(&flagStruct.OutputHtml,"html",false,"Output html Format")
	flag.BoolVar(&flagStruct.OutputMarkdown,"markdown",false,"Output Markdown Format")
	flag.StringVar(&flagStruct.Filter,"filter","","LDAP Filter Query")
	flag.StringVar(&flagStruct.Columns,"columns","","LDAP Result Columns e.g. DN,name,SID")
	flag.BoolVar(&flagStruct.TLSConnection,"tls",false,"Enable TLS Connection")
	flag.BoolVar(&flagStruct.VerifyTLS,"skip-verify",true,"SkipVerify TLS Connection")
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
	Dumper.ConnectLDAP(flagStruct.TLSConnection, flagStruct.VerifyTLS)
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

	if flagStruct.GetUsers {
		ldapResult := Dumper.Search(FilterUsersQuery)
		Dumper.GetUsers(ldapResult)
	}

	if flagStruct.Filter != "" {
		columns := strings.Split(flagStruct.Columns,",")
		ldapResult := Dumper.Search(flagStruct.Filter)
		Dumper.GeneralResult(ldapResult,columns)
	}

}
