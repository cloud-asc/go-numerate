package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func compSearch(computer string) *ldap.SearchRequest {
	var filter string
	if computer != "*" {
		filter = fmt.Sprintf("(&(objectClass=computer)(sAMAccountType=805306369)(CN=%s))", computer)
	} else {
		filter = "(&(objectClass=computer)(sAMAccountType=805306369))"
	}
	return ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{"*", "+"}, []ldap.Control{})

}

func computersConfirmed(l *ldap.Conn, query string, output string) {
	searchReq := compSearch(query)

	var allEntries []*ldap.Entry
	pagingControl := ldap.NewControlPaging(1000)
	searchReq.Controls = append(searchReq.Controls, pagingControl)

	for {
		result, err := l.Search(searchReq)
		if err != nil {
			log.Fatal(err)
		}
		allEntries = append(allEntries, result.Entries...)

		updatedControl := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if updatedControl == nil {
			break
		}
		pagingResult, ok := updatedControl.(*ldap.ControlPaging)
		if !ok || len(pagingResult.Cookie) == 0 {
			break
		}
		pagingControl.SetCookie(pagingResult.Cookie)
	}

	fmt.Println("")
	log.Println("Got", len(allEntries), "search results")

	switch output {
	case "console":
		for _, entry := range allEntries {
			fmt.Println("===============================================================")
			fmt.Println("DN:", entry.DN)
			for _, attribute := range entry.Attributes {
				fmt.Printf("  %s: %v\n", attribute.Name, strings.Join(attribute.Values, ", "))
			}
			fmt.Printf("\n")
		}
	case "csv":
		if len(allEntries) == 0 {
			fmt.Println("No results")
			return
		}

		// build headers from ALL entries
		headerMap := map[string]bool{"dn": true}
		for _, entry := range allEntries {
			for _, attribute := range entry.Attributes {
				headerMap[attribute.Name] = true
			}
		}
		headers := []string{"dn"}
		for h := range headerMap {
			if h != "dn" {
				headers = append(headers, h)
			}
		}

		csvOutput := [][]string{headers}

		for _, entry := range allEntries {
			attrMap := map[string]string{"dn": entry.DN}
			for _, attribute := range entry.Attributes {
				if attribute.Name == "objectSid" {
					attrMap[attribute.Name] = sidToString(entry.GetRawAttributeValue("objectSid"))
				} else if timeAttrs[attribute.Name] {
					attrMap[attribute.Name] = adFileTimeToTime(attribute.Values[0])
				} else if attribute.Name == "whenCreated" || attribute.Name == "whenChanged" {
					attrMap[attribute.Name] = parseGeneralizedTimeString(attribute.Values[0])
				} else if attribute.Name == "userAccountControl" {
					attrMap[attribute.Name] = parseUserAccountControl(attribute.Values[0])
				} else {
					attrMap[attribute.Name] = strings.Join(attribute.Values, "|")
				}
			}

			row := make([]string, len(headers))
			for i, h := range headers {
				row[i] = attrMap[h]
			}
			csvOutput = append(csvOutput, row)
		}

		if fileName == "" {
			t := time.Now()
			fileName = t.Format("01-02-06-150405") + "-computers"
		}
		csvExport(csvOutput, fileName)
		fmt.Printf("Successfully exported to %s.csv", fileName)
	}
}
