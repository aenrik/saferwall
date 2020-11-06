package main

import (
	// "encoding/json"
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/saferwall/saferwall/pkg/utils"
)

const (
	reAPIs = `(_Success_|WINBASEAPI|WINADVAPI)[\d\w\s\)\(,\[\]\!*+=&<>]+;`

	rePrototype = `(?P<Attr>WINBASEAPI|WINADVAPI) (?P<RetValType>[A-Z]+) (?P<CallConv>WINAPI|APIENTRY) (?P<ApiName>[a-zA-Z0-9]+)\((?P<Params>.*)\);`

	reParams = `(?P<Annotation>_In_|_In_opt_|_Inout_opt_|_Out_|_Inout_|_Out_opt_|_Outptr_opt_|_Reserved_|_Out_writes_[\w(),+ *]+|_In_reads_[\w()]+) (?P<Type>[\w *]+) (?P<Name>[a-zA-Z0-9]+)`
)

// APIParam represents a paramter of a Win32 API.
type APIParam struct {
	Annotation string
	Type       string
	Name       string
}

// API represents information about a Win32 API.
type API struct {
	Attr        string     `json:"attribute"`         // Microsoft-specific attribute.
	CallConv    string     `json:"callingConvention"` // Calling Convention.
	Name        string     `json:"name"`              // Name of the API.
	Params      []APIParam `json:"parameters"`        // API Arguments.
	CountParams uint8      `json:"countParams"`       // Count of Params.
	RetValType  string     `json:"returnValueType"`   // Return value type.
}

func regSubMatchToMapString(regEx, s string) (paramsMap map[string]string) {

	r := regexp.MustCompile(regEx)
	match := r.FindStringSubmatch(s)

	paramsMap = make(map[string]string)
	for i, name := range r.SubexpNames() {
		if i > 0 && i <= len(match) {
			paramsMap[name] = match[i]
		}
	}
	return
}

func parseAPIParameter(params string) APIParam {
	m := regSubMatchToMapString(reParams, params)
	apiParam := APIParam{
		Annotation: m["Annotation"],
		Name:       m["Name"],
		Type:       m["Type"],
	}
	return apiParam
}

func parseAPI(apiPrototype string) API {
	m := regSubMatchToMapString(rePrototype, apiPrototype)
	api := API{
		Attr:       m["Attr"],
		CallConv:   m["CallConv"],
		Name:       m["ApiName"],
		RetValType: m["RetValType"],
	}

	// Treat the VOID case.
	if m["Params"] == " VOID " {
		api.CountParams = 0
		return api
	}

	// Corder cases:
	/*
	 BOOL WINAPI ReadFile( _In_ HANDLE hFile, _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer, _In_ DWORD nNumberOfBytesToRead, _Out_opt_ LPDWORD lpNumberOfBytesRead, _Inout_opt_ LPOVERLAPPED lpOverlapped );
	*/
	p := strings.Split(m["Params"], ", ")
	for _, v := range p {
		api.Params = append(api.Params, parseAPIParameter(v))
		api.CountParams++
	}
	return api
}

func removeAnnotations(apiPrototype string) string {
	apiPrototype = strings.Replace(apiPrototype, "_Must_inspect_result_", "", -1)
	apiPrototype = strings.Replace(apiPrototype, "_Success_(return != 0 && return < nBufferLength)", "", -1)
	apiPrototype = strings.Replace(apiPrototype, "_Success_(return != 0 && return < cchBuffer)", "", -1)
	return apiPrototype
}

func standardizeSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// WriteStrSliceToFile writes a slice of string line by line to a file.
func WriteStrSliceToFile(filename string, data []string) (int, error) {
	// Open a new file for writing only
	file, err := os.OpenFile(
		filename,
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0666,
	)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	// Create a new writer.
	w := bufio.NewWriter(file)
	nn := 0
	for _, s := range data {
		n, _ := w.WriteString(s + "\n")
		nn += n
	}

	w.Flush()
	return nn, nil
}

func main() {

	// Parse arguments.
	filePath := flag.String("path", "", "The file path to parse")
	flag.Parse()
	if *filePath == "" {
		flag.Usage()
		os.Exit(0)
	}

	// Read Win32 include API headers.
	data, err := utils.ReadAll(*filePath)
	if err != nil {
		log.Fatalln(err)
	}

	// Grab all API prototypes
	// 1. Ignore: FORCEINLINE
	var apis []API
	var prototypes []string
	r := regexp.MustCompile(reAPIs)
	matches := r.FindAllString(string(data), -1)
	log.Println("Size:", len(matches))
	for _, v := range matches {
		prototype := removeAnnotations(v)
		prototype = standardizeSpaces(prototype)
		prototypes = append(prototypes, prototype)
		apis = append(apis, parseAPI(prototype))
	}

	// Marshall and write to json file.
	data, _ = json.MarshalIndent(apis, "", " ")
	utils.WriteBytesFile("apis.json", bytes.NewReader(data))

	// Write raw prototypes to a text file.
	WriteStrSliceToFile("prototypes.inc", prototypes)
}
