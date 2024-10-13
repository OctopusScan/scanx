package sqlInject

import (
	_ "embed"
	"fmt"
	"github.com/B9O2/Inspector/useful"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/beevik/etree"
)

//go:embed sql_error_xml/errors.xml
var errorsXml string
var dbmsErrors = make(map[string][]string)

var formatExceptionStrings = []string{
	"Type mismatch", "Error converting", "Please enter a", "Conversion failed",
	"String or binary data would be truncated", "Failed to convert", "unable to interpret text value",
	"Input string was not in a correct format", "System.FormatException", "java.lang.NumberFormatException",
	"ValueError: invalid literal", "TypeMismatchException", "CF_SQL_INTEGER", "CF_SQL_NUMERIC",
	"for CFSQLTYPE ", "cfqueryparam cfsqltype", "InvalidParamTypeException",
	"Invalid parameter type", "Attribute validation error for tag", "is not of type numeric",
	"<cfif Not IsNumeric(", "invalid input syntax for integer", "invalid input syntax for type",
	"invalid number", "character to number conversion error", "unable to interpret text value",
	"String was not recognized as a valid", "Convert.ToInt", "cannot be converted to a ",
	"InvalidDataException", "Arguments are of the wrong type",
}

var closeType = []string{"'", "\"", "')", "'))", "\")", "\"))"}
var annotator = []string{"#", "-- "}
var space = []string{"/**/"}
var and = []string{"And", "&&"}
var or = []string{"Or", "||"}
var delayTimeFunc = []string{"SlEEp({{time}})"}

func init() {
	dbmsErrors = make(map[string][]string)
	doc := etree.NewDocument()

	if err := doc.ReadFromString(errorsXml); err != nil {
		MainInsp.Print(useful.ERROR, useful.Text(fmt.Sprintf("load errors.xml error:%s", err.Error())))
	} else {
		root := doc.SelectElement("root")
		for _, dbms := range root.SelectElements("dbms") {
			for _, dbName := range dbms.Attr {
				var errWords []string
				for _, e := range dbms.SelectElements("error") {
					for _, errWord := range e.Attr {
						errWords = append(errWords, errWord.Value)
					}
				}
				dbmsErrors[dbName.Value] = errWords
			}
		}
	}
}
