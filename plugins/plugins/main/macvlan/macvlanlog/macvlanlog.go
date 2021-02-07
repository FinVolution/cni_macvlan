package macvlanlog

import (
	"log"
	"os"
	"strings"
)

var DebugLog *log.Logger
var LogFile *os.File

func CleanString(conn string) string {
	 
	conn = strings.Replace(conn, "\n", "", -1)
	conn = strings.Replace(conn, "\r", "", -1)
	conn = strings.Replace(conn, " ", "", -1)
	
	return conn
}

func InitLog(logname string) {

	fileName := CleanString(logname)
	logFile, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logFile, err = os.Create(fileName)
	}
	LogFile = logFile

	DebugLog = log.New(logFile, "[Debug]", log.Lshortfile|log.LstdFlags)
	 
}

func Close() {
	LogFile.Close()
}
