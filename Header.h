/* 
 * File:   Header.h
 * Author: root
 *
 * Created on May 28, 2014, 7:26 PM
 */

#ifndef HEADER_H
#define	HEADER_H

#include <cstdlib>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <sstream>
#include <mysql.h>
#include <time.h>
#include <math.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <vector>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <stdio.h>
#include <string>
#include <wchar.h>
#include <regex>

using namespace std;

typedef unsigned char uchar;
// Length of Pre master key to create main key of aes cryptography
#define PREMASTERKEYLENGTH	32

// Errors types
#define CONNECTIONERROR		100
#define MYSQLERROR		110
#define CALCULATEERROR		120
#define SOAPERROR		130
#define SESSIONERROR		140
#define USERINFOERRO		150

// Mysql Connection Informations
#define MYSQLSERVER            "localhost"
#define MYSQLUSER              "root"
#define MYSQLPASSWORD          "AmnPazhouh@92"
#define MYSQLDATABAE           "persianguard"

// Mysql Errors
#define MYSQLCONNECTIONERROR	"Mysql Connection Failed"
#define MYSQLINSERTERROR	"Mysql Insert Failed"
#define MYSQLUPDATEERROR	"Mysql Update Failed"

// Mysql Errors Code
#define MYSQLCONNECTIONERRORC	110100
#define MYSQLINSERTERRORC	110110
#define MYSQLUPDATEERRORC	110120

// Session Errors
#define SESSIONINVALID		"Session Code is Invalid"
#define SESSIONEXPIRED		"Session Code is expired"

// Session Error Code
#define SESSIONINVALIDC		140100
#define SESSIONEXPIREDC		140110

// Session Errors
#define USERKEYINVALID		"User Key is Invalid"
#define USERKEYEXPIRED		"User Key is expired"

// Session Error Code
#define USERKEYINVALIDC		150100
#define USERKEYEXPIREDC		150110

// SOAP timeout data
#define SEND_TIMEOUT		60
#define RECV_TIMEOUT		600
#define CONNECT_TIMEOUT		30
#define ACCEPT_TIMEOUT		30

// Sleep Time
#define SLEEPTIME		1000

// Update Files Directory
#define UPDATEFILESDIRECTORY "/var/Update"

// Stream Format
#define STREAMEFORMAT	    "[0-9]{8}"

struct FileInfo
{
	string FileName;
	int FileSize;
	string FolderName;
};

struct ErrorStruct
{
    size_t ErrorNumber;
    string Error;
    size_t ErrorType;
};

#endif	/* HEADER_H */

