// File: Update.h 
//gsoap ns service name: Update 
//gsoap ns service namespace: urn:Update 
//gsoap ns service location: http://www.yourdomain.com/Update.cgi
#include <iostream>
#include <string.h>
#include <vector>

#import "stlvector.h"

typedef std::string xsd__string;
typedef int xsd__int;
typedef double xsd__double;


class ns1__ErrorInfo {
public:
    xsd__string ErrorNumber;
    xsd__string Error;
    xsd__string ErrorType;
};

class ns1__FileInfo {
    xsd__string FileName;
    xsd__string FileSize;
    xsd__string FolderName;
};

typedef std::vector<ns1__FileInfo> xsd__FileList;

class ns1__SessionInfo {
public:
    xsd__string SessionCode;
    xsd__string PublicKey;
    ns1__ErrorInfo Error;
};

class ns1__UpdateArguments {
public:
    xsd__string SessionCode;
    xsd__string UserKey;
    xsd__string HardSerial;
    xsd__string PreMasterKey;
    ns1__FileInfo FilesList;
    ns1__ErrorInfo Error;
};

class ns1__UpdateFilesList {
public:
    xsd__FileList FilesList;
    ns1__ErrorInfo Error;
};

class ns1__UpdateResponse {
public:
    xsd__string FileContent;
    ns1__ErrorInfo Error;
};

xsd__int ns__RequestForUpdate(ns1__SessionInfo &response);
xsd__int ns__MakeSecureConnection(ns1__UpdateArguments* UpdateInfo, ns1__UpdateFilesList &response);
xsd__int ns__DoUpdate(ns1__UpdateArguments* UpdateInfo, ns1__UpdateResponse &response);
xsd__int ns__EndUpdate(ns1__UpdateArguments* UpdateInfo, ns1__ErrorInfo &response);


