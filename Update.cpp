/* 
 * File:   Update.cpp
 * Author: root
 *
 * Created on June 1, 2014, 10:08 AM
 */

#include "soapH.h"
#include "Update.nsmap"

#include "Header.h"
#include "UpdateClass.h"

using namespace std;

/*
 * 
 */
int main(int argc, char** argv)
{
    struct soap soap;
    soap.send_timeout = SEND_TIMEOUT;
    soap.recv_timeout = RECV_TIMEOUT;
    soap.connect_timeout = CONNECT_TIMEOUT;
    soap.accept_timeout = ACCEPT_TIMEOUT;

    int m, s; // master and slave sockets
    soap_init(&soap);
    m = soap_bind(&soap, NULL, 8080, 100);
    if (m < 0)
	soap_print_fault(&soap, stderr);
    else
    {
	fprintf(stderr, "Socket connection successful: master socket = %d\n", m);
	for (int i = 1; ; i++)
	{
	    s = soap_accept(&soap);
	    if (s < 0)
	    {
		soap_print_fault(&soap, stderr);
		break;
	    }
	    fprintf(stderr, "%d: accepted connection from IP=%d.%d.%d.%d socket=%d", i,
		    (int) (soap.ip >> 24)&0xFF, (int) (soap.ip >> 16)&0xFF, (int) (soap.ip >> 8)&0xFF, (int) soap.ip & 0xFF, s);
	    if (soap_serve(&soap) != SOAP_OK)	// process RPC request 
		soap_print_fault(&soap, stderr); // print error 
	    fprintf(stderr, "request served\n");
	    soap_destroy(&soap);	// clean up class instances 
	    soap_end(&soap);	// clean up everything and close socket 
	}
    }
    soap_done(&soap); // close master socket and detach context 
    // create soap context and serve one CGI-based request:
    //return soap_serve(soap_new());
}

/*
 * Generate Session Code and RSA Pair key
 * and Save to DataBase and
 * Send To Session Code and RSA Public key to Client
 */
xsd__int ns__RequestForUpdate(soap* soap, ns1__SessionInfo &response)
{
    UpdateClass *ucObj = new UpdateClass();

    if (ucObj->CreateSession())
    {
	// Set Data Response to Client

	// Set RSA Public Key send to Client
	response.PublicKey = ucObj->SerializeData(ucObj->GetPublicKey());
	// Set Session Code send to Client
	response.SessionCode = ucObj->SerializeData(ucObj->GetSessionCode());
    }
    else
    {
	// Error Data
	response.Error.Error= ucObj->GetError();
	response.Error.ErrorNumber =ucObj->GetErrorCode();
	response.Error.ErrorType = ucObj->GetErrorType();
    }

    delete ucObj;

    return SOAP_OK;
}

/*
 * Get Client Informations
 * (User Key and Hard Serial Number)
 * Check User and Save to Session Topple
 * then Get list Update File List info
 * and Send to Client
 */
xsd__int ns__MakeSecureConnection(soap* soap, ns1__UpdateArguments* UpdateInfo, ns1__UpdateFilesList &response)
{
    UpdateClass *ucObj = new UpdateClass();

    // Set Session Code
    ucObj->SetSessionCode(ucObj->UnSerializeData(UpdateInfo->SessionCode));
    ucObj->SetPreMasterKey(UpdateInfo->PreMasterKey);
    ucObj->SetUserKey(UpdateInfo->UserKey);
    ucObj->SetHardSerialNumber(UpdateInfo->HardSerial);
    ucObj->SetLastFileUpdate(UpdateInfo->FilesList.FileName);

    if (ucObj->PaireConnection())
    {
	// Get List of All Update Files Greater than Last Update File received from Client
	size_t iFileCount = ucObj->GetFilesCount();

	ns1__FileInfo fiTemp;

	// Prepare Update File List
	for (size_t i = 0; i < iFileCount ; i++)
	{
	    fiTemp.FileName = ucObj->SecureEncrypt(ucObj->GetFileName(i));
	    fiTemp.FileSize = ucObj->SecureEncrypt(ucObj->GetFileSize(i));

	    response.FilesList.push_back(fiTemp);
	}
    }
    else
    {
	// Error Data
	response.Error.Error= ucObj->GetError();
	response.Error.ErrorNumber =ucObj->GetErrorCode();
	response.Error.ErrorType = ucObj->GetErrorType();
    }
    delete ucObj;

    return SOAP_OK;
}

xsd__int ns__DoUpdate(soap* soap, ns1__UpdateArguments* UpdateInfo, ns1__UpdateResponse &response)
{
    UpdateClass *ucObj = new UpdateClass();

    // Set Session Code
    ucObj->SetSessionCode(ucObj->UnSerializeData(UpdateInfo->SessionCode));
    ucObj->SetPreMasterKey(UpdateInfo->PreMasterKey);
    ucObj->SetUserKey(UpdateInfo->UserKey);
    ucObj->SetHardSerialNumber(UpdateInfo->HardSerial);
    ucObj->SetLastFileUpdate(UpdateInfo->FilesList.FileName);

    if (ucObj->DoUpdate())
    {
	response.FileContent = ucObj->SecureEncrypt(ucObj->GetFileContent());
    }
    else
    {
	// Error Data
	response.Error.Error= ucObj->GetError();
	response.Error.ErrorNumber =ucObj->GetErrorCode();
	response.Error.ErrorType = ucObj->GetErrorType();
    }
    delete ucObj;
    return SOAP_OK;
}

xsd__int ns__EndUpdate(soap* soap, ns1__UpdateArguments* UpdateInfo, ns1__ErrorInfo &response)
{
    UpdateClass *ucObj = new UpdateClass();

    // Set Session Code
    ucObj->SetSessionCode(ucObj->UnSerializeData(UpdateInfo->SessionCode));
    ucObj->SetUserKey(UpdateInfo->UserKey);
    ucObj->SetHardSerialNumber(UpdateInfo->HardSerial);

    if (ucObj->EndSession())
    {
	// Error Data
	response.Error= ucObj->GetError();
	response.ErrorNumber =ucObj->GetErrorCode();
	response.ErrorType = ucObj->GetErrorType();
    }

    delete ucObj;
    return SOAP_OK;
}
