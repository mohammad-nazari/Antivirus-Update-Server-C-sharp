/* soapStub.h
   Generated by gSOAP 2.8.17r from /mnt/hgfs/APA/Projects/New Project/Update/Server/C++/Update/source.h

Copyright(C) 2000-2013, Robert van Engelen, Genivia Inc. All Rights Reserved.
The generated code is released under one of the following licenses:
GPL or Genivia's license for commercial use.
This program is released under the GPL with the additional exemption that
compiling, linking, and/or using OpenSSL is allowed.
*/

#ifndef soapStub_H
#define soapStub_H
#include <iostream>
#include <string.h>
#include <vector>
#include <vector>
#include "stdsoap2.h"
#if GSOAP_VERSION != 20817
# error "GSOAP VERSION MISMATCH IN GENERATED CODE: PLEASE REINSTALL PACKAGE"
#endif


/******************************************************************************\
 *                                                                            *
 * Enumerations                                                               *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Types with Custom Serializers                                              *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Classes and Structs                                                        *
 *                                                                            *
\******************************************************************************/


#if 0 /* volatile type: do not declare here, declared elsewhere */

#endif

#if 0 /* volatile type: do not declare here, declared elsewhere */

#endif

#ifndef SOAP_TYPE_ns1__ErrorInfo
#define SOAP_TYPE_ns1__ErrorInfo (13)
/* ns1:ErrorInfo */
class SOAP_CMAC ns1__ErrorInfo
{
public:
	std::string ErrorNumber;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:string */
	std::string Error;	/* required element of type xsd:string */
	std::string ErrorType;	/* required element of type xsd:string */
public:
	virtual int soap_type() const { return 13; } /* = unique type id SOAP_TYPE_ns1__ErrorInfo */
	virtual void soap_default(struct soap*);
	virtual void soap_serialize(struct soap*) const;
	virtual int soap_put(struct soap*, const char*, const char*) const;
	virtual int soap_out(struct soap*, const char*, int, const char*) const;
	virtual void *soap_get(struct soap*, const char*, const char*);
	virtual void *soap_in(struct soap*, const char*, const char*);
	         ns1__ErrorInfo() { ns1__ErrorInfo::soap_default(NULL); }
	virtual ~ns1__ErrorInfo() { }
};
#endif

#ifndef SOAP_TYPE_ns1__FileInfo
#define SOAP_TYPE_ns1__FileInfo (14)
/* ns1:FileInfo */
class SOAP_CMAC ns1__FileInfo
{
public:
	std::string FileName;	/* required element of type xsd:string */
	std::string FileSize;	/* required element of type xsd:string */
	std::string FolderName;	/* required element of type xsd:string */
public:
	virtual int soap_type() const { return 14; } /* = unique type id SOAP_TYPE_ns1__FileInfo */
	virtual void soap_default(struct soap*);
	virtual void soap_serialize(struct soap*) const;
	virtual int soap_put(struct soap*, const char*, const char*) const;
	virtual int soap_out(struct soap*, const char*, int, const char*) const;
	virtual void *soap_get(struct soap*, const char*, const char*);
	virtual void *soap_in(struct soap*, const char*, const char*);
	         ns1__FileInfo() { ns1__FileInfo::soap_default(NULL); }
	virtual ~ns1__FileInfo() { }
};
#endif

#ifndef SOAP_TYPE_ns1__SessionInfo
#define SOAP_TYPE_ns1__SessionInfo (17)
/* ns1:SessionInfo */
class SOAP_CMAC ns1__SessionInfo
{
public:
	std::string SessionCode;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:string */
	std::string PublicKey;	/* required element of type xsd:string */
	ns1__ErrorInfo Error;	/* required element of type ns1:ErrorInfo */
public:
	virtual int soap_type() const { return 17; } /* = unique type id SOAP_TYPE_ns1__SessionInfo */
	virtual void soap_default(struct soap*);
	virtual void soap_serialize(struct soap*) const;
	virtual int soap_put(struct soap*, const char*, const char*) const;
	virtual int soap_out(struct soap*, const char*, int, const char*) const;
	virtual void *soap_get(struct soap*, const char*, const char*);
	virtual void *soap_in(struct soap*, const char*, const char*);
	         ns1__SessionInfo() { ns1__SessionInfo::soap_default(NULL); }
	virtual ~ns1__SessionInfo() { }
};
#endif

#ifndef SOAP_TYPE_ns1__UpdateArguments
#define SOAP_TYPE_ns1__UpdateArguments (18)
/* ns1:UpdateArguments */
class SOAP_CMAC ns1__UpdateArguments
{
public:
	std::string SessionCode;	/* required element of type xsd:string */
	std::string UserKey;	/* required element of type xsd:string */
	std::string HardSerial;	/* required element of type xsd:string */
	std::string PreMasterKey;	/* required element of type xsd:string */
	ns1__FileInfo FilesList;	/* required element of type ns1:FileInfo */
	ns1__ErrorInfo Error;	/* required element of type ns1:ErrorInfo */
public:
	virtual int soap_type() const { return 18; } /* = unique type id SOAP_TYPE_ns1__UpdateArguments */
	virtual void soap_default(struct soap*);
	virtual void soap_serialize(struct soap*) const;
	virtual int soap_put(struct soap*, const char*, const char*) const;
	virtual int soap_out(struct soap*, const char*, int, const char*) const;
	virtual void *soap_get(struct soap*, const char*, const char*);
	virtual void *soap_in(struct soap*, const char*, const char*);
	         ns1__UpdateArguments() { ns1__UpdateArguments::soap_default(NULL); }
	virtual ~ns1__UpdateArguments() { }
};
#endif

#ifndef SOAP_TYPE_ns1__UpdateFilesList
#define SOAP_TYPE_ns1__UpdateFilesList (19)
/* ns1:UpdateFilesList */
class SOAP_CMAC ns1__UpdateFilesList
{
public:
	std::vector<ns1__FileInfo >FilesList;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* optional element of type xsd:FileList */
	ns1__ErrorInfo Error;	/* required element of type ns1:ErrorInfo */
public:
	virtual int soap_type() const { return 19; } /* = unique type id SOAP_TYPE_ns1__UpdateFilesList */
	virtual void soap_default(struct soap*);
	virtual void soap_serialize(struct soap*) const;
	virtual int soap_put(struct soap*, const char*, const char*) const;
	virtual int soap_out(struct soap*, const char*, int, const char*) const;
	virtual void *soap_get(struct soap*, const char*, const char*);
	virtual void *soap_in(struct soap*, const char*, const char*);
	         ns1__UpdateFilesList() { ns1__UpdateFilesList::soap_default(NULL); }
	virtual ~ns1__UpdateFilesList() { }
};
#endif

#ifndef SOAP_TYPE_ns1__UpdateResponse
#define SOAP_TYPE_ns1__UpdateResponse (20)
/* ns1:UpdateResponse */
class SOAP_CMAC ns1__UpdateResponse
{
public:
	std::string FileContent;	/* SOAP 1.2 RPC return element (when namespace qualified) */	/* required element of type xsd:string */
	ns1__ErrorInfo Error;	/* required element of type ns1:ErrorInfo */
public:
	virtual int soap_type() const { return 20; } /* = unique type id SOAP_TYPE_ns1__UpdateResponse */
	virtual void soap_default(struct soap*);
	virtual void soap_serialize(struct soap*) const;
	virtual int soap_put(struct soap*, const char*, const char*) const;
	virtual int soap_out(struct soap*, const char*, int, const char*) const;
	virtual void *soap_get(struct soap*, const char*, const char*);
	virtual void *soap_in(struct soap*, const char*, const char*);
	         ns1__UpdateResponse() { ns1__UpdateResponse::soap_default(NULL); }
	virtual ~ns1__UpdateResponse() { }
};
#endif

#ifndef SOAP_TYPE_ns__RequestForUpdate
#define SOAP_TYPE_ns__RequestForUpdate (23)
/* ns:RequestForUpdate */
struct ns__RequestForUpdate
{
public:
	int soap_type() const { return 23; } /* = unique type id SOAP_TYPE_ns__RequestForUpdate */
#ifdef WITH_NOEMPTYSTRUCT
private:
	char dummy;	/* dummy member to enable compilation */
#endif
};
#endif

#ifndef SOAP_TYPE_ns__MakeSecureConnection
#define SOAP_TYPE_ns__MakeSecureConnection (27)
/* ns:MakeSecureConnection */
struct ns__MakeSecureConnection
{
public:
	ns1__UpdateArguments *UpdateInfo;	/* optional element of type ns1:UpdateArguments */
public:
	int soap_type() const { return 27; } /* = unique type id SOAP_TYPE_ns__MakeSecureConnection */
};
#endif

#ifndef SOAP_TYPE_ns__DoUpdate
#define SOAP_TYPE_ns__DoUpdate (30)
/* ns:DoUpdate */
struct ns__DoUpdate
{
public:
	ns1__UpdateArguments *UpdateInfo;	/* optional element of type ns1:UpdateArguments */
public:
	int soap_type() const { return 30; } /* = unique type id SOAP_TYPE_ns__DoUpdate */
};
#endif

#ifndef SOAP_TYPE_ns__EndUpdate
#define SOAP_TYPE_ns__EndUpdate (33)
/* ns:EndUpdate */
struct ns__EndUpdate
{
public:
	ns1__UpdateArguments *UpdateInfo;	/* optional element of type ns1:UpdateArguments */
public:
	int soap_type() const { return 33; } /* = unique type id SOAP_TYPE_ns__EndUpdate */
};
#endif

#ifndef WITH_NOGLOBAL

#ifndef SOAP_TYPE_SOAP_ENV__Header
#define SOAP_TYPE_SOAP_ENV__Header (34)
/* SOAP Header: */
struct SOAP_ENV__Header
{
public:
	int soap_type() const { return 34; } /* = unique type id SOAP_TYPE_SOAP_ENV__Header */
#ifdef WITH_NOEMPTYSTRUCT
private:
	char dummy;	/* dummy member to enable compilation */
#endif
};
#endif

#endif

#ifndef WITH_NOGLOBAL

#ifndef SOAP_TYPE_SOAP_ENV__Code
#define SOAP_TYPE_SOAP_ENV__Code (35)
/* SOAP Fault Code: */
struct SOAP_ENV__Code
{
public:
	char *SOAP_ENV__Value;	/* optional element of type xsd:QName */
	struct SOAP_ENV__Code *SOAP_ENV__Subcode;	/* optional element of type SOAP-ENV:Code */
public:
	int soap_type() const { return 35; } /* = unique type id SOAP_TYPE_SOAP_ENV__Code */
};
#endif

#endif

#ifndef WITH_NOGLOBAL

#ifndef SOAP_TYPE_SOAP_ENV__Detail
#define SOAP_TYPE_SOAP_ENV__Detail (37)
/* SOAP-ENV:Detail */
struct SOAP_ENV__Detail
{
public:
	char *__any;
	int __type;	/* any type of element <fault> (defined below) */
	void *fault;	/* transient */
public:
	int soap_type() const { return 37; } /* = unique type id SOAP_TYPE_SOAP_ENV__Detail */
};
#endif

#endif

#ifndef WITH_NOGLOBAL

#ifndef SOAP_TYPE_SOAP_ENV__Reason
#define SOAP_TYPE_SOAP_ENV__Reason (40)
/* SOAP-ENV:Reason */
struct SOAP_ENV__Reason
{
public:
	char *SOAP_ENV__Text;	/* optional element of type xsd:string */
public:
	int soap_type() const { return 40; } /* = unique type id SOAP_TYPE_SOAP_ENV__Reason */
};
#endif

#endif

#ifndef WITH_NOGLOBAL

#ifndef SOAP_TYPE_SOAP_ENV__Fault
#define SOAP_TYPE_SOAP_ENV__Fault (41)
/* SOAP Fault: */
struct SOAP_ENV__Fault
{
public:
	char *faultcode;	/* optional element of type xsd:QName */
	char *faultstring;	/* optional element of type xsd:string */
	char *faultactor;	/* optional element of type xsd:string */
	struct SOAP_ENV__Detail *detail;	/* optional element of type SOAP-ENV:Detail */
	struct SOAP_ENV__Code *SOAP_ENV__Code;	/* optional element of type SOAP-ENV:Code */
	struct SOAP_ENV__Reason *SOAP_ENV__Reason;	/* optional element of type SOAP-ENV:Reason */
	char *SOAP_ENV__Node;	/* optional element of type xsd:string */
	char *SOAP_ENV__Role;	/* optional element of type xsd:string */
	struct SOAP_ENV__Detail *SOAP_ENV__Detail;	/* optional element of type SOAP-ENV:Detail */
public:
	int soap_type() const { return 41; } /* = unique type id SOAP_TYPE_SOAP_ENV__Fault */
};
#endif

#endif

/******************************************************************************\
 *                                                                            *
 * Typedefs                                                                   *
 *                                                                            *
\******************************************************************************/

#ifndef SOAP_TYPE__QName
#define SOAP_TYPE__QName (5)
typedef char *_QName;
#endif

#ifndef SOAP_TYPE__XML
#define SOAP_TYPE__XML (6)
typedef char *_XML;
#endif

#ifndef SOAP_TYPE_xsd__string
#define SOAP_TYPE_xsd__string (9)
typedef std::string xsd__string;
#endif

#ifndef SOAP_TYPE_xsd__int
#define SOAP_TYPE_xsd__int (10)
typedef int xsd__int;
#endif

#ifndef SOAP_TYPE_xsd__double
#define SOAP_TYPE_xsd__double (12)
typedef double xsd__double;
#endif

#ifndef SOAP_TYPE_xsd__FileList
#define SOAP_TYPE_xsd__FileList (16)
typedef std::vector<ns1__FileInfo >xsd__FileList;
#endif


/******************************************************************************\
 *                                                                            *
 * Externals                                                                  *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Server-Side Operations                                                     *
 *                                                                            *
\******************************************************************************/


SOAP_FMAC5 int SOAP_FMAC6 ns__RequestForUpdate(struct soap*, ns1__SessionInfo &response);

SOAP_FMAC5 int SOAP_FMAC6 ns__MakeSecureConnection(struct soap*, ns1__UpdateArguments *UpdateInfo, ns1__UpdateFilesList &response);

SOAP_FMAC5 int SOAP_FMAC6 ns__DoUpdate(struct soap*, ns1__UpdateArguments *UpdateInfo, ns1__UpdateResponse &response);

SOAP_FMAC5 int SOAP_FMAC6 ns__EndUpdate(struct soap*, ns1__UpdateArguments *UpdateInfo, ns1__ErrorInfo &response);

/******************************************************************************\
 *                                                                            *
 * Server-Side Skeletons to Invoke Service Operations                         *
 *                                                                            *
\******************************************************************************/

extern "C" SOAP_FMAC5 int SOAP_FMAC6 soap_serve(struct soap*);

extern "C" SOAP_FMAC5 int SOAP_FMAC6 soap_serve_request(struct soap*);

SOAP_FMAC5 int SOAP_FMAC6 soap_serve_ns__RequestForUpdate(struct soap*);

SOAP_FMAC5 int SOAP_FMAC6 soap_serve_ns__MakeSecureConnection(struct soap*);

SOAP_FMAC5 int SOAP_FMAC6 soap_serve_ns__DoUpdate(struct soap*);

SOAP_FMAC5 int SOAP_FMAC6 soap_serve_ns__EndUpdate(struct soap*);

#endif

/* End of soapStub.h */
