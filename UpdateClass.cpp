/* 
 * File:   UpdateClass.cpp
 * Author: root
 * 
 * Created on June 2, 2014, 12:26 PM
 */

#include "UpdateClass.h"

UpdateClass::UpdateClass()
{
    this->ResetArguments();
}

UpdateClass::UpdateClass(const UpdateClass& orig)
{
}

UpdateClass::~UpdateClass()
{
}

string UpdateClass::GetAESKey()
{
    return this->strEncryptKey;
}

void UpdateClass::SetAESKey(string Value)
{
    this->strEncryptKey = Value;
}

string UpdateClass::GetPublicKey()
{
    return this->strPublicKey;
}

void UpdateClass::SetPublicKey(string Value)
{
    this->strPublicKey = Value;
}

string UpdateClass::GetPrivateKey()
{
    return this->strPrivateKey;
}

void UpdateClass::SetPrivateKey(string Value)
{
    this->strPrivateKey = Value;
}

string UpdateClass::GetPreMasterKey()
{
    return this->strPreMasterKey;
}

void UpdateClass::SetPreMasterKey(string Value)
{
    this->strPreMasterKey = Value;
}

string UpdateClass::GetUserKey()
{
    return this->strUserKey;
}

void UpdateClass::SetUserKey(string Value)
{
    this->strUserKey = Value;
}

string UpdateClass::GetSessionCode()
{
    return this->strSessionCode;
}

void UpdateClass::SetSessionCode(string Value)
{
    this->strSessionCode = Value;
}

string UpdateClass::GetMACAddress()
{
    return this->strMACAddress;
}

void UpdateClass::SetMACAddress(string Value)
{
    this->strMACAddress = Value;
}

string UpdateClass::GetHardSerialNumber()
{
    return this->strHardSerialNo;
}

void UpdateClass::SetHardSerialNumber(string Value)
{
    this->strHardSerialNo = Value;
}

vector<FileInfo> UpdateClass::GetUpdateFileList()
{
    return this->vFileList;
}

void UpdateClass::SetUpdateFileList(vector<FileInfo> Value)
{
    this->vFileList = Value;
}

string UpdateClass::GetLastFileUpdate()
{
    return this->strLastFileUpdate;
}

void UpdateClass::SetLastFileUpdate(string Value)
{
    this->strLastFileUpdate = Value;
}

string UpdateClass::GetFileContent()
{
    return this->strFileContent;
}

void UpdateClass::SetFileContent(string Value)
{
    this->strFileContent = Value;
}

size_t UpdateClass::GetFilesCount()
{
    return this->iFilesCount;
}

void UpdateClass::SetFilesCount(size_t Value)
{
    this->iFilesCount = Value;
}

string UpdateClass::GetFileName(size_t Index)
{
    return this->vFileList[Index].FileName;
}

string UpdateClass::GetFileSize(size_t Index)
{
    return this->IntToString(this->vFileList[Index].FileSize);
}

string UpdateClass::GetFolderName(size_t Index)
{
    return this->vFileList[Index].FolderName;
}

string UpdateClass::GetError()
{
    return this->errObj.Error;
}

string UpdateClass::GetErrorCode()
{
    return this->IntToString(this->errObj.ErrorNumber);
}

string UpdateClass::GetErrorType()
{
    return this->IntToString(this->errObj.ErrorType);
}

bool UpdateClass::ResetArguments()
{
    this->strPublicKey.clear();
    this->strPrivateKey.clear();
    this->strEncryptKey.clear();
    this->strSessionCode.clear();
    this->strUserKey.clear();
    this->strMACAddress.clear();
    this->strHardSerialNo.clear();
    this->strPreMasterKey.clear();
    this->strMessage.clear();
    this->strFileContent.clear();
    this->strLastFileUpdate.clear();

    this->errObj.Error.clear();
    this->errObj.ErrorType = 0;
    this->errObj.ErrorNumber = 0;

    this->vFileList.clear();

    return true;
}

bool UpdateClass::CreateSession()
{
    MySql mysqlObj;
    // Connect to Database
    mysqlObj.connect(MYSQLSERVER, MYSQLUSER, MYSQLPASSWORD, MYSQLDATABAE);

    if (mysqlObj.resultError == "") // Connection OK
    {
	// Generate SessionCode Random string (32 byte)
	this->strSessionCode = this->GenerateRandomString(32);

	// Generate RSA Private and Public Key
	this->GeneratRSAPairKeys();

	// Get Current Time
	string strCurrentTime = this->GetCurrentLocalTime();

	// Generate Insert Query string
	string strQuery = "INSERT INTO `Session`(`SessionCode`, `SessionPrivateKey`, `SessionPublicKey`, `SessionActive`, `SessionStartDate`) VALUES (\'"  + this->strSessionCode + "\',\'" + this->strPrivateKey + "\',\'" + this->strPublicKey + "\',1,\'" + strCurrentTime + "\')";

	// Execute
	mysqlObj.execute(strQuery);
	if (mysqlObj.resultError != "")
	{
	    this->SetError(MYSQLERROR, MYSQLINSERTERRORC, MYSQLINSERTERROR);
	    return false;
	}
    }
    else    // Error in Connection
    {
	this->SetError(MYSQLERROR, MYSQLCONNECTIONERRORC, MYSQLCONNECTIONERROR);
	return false;
    }

    return true;
}

bool UpdateClass::PaireConnection()
{
    if (this->CheckSession())
    {
	this->strPreMasterKey = this->UnSerializeData(this->strPreMasterKey);
	this->strEncryptKey = this->Make16BitKey(this->strPreMasterKey);

	this->strUserKey = this->SecureDecrypt(this->strUserKey);
	this->strHardSerialNo = this->SecureDecrypt(this->strHardSerialNo);

	this->strLastFileUpdate = this->SecureDecrypt(this->strLastFileUpdate);

	// Check User Info
	if (this->CheckUser()) // User is Valid
	{
	    if (this->UpdateSession()) // Set User Info into Session Topple
	    {
		// Get List of Update Files
		this->GetFilesInDirectory(UPDATEFILESDIRECTORY);

		// Number of Update Files
		this->iFilesCount = this->vFileList.size();
	    }
	    else
	    {
		return false;
	    }
	}
	else
	{
	    return false;
	}
    }
    else
    {
	return false;
    }

    return true;
}

bool UpdateClass::DoUpdate()
{
    if (this->CheckSession())
    {
	this->strUserKey = this->SecureDecrypt(this->strUserKey);
	this->strHardSerialNo = this->SecureDecrypt(this->strHardSerialNo);

	this->strLastFileUpdate = this->SecureDecrypt(this->strLastFileUpdate);

	// Check User Info
	if (this->CheckUser()) // User is Valid
	{
	    size_t fileSize;
	    string filePath = UPDATEFILESDIRECTORY;
	    filePath += "/" + this->strLastFileUpdate;
	    this->strFileContent = this->ReadFileData(filePath, &fileSize);
	}
	else
	{
	    return false;
	}
    }
    else
    {
	return false;
    }

    return true;
}

bool UpdateClass::EndSession()
{
    if (this->CheckSession())
    {
	this->strUserKey = this->SecureDecrypt(this->strUserKey);
	this->strHardSerialNo = this->SecureDecrypt(this->strHardSerialNo);

	// Check User Info
	if (this->CheckUser()) // User is Valid
	{
	    this->CloseSession();
	}
	else
	{
	    return false;
	}
    }
    else
    {
	return false;
    }

    return true;
}

bool UpdateClass::CheckSession()
{
    MySql mysqlObj;
    // Connect to Database
    mysqlObj.connect(MYSQLSERVER, MYSQLUSER, MYSQLPASSWORD, MYSQLDATABAE);

    if (mysqlObj.resultError == "") // Connection OK
    {
	string strQuery = "SELECT `SessionPrivateKey`, `SessionAESKey`, `SessionActive` FROM `Session` WHERE `SessionCode` = \'" + this->strSessionCode + "\';";

	// Execute
	mysqlObj.execute(strQuery);
	if (mysqlObj.resultError != "")
	{
	    this->SetError(MYSQLERROR, MYSQLINSERTERRORC, MYSQLINSERTERROR);
	    return false;
	}

	// Fetch Result
	ResultSet rsObj;
	mysqlObj.populate(rsObj);

	// Session not exist
	if (rsObj.countRows() == 0)
	{
	    this->SetError(SESSIONERROR, SESSIONINVALIDC, SESSIONINVALID);
	    return false;
	}

	// Fetch Result
	std::vector<std::string> fieldsVect;
	rsObj.fetch(fieldsVect);

	// Set Info
	this->strPrivateKey = fieldsVect[0];
	this->strEncryptKey = fieldsVect[1];

	if (atoi(fieldsVect[2].c_str()) == false)
	{
	    this->SetError(SESSIONERROR, SESSIONEXPIREDC, SESSIONEXPIRED);
	    return false;
	}
    }
    return true;
}

bool UpdateClass::UpdateSession()
{
    MySql mysqlObj;
    // Connect to Database
    mysqlObj.connect(MYSQLSERVER, MYSQLUSER, MYSQLPASSWORD, MYSQLDATABAE);

    if (mysqlObj.resultError == "") // Connection OK
    {
	string strQuery = "UPDATE `Session` SET `SessionUserKey`= \'" + this->strUserKey + "\', `SessionAESKey`= \'" + this->strEncryptKey + "\' WHERE `SessionCode` = \'" + this->strSessionCode + "\';";

	// Execute
	mysqlObj.execute(strQuery);
	if (mysqlObj.resultError != "")
	{
	    this->SetError(MYSQLERROR, MYSQLINSERTERRORC, MYSQLINSERTERROR);
	    return false;
	}
    }
    return true;
}

bool UpdateClass::CheckUser()
{
    MySql mysqlObj;
    // Connect to Database
    mysqlObj.connect(MYSQLSERVER, MYSQLUSER, MYSQLPASSWORD, MYSQLDATABAE);

    if (mysqlObj.resultError == "") // Connection OK
    {
	string strQuery = "SELECT `ID` FROM `Users` WHERE `UsersKey` = \'" + this->strUserKey + "\' and `MACAddress` = \'" + this->strHardSerialNo + "\';";

	// Execute
	mysqlObj.execute(strQuery);
	if (mysqlObj.resultError != "")
	{
	    this->SetError(MYSQLERROR, MYSQLINSERTERRORC, MYSQLINSERTERROR);
	    return false;
	}

	// Fetch Result
	ResultSet rsObj;
	mysqlObj.populate(rsObj);

	// Session not exist
	if (rsObj.countRows() == 0)
	{
	    this->SetError(USERINFOERRO, USERKEYINVALIDC, USERKEYINVALID);
	    return false;
	}
    }
    return true;
}

bool UpdateClass::CloseSession()
{
    string strCurrentTime = this->GetCurrentLocalTime();
    MySql mysqlObj;
    // Connect to Database
    mysqlObj.connect(MYSQLSERVER, MYSQLUSER, MYSQLPASSWORD, MYSQLDATABAE);

    if (mysqlObj.resultError == "") // Connection OK
    {
	string strQuery = "UPDATE `Session` SET `SessionActive`= 0, `SessionEndDate`= \'" + strCurrentTime + "\' WHERE `SessionCode` = \'" + this->strSessionCode + "\';";
	// Execute
	mysqlObj.execute(strQuery);
	if (mysqlObj.resultError != "")
	{
	    this->SetError(MYSQLERROR, MYSQLINSERTERRORC, MYSQLINSERTERROR);
	    return false;
	}
    }
    return true;
}

string UpdateClass::GenerateRandomString(int lenght)
{
    string strTemp;
    //create a random password here
    char charArray[] ={'a', 'A', 'b', 'B', 'c', 'C', 'd', 'D', 'e', 'E', 'f', 'F', 'g', 'G', 'h', 'H', 'i', 'I', 'j', 'J', 'k', 'K', 'l', 'L', 'm', 'M', 'n', 'N', 'o', 'O', 'p', 'P', 'q', 'Q', 'r', 'R', 's', 'S',	't', 'T', 'u', 'U', 'v', 'V', 'w', 'W', 'x', 'X', 'y', 'Y', 'z', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '?', '<', '>', '.', ',', ';', '-', '@', '!', '#', '$', '%', '^', '&', '*', '(', ')'};
    long int max_chars = sizeof (charArray) - 1;
    srand(time(0) * 1000000);

    strTemp.clear();

    for (long int i = 0; i < PREMASTERKEYLENGTH; i++)
    {
	strTemp.push_back(charArray[rand() % max_chars]);
    }

    return strTemp;
}

bool UpdateClass::GeneratRSAPairKeys()
{
    Crypto crpObj;
    crpObj.GeneratePairKey();
    this->strPrivateKey = crpObj.privateKey;
    this->strPublicKey = crpObj.publicKey;

    return true;
}

string UpdateClass::Make16BitKey(string PreMasterKeyArg)
{
    size_t first = 0, limit = 0, pmKeyLen = strlen(PreMasterKeyArg.c_str());

    if (pmKeyLen)
    {
	uchar strAESKey[(AES_KEYLEN / 8)];
	uchar md5Out[32];
	MD5((const uchar *) PreMasterKeyArg.c_str(), pmKeyLen, md5Out);

	first = md5Out[15];
	limit = md5Out[13] * md5Out[14];

	first = (first < pmKeyLen ? first : first % pmKeyLen);
	limit = (limit < (pmKeyLen - first) ? limit : limit % (pmKeyLen - first));

	// Second mD5 from first MD5 of pre_master Key in a limited string of pre_master Key
	MD5((const unsigned char *) PreMasterKeyArg.c_str() + first, limit, strAESKey);

	// Length of AES key is 256 bit(32 byte) else is 128 bit(16 byte)
	if ((AES_KEYLEN / 8) == 32)
	{
	    MD5((const unsigned char *) PreMasterKeyArg.c_str() + first, limit, strAESKey + 16);
	}

	Coding codingObj;

	string strAESEncryptKey = codingObj.base64_encode((const unsigned char *) strAESKey, (AES_KEYLEN / 8));

	return strAESEncryptKey;
    }
    else
    {
	return "";
    }
}

//************************************
// Method:    SerializeData
// FullName:  UpdateClass::SerializeData
// Access:    public 
// Returns:   string
// Qualifier:
// Parameter: string DataArg
// Summary:	  Encode string into Base64Binary
//************************************

string UpdateClass::SerializeData(string DataArg)
{
    /*int iSize = DataArg.size();
    char *strTemp = new char[iSize];
    soap_s2base64(NULL,(const unsigned char *)DataArg.c_str(),strTemp,iSize);

    return strTemp;*/

    Coding codingObj;

    DataArg = codingObj.base64_encode((const unsigned char *) DataArg.c_str(), DataArg.size());

    return DataArg;
}

//************************************
// Method:    UnSerializeData
// FullName:  UpdateClass::UnSerializeData
// Access:    public 
// Returns:   string
// Qualifier:
// Parameter: string DataArg
// Summary:	  Decode Base64Binary into string
//************************************

string UpdateClass::UnSerializeData(string DataArg)
{
    /*int iSize = DataArg.size();
    char *strTemp = new char[iSize];
    soap_base642s(NULL,DataArg.c_str(),strTemp,iSize,&iSize);

    return strTemp;*/

    Coding codingObj;

    DataArg = codingObj.base64_decode(DataArg);

    return DataArg;
}

//************************************
// Method:    SecureEncrypt
// FullName:  UpdateClass::SecureEncrypt
// Access:    public 
// Returns:   string
// Qualifier:
// Parameter: string DataArg
// Summary:	  Encrypt by public key
//************************************

string UpdateClass::SecureEncrypt(string DataArg)
{
    DataArg = this->AESEncrypt(DataArg);

    //return Cipher data
    return DataArg;
}

//************************************
// Method:    SecureDecrypt
// FullName:  UpdateClass::SecureDecrypt
// Access:    public 
// Returns:   string
// Qualifier:
// Parameter: string DataArg
// Summary:	  Decrypt by private key
//************************************

string UpdateClass::SecureDecrypt(string DataArg)
{
    DataArg = this->AESDecrypt(DataArg);

    //return Plain data
    return DataArg;
}

//************************************
// Method:    SecureVerify
// FullName:  UpdateClass::SecureVerify
// Access:    private 
// Returns:   string
// Qualifier:
// Parameter: string DataArg
// Summary:	  Just Verify and Get rijndael data
//************************************

string UpdateClass::SecureSign(string DataArg)
{
    //return Plain data
    return DataArg;
}

//************************************
// Method:    SecureVerify
// FullName:  UpdateClass::SecureVerify
// Access:    private 
// Returns:   string
// Qualifier:
// Parameter: string DataArg
// Summary:	  Just Verify and Get rijndael data
//************************************

string UpdateClass::SecureVerify(string DataArg)
{
    //return Plain data
    return DataArg;
}

//************************************
// Method:    AESEncrypt
// FullName:  UpdateClass::AESEncrypt
// Access:    private 
// Returns:   string
// Qualifier:
// Parameter: string DataArg
// Summary:	  Encrypt data with AES Rijndael algorithm
//			  with 16Byte(128 bit) length key and
//			  32Byte(256 bit) length encryption block
//************************************

string UpdateClass::AESEncrypt( string DataArg )
{
    Crypto crpObj;
    if (crpObj.setAESKey(this->strEncryptKey) == SUCCESS)
    {
	if (crpObj.AESEncrypt(DataArg) == SUCCESS)
	{
	    DataArg = crpObj.strEncryptMessage;
	}
	else
	{
	    return "";
	}
    }
    else
    {
	return "";
    }

    //return Cipher data
    return DataArg;
}

//************************************
// Method:    AESDecrypt
// FullName:  UpdateClass::AESDecrypt
// Access:    private 
// Returns:   string
// Qualifier:
// Parameter: string DataArg
// Summary:	  Decrypt data with AES Rijndael algorithm
//			  with 16Byte(128 bit) length key and
//			  32Byte(256 bit) decryption block
//************************************

string UpdateClass::AESDecrypt( string DataArg )
{
    Crypto crpObj;
    if (crpObj.setAESKey(this->strEncryptKey) == SUCCESS)
    {
	if (crpObj.AESDecrypt(DataArg) == SUCCESS)
	{
	    DataArg = crpObj.strDecryptMessage;
	}
	else
	{
	    return "";
	}
    }
    else
    {
	return "";
    }

    //return Plain data
    return DataArg;
}


//************************************
// Method:    AESEncrypt
// FullName:  UpdateClass::AESEncrypt
// Access:    private 
// Returns:   string
// Qualifier:
// Parameter: string DataArg
// Summary:	  Encrypt data with AES Rijndael algorithm
//			  with 16Byte(128 bit) length key and
//			  32Byte(256 bit) length encryption block
//************************************

string UpdateClass::RSAEncrypt(string DataArg)
{
    Crypto crpObj;
    if (crpObj.setPriKey((unsigned char*) this->strPrivateKey.c_str(), this->strPrivateKey.size()) == SUCCESS)
    {
	if (crpObj.RSAEncrypt(DataArg) == SUCCESS)
	{
	    DataArg = crpObj.strEncryptMessage;
	}
	else
	{
	    return "";
	}
    }
    else
    {
	return "";
    }

    //return Cipher data
    return DataArg;
}

//************************************
// Method:	AESDecrypt
// FullName:	UpdateClass::AESDecrypt
// Access:	private 
// Returns:	string
// Qualifier:
// Parameter:	string DataArg
// Summary:	Decrypt data with AES Rijndael algorithm
//		with 16Byte(128 bit) length key and
//		32Byte(256 bit) decryption block
//************************************

string UpdateClass::RSADecrypt( string DataArg )
{
    Crypto crpObj;
    if (crpObj.setPriKey((unsigned char*) this->strPrivateKey.c_str(), this->strPrivateKey.size()) == SUCCESS)
    {
	if (crpObj.RSADecrypt(DataArg) == SUCCESS)
	{
	    DataArg = crpObj.strDecryptMessage;
	}
	else
	{
	    return "";
	}
    }
    else
    {
	return "";
    }

    //return Plain data
    return DataArg;
}

bool UpdateClass::SetError(size_t ErrorType, size_t ErrorNumber, string Error)
{
    this->errObj.Error = Error;
    this->errObj.ErrorNumber = ErrorNumber;
    this->errObj.ErrorType = ErrorType;
    return true;
}

/* Returns a list of files in a directory (except the ones that begin with a dot) */

void UpdateClass::GetFilesInDirectory(const string &directory)
{
    struct dirent **namelist;
    int n, i;

    FileInfo fiObj;
    // Search and list all files in this Directory and Sort it
    n = scandir(directory.c_str(), &namelist, 0, versionsort);
    if (n > 0)
    {
	size_t lastFileDate = atoi(this->strLastFileUpdate.substr(0, 8).c_str());
	size_t lastFileNo = atoi(this->strLastFileUpdate.substr(9, string::npos).c_str());
	for (i =0 ; i < n; ++i)
	{
	    if (this->IsNumberStream(namelist[i]->d_name))
	    {
		string strFileDate = namelist[i]->d_name;
		size_t fileDate = atoi(strFileDate.substr(0, 8).c_str());
		size_t fileNo = atoi(strFileDate.substr(9, string::npos).c_str());
		if (lastFileDate < fileDate || (lastFileDate == fileDate && lastFileNo < fileNo))
		{
		    //this->files.push_back(namelist[i]->d_name);
		    fiObj.FileName = namelist[i]->d_name;
		    struct stat filestatus;
		    string filePath = directory + "/" + namelist[i]->d_name;
		    stat(filePath.c_str() , &filestatus );
		    fiObj.FileSize = filestatus.st_size;

		    this->vFileList.push_back(fiObj);
		    free(namelist[i]);
		}
	    }
	}
	free(namelist);
    }

} // GetFilesInDirectory

string UpdateClass::IntToString( long int IntData )
{
    // Temporary string
    string result = static_cast<ostringstream*> ( &(ostringstream() << IntData) )->str();
    return result;
}

string UpdateClass::IntToString( long int IntData, int Format )
{
    // Temporary string
    char format[10];
    char result[1000];
    sprintf(format, "%%0%dd", Format);

    sprintf(result, format, IntData);
    //= static_cast<ostringstream*> (&(ostringstream() << IntData))->str();
    return result;
}

std::wstring UpdateClass::IntToStringW( long int IntData )
{
    // Temporary string
    wstring result = static_cast<wostringstream*> ( &(wostringstream() << IntData) )->str();
    return result;
}

string UpdateClass::GetCurrentLocalTime()
{
    time_t rawtime;
    struct tm stcDateTime;

    time ( &rawtime ); //get current date time
    stcDateTime = *gmtime( &rawtime );

    // Generate Insert Query string
    string strLocalTime = this->IntToString(stcDateTime.tm_year + 1900, 4) + "-" + this->IntToString(stcDateTime.tm_mon + 1, 2) + "-" + this->IntToString(stcDateTime.tm_mday, 2) + " " + this->IntToString(stcDateTime.tm_hour, 2) + ":" + this->IntToString(stcDateTime.tm_min, 2) + ":" + this->IntToString(stcDateTime.tm_sec, 2);

    return strLocalTime;
}

//************************************
// Method:	CheckFileFormat
// FullName:	UpdateClass::CheckFileFormat
// Access:	private
// Returns:	bool
// Qualifier:
// Parameter:	string FileContent
// Parameter:	string Format
// Summary:	Check data format with regular expression
//************************************

bool UpdateClass::CheckSteamFormat(string Stream, string Format)
{
    regex *r = new regex(Format);
    smatch results;

    if (regex_match(Stream, *r))
	return true;
    else
	return false;
}

bool UpdateClass::IsNumberStream(string s)
{
    //    return !s.empty() && std::find_if(s.begin(),
    //				      s.end(), [](char c)
    //				      {
    //					  return !std::isdigit(c); }) == s.end();
    size_t iLength = s.size();
    for (int i = 0; i < iLength ; i++)
    {
	if (!isdigit(s[i]) && s[i] != '_')
	    return false;
    }
    return true;
}

bool UpdateClass::CompareByFileName(const FileInfo &a, const FileInfo &b)
{
    return a.FileName < b.FileName;
}

//************************************
// Method:    ReadFileData
// FullName:  UpdateClass::ReadFileData
// Access:    private 
// Returns:   string
// Qualifier:
// Parameter: string Address
// Summary:	  read file data
//************************************

string UpdateClass::ReadFileData( string Address, size_t *FSize )
{
    FILE *fFile;
    try
    {
	fFile = fopen(Address.c_str(), "rb");
	if (fFile)
	{
	    fseek(fFile, 0, SEEK_END);
	    *FSize = ftell(fFile);
	    fseek(fFile, 0, SEEK_SET);
	    if (*FSize > 0)
	    {
		char *cFileData = new char[*FSize + 1];
		fread(cFileData, *FSize, sizeof (char), fFile);
		cFileData[*FSize] = 0;
		fclose(fFile);
		string tmp(cFileData);

		delete[] cFileData;

		return tmp;
	    }
	    fclose(fFile);
	    return "";
	}
	return "";
    }
    catch (exception* e)
    {
	//this->strErroCode = e->what();
    }
    return "";
}