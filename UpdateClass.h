/* 
 * File:   UpdateClass.h
 * Author: root
 *
 * Created on June 2, 2014, 12:26 PM
 */

#ifndef UPDATECLASS_H
#define	UPDATECLASS_H

#include "Header.h"
#include "Crypto.h"
#include "Base64.h"
#include "MySql.h"
#include "stdsoap2.h"

class UpdateClass {
public:
    UpdateClass();
    UpdateClass(const UpdateClass& orig);
    virtual ~UpdateClass();

    bool CreateSession();
    bool PaireConnection();
    bool DoUpdate();
    bool EndSession();
    
    string GetAESKey();
    void SetAESKey(string Value);
    string GetPublicKey();
    void SetPublicKey(string Value);
    string GetPrivateKey();
    void SetPrivateKey(string Value);
    string GetPreMasterKey();
    void SetPreMasterKey(string Value);
    string GetUserKey();
    void SetUserKey(string Value);
    string GetSessionCode();
    void SetSessionCode(string Value);
    string GetMACAddress();
    void SetMACAddress(string Value);
    string GetHardSerialNumber();
    void SetHardSerialNumber(string Value);
    vector<FileInfo> GetUpdateFileList();
    void SetUpdateFileList(vector<FileInfo> Value);
    string GetLastFileUpdate();
    void SetLastFileUpdate(string Value);
    string GetFileContent();
    void SetFileContent(string Value);
    size_t GetFilesCount();
    void SetFilesCount(size_t Value);

    string GetError();
    string GetErrorCode();
    string GetErrorType();

    string GetFileName(size_t Index);
    string GetFileSize(size_t Index);
    string GetFolderName(size_t Index);

    string SerializeData(string DataArg);
    string UnSerializeData(string DataArg);
    string SecureEncrypt(string DataArg);
    string SecureDecrypt(string DataArg);
    string SecureSign(string DataArg);
    string SecureVerify(string DataArg);
    string AESEncrypt(string DataArg);
    string AESDecrypt(string DataArg);
    string RSAEncrypt(string DataArg);
    string RSADecrypt(string DataArg);

private:
    vector<FileInfo> vFileList;

    string strPublicKey, strPrivateKey, strEncryptKey, strSessionCode, strUserKey, strMACAddress, strHardSerialNo, strPreMasterKey, strMessage, strFileContent, strLastFileUpdate;

    ErrorStruct errObj;

    size_t iFilesCount;

private:
    bool ResetArguments();

    bool CheckSession();
    bool UpdateSession();
    bool CheckUser();
    bool CloseSession();

    // private Methods
    string GenerateRandomString(int lenght);
    bool GeneratRSAPairKeys();

    bool SetError(size_t ErrorType, size_t ErrorNumber, string Error);

    string Make16BitKey(string PreMasterKeyArg);

    string WString2String(wchar_t *InputArg);
    wstring String2WString(char *InputArg);

    bool Replace(std::string& str, const std::string& from, const std::string& to);
    bool ReplaceW(std::wstring& str, const std::wstring& from, const std::wstring& to);
    string TrimString(string Input);
    wstring WTrimString(wstring Input);
    string IntToString(long int IntData);
    string IntToString(long int IntData, int Format);
    wstring IntToStringW(long int IntData);
    long int FindAllMaching(string Input, string MachStr);
    bool CheckSteamFormat(string Stream, string Format);
    bool IsNumberStream(string s);
    bool CompareByFileName(const FileInfo &a, const FileInfo &b);

    bool FileExist(string FilePath);
    bool DeleteExistFile(string Path);
    bool WriteFileData(string FilePath, string Data);
    string ReadFileData(string FilePath, size_t *FileSize);
    void GetFilesInDirectory(const string &directory);

    string GetCurrentLocalTime();
};

#endif	/* UPDATECLASS_H */

