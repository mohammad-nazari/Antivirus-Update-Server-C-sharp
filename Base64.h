#ifndef _CODING_H_
#define _CODING_H_
/********************************************************************
	created:	2013/08/20
	created:	20:8:2013   15:47
	filename: 	F:\APA\Projects\New Project\Webservice\DownloadFile Unicode\DownloadFile\Coding.h
	file path:	F:\APA\Projects\New Project\Webservice\DownloadFile Unicode\DownloadFile
	file base:	Coding
	file ext:	h
	author:		Mohammad Nazari
	
	purpose:	Encode and Decode strings
*********************************************************************/

#include <iosfwd>
#include <fstream>
#include <ostream>
#include <istream>
#include <stdio.h>
#include <locale>
#include <string.h>
#include <math.h>


class Coding
{
public:
	Coding();
	~Coding();
	std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
	std::string base64_decode(std::string const& encoded_string);
protected:
private:
	std::string base64_chars;
	static inline bool is_base64(unsigned char c);
};
#endif