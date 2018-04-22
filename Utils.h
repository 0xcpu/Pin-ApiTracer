#pragma once

#include <iostream>
#include <fstream>
#include <set>
#include <map>

#define API_NAME_LEN 256
#define API_ARGS_LEN 512

typedef struct s_Module {
    std::string Name;
	ADDRINT Start;
	ADDRINT End;
} s_Module;

typedef struct _ApiArgsFormat
{
    char cApiName[API_NAME_LEN];
    char cApiArgsFormat[API_ARGS_LEN];
} ApiArgsFormat, *pApiArgsFormat;

typedef struct _ApiArgsArray
{
    size_t Count;
    size_t Capacity;
    pApiArgsFormat Args;
} ApiArgsArray, *pApiArgsArray;

void           FormatArguments(char * const Buffer, const char * const cFormat, void *Args);
pApiArgsArray  LoadApiArgsFormat(const char * const cFilename);
void           UnloadApiArgsFormat(pApiArgsArray ArgsArrayPtr);
pApiArgsFormat FindFormatByName(const pApiArgsArray ArgsArrayPtr, const char * const cApiName);
const s_Module *GetModuleByAddr(ADDRINT Address, std::map<ADDRINT, s_Module> *Modules);
const bool     IsSectionChanged(ADDRINT Address, std::map<ADDRINT, s_Module> *Sections);
const bool     IsMyModule(const s_Module* Mod, std::string Name);
std::string    GetFileName(const std::string& Str);
