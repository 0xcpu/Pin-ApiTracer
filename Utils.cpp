#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "Utils.h"

static void _InitApiArgsArray(pApiArgsArray ArgsArrayPtr)
{
    ArgsArrayPtr->Count    = 0;
    ArgsArrayPtr->Capacity = API_ARGS_LEN;
    ArgsArrayPtr->Args     = NULL;
}

void FormatArguments(char * const Buffer, const char * const cFormat, void *Args)
{
    va_list ArgsList = (va_list)Args;
    vsprintf(Buffer, cFormat, ArgsList);
}

pApiArgsArray LoadApiArgsFormat(const char * const cFileName)
{
    if (cFileName == NULL)
        return NULL;
    
    FILE *Fd = fopen(cFileName, "r");
    if (Fd == NULL)
        return NULL;

    char cApiName[API_NAME_LEN];
    char cApiArgsFormat[API_ARGS_LEN];

    pApiArgsArray ArgsArrayPtr = (pApiArgsArray)calloc(1, sizeof(ApiArgsArray));
    if (ArgsArrayPtr == NULL) {
        fclose(Fd);

        return NULL;
    }
    _InitApiArgsArray(ArgsArrayPtr);
    ArgsArrayPtr->Args = (pApiArgsFormat)calloc(ArgsArrayPtr->Capacity, sizeof(ApiArgsFormat) * ArgsArrayPtr->Capacity);
    if (ArgsArrayPtr->Args == NULL) {
        fclose(Fd);
        free(ArgsArrayPtr);

        ArgsArrayPtr = NULL;

        return NULL;
    }

    while (!feof(Fd)) {
        cApiName[0]       = 0;
        cApiArgsFormat[0] = 0;

        fscanf(Fd, "%s\t\"%[^\"]\"", &cApiName, &cApiArgsFormat);
        strncpy(ArgsArrayPtr->Args[ArgsArrayPtr->Count].cApiName, cApiName, API_NAME_LEN);
        strncpy(ArgsArrayPtr->Args[ArgsArrayPtr->Count].cApiArgsFormat, cApiArgsFormat, API_ARGS_LEN);
        ArgsArrayPtr->Args[ArgsArrayPtr->Count].cApiName[API_NAME_LEN - 1]       = 0;
        ArgsArrayPtr->Args[ArgsArrayPtr->Count].cApiArgsFormat[API_ARGS_LEN - 1] = 0;

        ArgsArrayPtr->Count++;

        if (ArgsArrayPtr->Count > ArgsArrayPtr->Capacity) {
            pApiArgsFormat NewArgsPtr = (pApiArgsFormat)realloc(ArgsArrayPtr->Args, ArgsArrayPtr->Capacity * 2);
            if (NewArgsPtr == NULL) {
                free(ArgsArrayPtr->Args);
                free(ArgsArrayPtr);
                ArgsArrayPtr->Args = NULL;
                ArgsArrayPtr       = NULL;

                break;
            } else {
                ArgsArrayPtr->Args     = NewArgsPtr;
                ArgsArrayPtr->Capacity = ArgsArrayPtr->Capacity * 2;
            }
        }
    }

    fclose(Fd);

    return ArgsArrayPtr;
}

void UnloadApiArgsFormat(pApiArgsArray ArgsArrayPtr)
{
    if (ArgsArrayPtr != NULL) {
        if (ArgsArrayPtr->Args != NULL) {
            free(ArgsArrayPtr->Args);
            ArgsArrayPtr->Args = NULL;
        }

        free(ArgsArrayPtr);
        ArgsArrayPtr = NULL;
    }
}

pApiArgsFormat FindFormatByName(const pApiArgsArray ArgsArrayPtr, const char * const cApiName)
{
    if (ArgsArrayPtr == NULL || cApiName == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < ArgsArrayPtr->Count; i++) {
        if (strncmp(ArgsArrayPtr->Args[i].cApiName, cApiName, strlen(cApiName)) == 0) {
            return &ArgsArrayPtr->Args[i];
        }
    }

    return NULL;
}

const s_Module *GetModuleByAddr(ADDRINT Address, std::map<ADDRINT, s_Module> *Modules)
{
	std::map<ADDRINT, s_Module>::iterator bound = Modules->upper_bound(Address);
	std::map<ADDRINT, s_Module>::iterator itr   = Modules->begin();
    
	for ( ; itr != bound; itr++) {
		s_Module &mod = itr->second;
		if (Address >= mod.Start && Address < mod.End) {
			return &mod;
		}
	}
    
	return NULL;
}

const bool IsSectionChanged(ADDRINT Address, std::map<ADDRINT, s_Module> *Sections)
{
	static s_Module* PrevModule = NULL;
	const  s_Module* CurrModule = GetModuleByAddr(Address, Sections);
	
	if (PrevModule != CurrModule) {
		PrevModule = (s_Module*)CurrModule;
        
		return true;
	}
    
	return false;
}

const bool IsMyModule(const s_Module* Mod, std::string Name) 
{
	if (!Mod)
        return false;
    
	std::size_t Found = Mod->Name.find(Name);
	if (Found != std::string::npos) {
        
		return true;
	}
    
	return false;
}

std::string GetFileName(const std::string& Str)
{
    std::size_t Found = Str.find_last_of("/\\");
    std::size_t Ext   = Str.find_last_of(".");
    
    return Str.substr(Found + 1, Ext - (Found + 1));
}
