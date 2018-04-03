/*
 * ApiTracer, CC by: hasherezade@gmail.com
 * Runs with: Intel PIN (https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)
 *
 * This tool can be used for logging: 
 * - names of the called imports
 * - strings given as the arguments to some chosen functions
 *
 * args:
 * -m	<module_name>
 *      Analysed module name (by default: same as the main app name; 
 *      if you change it you can also trace the calls named from inside some of the loaded DLLs)
 * -o	<output_path> - Output file
 *
 * Pin version 3.6 by 0xcpu
 */

#include "pin.h"
#include "Utils.h"

#define TOOL_NAME    "ApiTracer"
#define AT_PAGE_SIZE 0x1000
#define UNKNOWN_ADDR (-1)
#if _WIN64
#define HEX_PADD "018" // 16 + 2(because of # in format specifier)
#else
#define HEX_PADD "010"
#endif

/* ================================================================== */
// Global variables 
/* ================================================================== */

string g_AnalysedApp;
string g_Param;
string g_StringsFileName;

FILE *g_TraceFile   = NULL; // trace log
FILE *g_StringsFile = NULL; // collect dumped strings

INT g_MyPid;         	    // PID of application

pApiArgsArray g_ArgsArrayPtr;
char *g_Args;

std::map<ADDRINT, s_Module> g_Modules;
std::map<ADDRINT, s_Module> g_Sections;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
                            "o", "", "specify file name for the output");

KNOB<string> KnobModuleName(KNOB_MODE_WRITEONCE,  "pintool",
                            "m", "", "Analysed module name (by default same as app name)");

KNOB<string> KnobInputArgsFile(KNOB_MODE_WRITEONCE,  "pintool",
                               "f", "", "specify file name for API format args");

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID SaveTranitions(ADDRINT Address, UINT32 NumInstInBbl)
{
    PIN_LockClient();

    static ADDRINT  PrevAddr = UNKNOWN_ADDR;

    static s_Module *PrevMod = NULL;
    const  s_Module *ModPtr  = GetModuleByAddr(Address, &g_Modules);

    static bool IsPrevMy = false;
    bool IsCurrMy = IsMyModule(ModPtr, g_AnalysedApp);

    if (IsCurrMy == false && IsPrevMy == true && PrevAddr != UNKNOWN_ADDR) {
	if (ModPtr) {
#if _WIN64
	    fprintf(g_TraceFile, "%#" HEX_PADD "llx,%s.", PrevAddr, GetFileName(ModPtr->Name).c_str());
#else
            fprintf(g_TraceFile, "%#" HEX_PADD "x,%s.", PrevAddr, GetFileName(ModPtr->Name).c_str());
#endif
	    IMG Img = IMG_FindByAddress(Address);
	    RTN Rtn = RTN_FindByAddress(Address);
	    if (IMG_Valid(Img) && RTN_Valid(Rtn)) {
		const string Func = RTN_Name(Rtn);
		fprintf(g_TraceFile, "%s", Func.c_str());
	    }
	    fprintf(g_TraceFile, "\n");
	} else {
#if _WIN64
            fprintf(g_TraceFile, "%#" HEX_PADD "llx,unknown module [%#" HEX_PADD "llx]\n", PrevAddr, Address);
#else
	    fprintf(g_TraceFile, "%#" HEX_PADD "x,unknown module [%#" HEX_PADD "x]\n", PrevAddr, Address);
#endif
	}
	fflush(g_TraceFile);
    }

    if (IsCurrMy) {
	ADDRINT ImgBase = Address - ModPtr->Start; // substract module's ImageBase
	const s_Module* Section = GetModuleByAddr(ImgBase, &g_Sections);
	if (IsSectionChanged(ImgBase, &g_Sections)) {
	    std::string Name = (Section != NULL) ? Section->Name : "?";
#if _WIN64
            fprintf(g_TraceFile, "%#" HEX_PADD "llx,[section]: %s\n", ImgBase, Name.c_str());
#else
	    fprintf(g_TraceFile, "%#" HEX_PADD "x,[section]: %s\n", ImgBase, Name.c_str());
#endif
	    fflush(g_TraceFile);
	}
	PrevAddr = ImgBase; /* update saved */
    }

    /* update saved */
    IsPrevMy = IsCurrMy;
    PrevMod  = (s_Module*)ModPtr;

    PIN_UnlockClient();
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Insert call to the SaveTranitions() analysis routine before every basic block 
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID InstrumentTrace(TRACE Trace, VOID *V)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(Trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
	    // Insert a call to SaveTranitions() before every basic block
	    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE,
			       (AFUNPTR)SaveTranitions,
			       IARG_INST_PTR,
			       IARG_UINT32, BBL_NumIns(bbl),
			       IARG_END);
	    }
	}
}

VOID LogFunction1WChar(const char * const cName, const wchar_t * const wStr)
{
    if (wStr == NULL)
        return;
    fprintf(g_StringsFile, "[%s] %ls\n", cName, wStr);
    fflush(g_StringsFile);
}

VOID LogFunction1Char(const char * const cName, const char * const cStr)
{
    if (cStr == NULL)
        return;
    fprintf(g_StringsFile, "[%s] %s\n", cName, cStr);
    fflush(g_StringsFile);
}

VOID LogFunction2WChar(const char    * const cFuncName,
                       const wchar_t * const wFileName,
                       const wchar_t * const wArgs)
{
    if (wFileName == NULL)
        return;
    fprintf(g_StringsFile, "[%s] : %ls : %ls\n", cFuncName, wFileName, wArgs);
    fflush(g_StringsFile);
}

VOID LogSentData(const char    * const cFuncName,
                 const wchar_t * const wHeaders,
                 const uint32_t HeadersLength,
                 const unsigned char * const cContent,
                 const uint32_t ContentLen)
{
    if (wHeaders == NULL)
        return;
    fprintf(g_StringsFile, "[%s] : [%d]%ls : [%d]\n", cFuncName, HeadersLength, wHeaders, ContentLen);
    for (uint32_t i = 0; i < ContentLen; i++) {
	if (isalnum(cContent[i])) {
	    fprintf(g_StringsFile, "%c ", cContent[i]);
	} else {
	    fprintf(g_StringsFile, ". ", cContent[i]);
	}
    }
    if (ContentLen) {
	fprintf(g_StringsFile, "\nhex: \n");
    }
    for (uint32_t i = 0; i < ContentLen; i++) {
	fprintf(g_StringsFile, "%#" HEX_PADD "x ", cContent[i]);
    }
    if (ContentLen) {
	fprintf(g_StringsFile, "---\n");
    }
    fflush(g_StringsFile);
}

VOID MonitorFunction1Arg(IMG Image, const char * const cFuncName)
{
    RTN CfwRtn = RTN_FindByName(Image, cFuncName);
    if (RTN_Valid(CfwRtn))
	{
	    RTN_Open(CfwRtn);
	    RTN_InsertCall(CfwRtn, IPOINT_BEFORE, (AFUNPTR)LogFunction1WChar,
			   IARG_ADDRINT, cFuncName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END);
	    RTN_Close(CfwRtn);
	}
}

VOID MonitorCreateProcess(IMG Image, const char * const cFuncName)
{
    RTN CfwRtn = RTN_FindByName(Image, cFuncName);
    if (RTN_Valid(CfwRtn))
	{
	    RTN_Open(CfwRtn);
	    RTN_InsertCall(CfwRtn, IPOINT_BEFORE, (AFUNPTR)LogFunction2WChar,
			   IARG_ADDRINT, cFuncName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			   IARG_END);
	    RTN_Close(CfwRtn);
	}
}

VOID MonitorWideCharToMultiByte(IMG Image, const char * const cFuncName)
{
    RTN CfwRtn = RTN_FindByName(Image, cFuncName);
    if (RTN_Valid(CfwRtn))
	{
	    RTN_Open(CfwRtn);
	    RTN_InsertCall(CfwRtn, IPOINT_BEFORE, (AFUNPTR)LogFunction1WChar,
			   IARG_ADDRINT, cFuncName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			   IARG_END);
	    RTN_Close(CfwRtn);
	}
}

VOID MonitorVsnsprintf(IMG Image, const char * const funcName)
{
    RTN CfwRtn = RTN_FindByName(Image, funcName);
    if (RTN_Valid(CfwRtn))
	{
	    RTN_Open(CfwRtn);
	    RTN_InsertCall(CfwRtn, IPOINT_AFTER, (AFUNPTR)LogFunction1Char,
			   IARG_ADDRINT, funcName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END
			   );
	    RTN_Close(CfwRtn);
	}
}

VOID MonitorCreateFileW(IMG Image, const char * const cFuncName)
{
    RTN CfwRtn = RTN_FindByName(Image, cFuncName);
    if (RTN_Valid(CfwRtn))
	{
	    RTN_Open(CfwRtn);
	    RTN_InsertCall(CfwRtn, IPOINT_BEFORE, (AFUNPTR)LogFunction1WChar,
			   IARG_ADDRINT, cFuncName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END);
	    RTN_Close(CfwRtn);
	}
}

VOID MonitorRegOpenKeyExW(IMG Image, const char * const cFuncName)
{
    RTN CfwRtn = RTN_FindByName(Image, cFuncName);
    if (RTN_Valid(CfwRtn))
	{
	    RTN_Open(CfwRtn);
	    RTN_InsertCall(CfwRtn, IPOINT_BEFORE, (AFUNPTR)LogFunction1WChar,
			   IARG_ADDRINT, cFuncName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			   IARG_END);
	    RTN_Close(CfwRtn);
	}
}

VOID MonitorHttpSendRequestW(IMG Image, const char * const cFuncName)
{
    RTN CfwRtn = RTN_FindByName(Image, cFuncName);
    if (RTN_Valid(CfwRtn))
	{
	    RTN_Open(CfwRtn);
	    RTN_InsertCall(CfwRtn, IPOINT_BEFORE, (AFUNPTR)LogSentData,
			   IARG_ADDRINT, cFuncName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
			   IARG_END);
	    RTN_Close(CfwRtn);
	}
}

VOID LogFunctionArgs(const char * const cFuncName, THREADID Tid, ADDRINT Sp)
{
    assert(cFuncName != NULL);

    pApiArgsFormat ArgFmt = FindFormatByName(g_ArgsArrayPtr, cFuncName);
    if (ArgFmt != NULL) {
        if (g_Args == NULL) {
            g_Args = (char *)calloc(AT_PAGE_SIZE, sizeof(char));
            if (g_Args == NULL)
                goto noargs;
        }
        assert(g_Args != NULL);

        FormatArguments(g_Args, ArgFmt->cApiArgsFormat, (void *)(Sp + sizeof(ADDRINT)));
        fprintf(g_StringsFile, "tid: %-2d function: %s(%s)\n", Tid, cFuncName, g_Args);
        fflush(g_StringsFile);
    } else {
        goto noargs;
    }

    if (0) {
    noargs:
        fprintf(g_StringsFile, "tid: %-2d function: %s(%s)\n", Tid, cFuncName, "no args");
        fflush(g_StringsFile);
    }
}

VOID MonitorFunction(IMG Image, const char * const cFuncName)
{
    RTN CfwRtn = RTN_FindByName(Image, cFuncName);
    if (RTN_Valid(CfwRtn)) {
        RTN_Open(CfwRtn);

        RTN_InsertCall(CfwRtn, IPOINT_BEFORE, (AFUNPTR)LogFunctionArgs,
                       IARG_ADDRINT, cFuncName,
                       IARG_THREAD_ID,
                       IARG_REG_VALUE, REG_STACK_PTR,
                       IARG_END);

        RTN_Close(CfwRtn);
    }
}

VOID ImageLoad(IMG Image, VOID *V)
{
    // Add module into a global map
    s_Module Mod;
    Mod.Name  = std::string(IMG_Name(Image));
    Mod.Start = IMG_LowAddress(Image);
    Mod.End   = IMG_HighAddress(Image);
    g_Modules[Mod.Start] = Mod;

    if (g_MyPid == 0 && IsMyModule(&Mod, g_AnalysedApp)) {
	// enumerate sections within the analysed module
	for (SEC sec = IMG_SecHead(Image); SEC_Valid(sec); sec = SEC_Next(sec)) {
	    s_Module Section;
	    Section.Name  = SEC_Name(sec);
	    Section.Start = SEC_Address(sec) - Mod.Start;
	    Section.End   = Section.Start + SEC_Size(sec);
	    g_Sections[Section.Start] = Section;
	}
    }

    string ArgsFileName = KnobInputArgsFile.Value();
    if (ArgsFileName.empty()) {
    monitor_chosen:
        // functions chosen to be monitored:
        MonitorFunction1Arg(Image, "LoadLibraryW");
        MonitorCreateProcess(Image, "CreateProcessW");
        MonitorWideCharToMultiByte(Image, "WideCharToMultiByte");
        MonitorVsnsprintf(Image, "_vsnprintf");
        MonitorRegOpenKeyExW(Image, "RegOpenKeyExW");
        MonitorHttpSendRequestW(Image, "HttpSendRequestW");
        MonitorCreateFileW(Image, "CreateFileW");
    } else {
        if (g_ArgsArrayPtr == NULL) {
            g_ArgsArrayPtr = LoadApiArgsFormat(ArgsFileName.c_str());
            if (g_ArgsArrayPtr == NULL)
                goto monitor_chosen;
        }
        assert(g_ArgsArrayPtr != NULL);

        for (size_t i = 0; i < g_ArgsArrayPtr->Count; i++) {
            MonitorFunction(Image, g_ArgsArrayPtr->Args[i].cApiName);
        }
    }
}

BOOL Init()
{
    // init output file:
    string FileName = KnobOutputFile.Value();
    if (FileName.empty())
        FileName = "output.txt";
    g_TraceFile = fopen(FileName.c_str(), "w");
    if (g_TraceFile == NULL) {
        cerr << "Failed to open trace file" << endl;

        return false;
    }

    g_StringsFileName = FileName + "_strings.txt";
    g_StringsFile = fopen(g_StringsFileName.c_str(), "w");
    if (g_StringsFile == NULL) {
        cerr << "Failed to open strings file" << endl;

        return false;
    }

    return true;
}

VOID Fini(INT32 ExitCode, VOID *V)
{
    UnloadApiArgsFormat(g_ArgsArrayPtr);

    if (g_Args != NULL) {
        free(g_Args);
        g_Args = NULL;
    }

    fclose(g_TraceFile);
    fclose(g_StringsFile);
}

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out : " << endl <<
	"Addresses of redirections into to a new section." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if(PIN_Init(argc, argv))
	{
	    return Usage();
	}

    g_AnalysedApp = KnobModuleName.Value();
    if (g_AnalysedApp.length() == 0) {
	// init App Name (g_AnalysedApp):
	for (int i = 1; i < (argc - 1); i++ ) {
	    if (strcmp(argv[i], "--") == 0) {
		g_AnalysedApp = argv[i + 1];
		if (i + 2 < argc) {
		    g_Param = argv[i + 2];
		}
		break;
	    }
	}
    }

    if (!Init())
        return -1;

    // Register function to be called for every loaded module
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);

    cout << "===============================================" << endl;
    cout << "This application is instrumented by " << TOOL_NAME << endl;
    cout << "Tracing module: " << g_AnalysedApp << endl;
    if (!KnobOutputFile.Value().empty()) 
	{
	    cout << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
	}
    cout << "===============================================" << endl;

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
