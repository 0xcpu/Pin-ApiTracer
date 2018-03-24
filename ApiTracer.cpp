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

#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>
#include <map>

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

std::string m_AnalysedApp;
std::string m_Param;
std::string m_StringsFileName;

FILE *m_TraceFile   = NULL; // trace log
FILE *m_StringsFile = NULL; // collect dumped strings

INT m_myPid = 0;	    // PID of application

struct s_module {
    std::string name;
    ADDRINT start;
    ADDRINT end;
};

std::map<ADDRINT, s_module> m_Modules;
std::map<ADDRINT, s_module> m_Sections;


const s_module *getModuleByAddr(ADDRINT Address, std::map<ADDRINT, s_module> &modules)
{
    std::map<ADDRINT, s_module>::iterator bound =  modules.upper_bound(Address);
    std::map<ADDRINT, s_module>::iterator itr = modules.begin();
    
    for ( ; itr != bound ; itr++) {
	s_module &mod = itr->second;
	if (Address >= mod.start && Address < mod.end) {
	    return &mod;
	}
    }
    return NULL;
}

const bool isPageChanged(ADDRINT Address)  // without imagebase
{
    static ADDRINT prevPageAddr = UNKNOWN_ADDR;
    
    ADDRINT currPageAddr = (Address / AT_PAGE_SIZE);
    if (prevPageAddr == UNKNOWN_ADDR || prevPageAddr != currPageAddr) { // execution in different memory page!
	prevPageAddr = currPageAddr;
	return true;
    }
    return false;
}

const bool isSectionChanged(ADDRINT Address)  // without imagebase
{
    static s_module* prevModule = NULL;
    const s_module* currModule = getModuleByAddr(Address, m_Sections);
	
    if (prevModule != currModule) {
	prevModule = (s_module*) currModule;
	return true;
    }
    return false;
}

bool isMyModule(const s_module* mod, std::string name) 
{
    if (!mod) return false;
    std::size_t found = mod->name.find(name);
    if (found != std::string::npos) {
	return true;
    }
    return false;
}

std::string getFilename(const std::string& str)
{
    std::size_t found = str.find_last_of("/\\");
    std::size_t ext = str.find_last_of(".");
    return str.substr(found + 1, ext - (found + 1));
}


/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
			    "o", "", "specify file name for the output");

KNOB<string> KnobModuleName(KNOB_MODE_WRITEONCE,  "pintool",
			    "m", "", "Analysed module name (by default same as app name)");

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

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID SaveTranitions(ADDRINT Address, UINT32 numInstInBbl)
{
    PIN_LockClient();
    static s_module *prev_mod = NULL;
    static bool     is_prevMy = false;
    static ADDRINT  prevAddr  = UNKNOWN_ADDR;

    const s_module *mod_ptr = getModuleByAddr(Address, m_Modules);
    bool is_currMy = isMyModule(mod_ptr, m_AnalysedApp);

    if (is_currMy == false && is_prevMy == true && prevAddr != UNKNOWN_ADDR) {
	if (mod_ptr) {
#if _WIN64
	    fprintf(m_TraceFile, "%#" HEX_PADD "llx,%s.", prevAddr, getFilename(mod_ptr->name).c_str());
#else
	    fprintf(m_TraceFile, "%#" HEX_PADD "x,%s.", prevAddr, getFilename(mod_ptr->name).c_str());
#endif
	    //PIN_LockClient();
	    IMG pImg = IMG_FindByAddress(Address);
	    RTN rtn  = RTN_FindByAddress(Address);
	    //PIN_UnlockClient();
		
	    if (IMG_Valid(pImg) && RTN_Valid(rtn)) {
		const string func = RTN_Name(rtn);
		fprintf(m_TraceFile, "%s", func.c_str());
	    }
	    fprintf(m_TraceFile, "\n");
		
	} else {
#if _WIN64
	    fprintf(m_TraceFile, "%#" HEX_PADD "llx,unknown module [%#" HEX_PADD "llx]\n", prevAddr, Address);
#else
	    fprintf(m_TraceFile, "%#" HEX_PADD "x,unknown module [%#" HEX_PADD "x]\n", prevAddr, Address);
#endif
	}
	fflush(m_TraceFile);
    }

    if (is_currMy) {
	ADDRINT addr = Address - mod_ptr->start; // substract module's ImageBase
	const s_module* sec = getModuleByAddr(addr, m_Sections);
	if (isSectionChanged(addr)) {
	    std::string name = (sec != NULL) ? sec->name : "?";
#if _WIN64
	    fprintf(m_TraceFile, "%#" HEX_PADD "llx,[section]: %s\n", addr, name.c_str());
#else
	    fprintf(m_TraceFile, "%#" HEX_PADD "x,[section]: %s\n", addr, name.c_str());
#endif
	    fflush(m_TraceFile);
	}
	prevAddr = addr; /* update saved */
    }
	
    /* update saved */
    is_prevMy = is_currMy;
    prev_mod  = (s_module*) mod_ptr;

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
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
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

VOID LogFunction1WChar(CHAR *name, wchar_t *str)
{
    if (str == NULL) return;
    fprintf(m_StringsFile, "[%s] %ls\n", name, str);
    fflush(m_StringsFile);
}

VOID LogFunction1Char(CHAR *name, CHAR *str)
{
    if (str == NULL) return;
    fprintf(m_StringsFile, "[%s] %s\n", name, str);
    fflush(m_StringsFile);
}

VOID LogFunction2WChar(CHAR *funcname, wchar_t *filename, wchar_t *args)
{
    if (filename == NULL) return;
    fprintf(m_StringsFile, "[%s] : %ls : %ls\n", funcname, filename, args);
    fflush(m_StringsFile);
}

VOID LogSentData(CHAR *funcname, wchar_t *headers, int headers_length, unsigned char *content, int content_len)
{
    if (headers == NULL) return;
    fprintf(m_StringsFile, "[%s] : [%d]%ls : [%d]\n", funcname,  headers_length, headers, content_len);
    for (int i = 0; i < content_len; i++) {
	if (isalnum(content[i])) {
	    fprintf(m_StringsFile, "%c ", content[i]);
	} else {
	    fprintf(m_StringsFile, ". ", content[i]);
	}
    }
    if (content_len) {
	fprintf(m_StringsFile, "\nhex: \n");
    }
    for (int i = 0; i < content_len; i++) {
	fprintf(m_StringsFile, "%#" HEX_PADD "x ", content[i]);
    }
    if (content_len) {
	fprintf(m_StringsFile, "---\n");
    }
    fflush(m_StringsFile);
}

VOID MonitorFunction1Arg(IMG Image, const char *funcName)
{
    RTN cfwRtn = RTN_FindByName(Image, funcName);
    if (RTN_Valid(cfwRtn))
	{
	    RTN_Open(cfwRtn);
	    RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)LogFunction1WChar,
			   IARG_ADDRINT, funcName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END
			   );
	    RTN_Close(cfwRtn);
	}
}

VOID MonitorCreateProcess(IMG Image, const char* funcName)
{
    RTN cfwRtn = RTN_FindByName(Image, funcName);
    if (RTN_Valid(cfwRtn))
	{
	    RTN_Open(cfwRtn);
	    RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)LogFunction2WChar,
			   IARG_ADDRINT, funcName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			   IARG_END
			   );
	    RTN_Close(cfwRtn);
	}
}

VOID MonitorWideCharToMultiByte(IMG Image, const char *funcName)
{
    RTN cfwRtn = RTN_FindByName(Image, funcName);
    if (RTN_Valid(cfwRtn))
	{
	    RTN_Open(cfwRtn);
	    RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)LogFunction1WChar,
			   IARG_ADDRINT, funcName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			   IARG_END
			   );
	    RTN_Close(cfwRtn);
	}
}

VOID MonitorVsnsprintf(IMG Image, const char *funcName)
{
    RTN cfwRtn = RTN_FindByName(Image, funcName);
    if (RTN_Valid(cfwRtn))
	{
	    RTN_Open(cfwRtn);
	    RTN_InsertCall(cfwRtn, IPOINT_AFTER, (AFUNPTR)LogFunction1Char,
			   IARG_ADDRINT, funcName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END
			   );
	    RTN_Close(cfwRtn);
	}
}

VOID MonitorCreateFileW(IMG Image, const char *funcName)
{
    RTN cfwRtn = RTN_FindByName(Image, funcName);
    if (RTN_Valid(cfwRtn))
	{
	    RTN_Open(cfwRtn);
	    RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)LogFunction1WChar,
			   IARG_ADDRINT, funcName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END
			   );
	    RTN_Close(cfwRtn);
	}
}

VOID MonitorRegOpenKeyExW(IMG Image, const char *funcName)
{
    RTN cfwRtn = RTN_FindByName(Image, funcName);
    if (RTN_Valid(cfwRtn))
	{
	    RTN_Open(cfwRtn);
	    RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)LogFunction1WChar,
			   IARG_ADDRINT, funcName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			   IARG_END
			   );
	    RTN_Close(cfwRtn);
	}
}

VOID MonitorHttpSendRequestW(IMG Image, const char *funcName)
{
    RTN cfwRtn = RTN_FindByName(Image, funcName);
    if (RTN_Valid(cfwRtn))
	{
	    RTN_Open(cfwRtn);
	    RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)LogSentData,
			   IARG_ADDRINT, funcName,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
			   IARG_END
			   );
	    RTN_Close(cfwRtn);
	}
}

VOID ImageLoad(IMG Image, VOID *v)
{
    // Add module into a global map
    s_module mod;
    mod.name  = std::string(IMG_Name(Image));
    mod.start = IMG_LowAddress(Image);
    mod.end   = IMG_HighAddress(Image);
    m_Modules[mod.start] = mod;

    if (m_myPid == 0 && isMyModule(&mod, m_AnalysedApp)) {

	// enumerate sections within the analysed module
	for (SEC sec = IMG_SecHead(Image); SEC_Valid(sec); sec = SEC_Next(sec)) {
	    s_module section;
	    section.name  = SEC_Name(sec);
	    section.start = SEC_Address(sec) - mod.start;
	    section.end   = section.start + SEC_Size(sec);
	    m_Sections[section.start] = section;
	}
    }
    // functions chosen to be monitored:
    MonitorFunction1Arg(Image, "LoadLibraryW");
    MonitorCreateProcess(Image, "CreateProcessW");
    MonitorWideCharToMultiByte(Image, "WideCharToMultiByte");
    MonitorVsnsprintf(Image, "_vsnprintf");
    MonitorRegOpenKeyExW(Image, "RegOpenKeyExW");
    MonitorHttpSendRequestW(Image, "HttpSendRequestW");
    MonitorCreateFileW(Image, "CreateFileW");
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if(PIN_Init(argc, argv))
	{
	    return Usage();
	}

    m_AnalysedApp = KnobModuleName.Value();
    if (m_AnalysedApp.length() == 0) {
	// init App Name (m_AnalysedApp):
	for (int i = 1; i < (argc - 1); i++ ) {
	    if (strcmp(argv[i], "--") == 0) {
		m_AnalysedApp = argv[i + 1];
		if (i + 2 < argc) {
		    m_Param = argv[i + 2];
		}
		break;
	    }
	}
    }
    // init output file:
    string fileName = KnobOutputFile.Value();
    if (fileName.empty()) fileName = "output.txt";
    m_TraceFile = fopen(fileName.c_str(), "w");

    m_StringsFileName = fileName + "_strings.txt";
    m_StringsFile = fopen(m_StringsFileName.c_str(), "w");

    // Register function to be called for every loaded module
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(Trace, 0);
	
    cout << "===============================================" << endl;
    cout << "This application is instrumented by " << TOOL_NAME << endl;
    cout << "Tracing module: " << m_AnalysedApp << endl;
    if (!KnobOutputFile.Value().empty()) 
	{
	    cout << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
	}
    cout << "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
