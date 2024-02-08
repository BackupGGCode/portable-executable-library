#pragma once
#ifndef _M_X64
#ifdef _DEBUG
#pragma comment(lib, "../../bin/pe_bliss/Win32/Debug/pe_bliss.lib")
#else
#pragma comment(lib, "../../bin/pe_bliss/Win32/Release/pe_bliss.lib")
#endif
#else
#ifdef _DEBUG
#pragma comment(lib, "../../bin/pe_bliss/x64/Debug/pe_bliss.lib")
#else
#pragma comment(lib, "../../bin/pe_bliss/x64/Release/pe_bliss.lib")
#endif
#endif
