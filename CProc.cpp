#include "framework.h"
#include "CProc.h"

#define DIR L"d:\\" 
#define BASE L"d:\\extrae_original\\taw\\"
#define DID_DAT L"d:\\extrae_original\\taw\\did.dat" 
#define EXE L"d:\\extrae_original\\taw\\f22.dat"
#define DID_ENV L"DID=d:\\extrae_original\\taw\\"
#define ENGLISH

CProc::CProc() {}

void CProc::Start()
{
	Extraer();
}

void CProc::Extraer()
{
	wchar_t ruta_txt[MAX_PATH];
	wcscpy_s(ruta_txt, BASE);
	wcscat_s(ruta_txt, L"archivos.txt");

	txt_file = CreateFileW(ruta_txt, GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (txt_file == INVALID_HANDLE_VALUE)
	{
		//Error opening
		return;
	}
	SetFilePointer(txt_file, 0, nullptr, FILE_END);

	dat_file = CreateFileW(DID_DAT, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (dat_file == INVALID_HANDLE_VALUE)
	{
		//Error opening
		return;
	}

	PROCESS_INFORMATION pr_info;
		ZeroMemory(&pr_info, sizeof(PROCESS_INFORMATION));
	if (ArrancarExe(&pr_info))
	{
		DebugLoop(&pr_info);
		CloseHandle(pr_info.hProcess);
	}

	CloseHandle(dat_file);
	CloseHandle(txt_file);
}

bool CProc::ArrancarExe(PROCESS_INFORMATION* pr_info)
{
	STARTUPINFO sti;
	ZeroMemory(&sti, sizeof(STARTUPINFO));
	sti.cb = sizeof(STARTUPINFO);

	BOOL ok = CreateProcess(EXE, nullptr, nullptr, nullptr, FALSE, DEBUG_PROCESS | CREATE_UNICODE_ENVIRONMENT, (LPVOID)DID_ENV, BASE, &sti, pr_info);
	if (ok == FALSE)
	{
		//Exe launch error
		return false;
	}

	return true;
}

void CProc::DebugLoop(PROCESS_INFORMATION* pr_info)
{
#ifdef ENGLISH
	const LPVOID baseNombre0 = (LPVOID)0x0057B211;//0x00597481; //0x0057B211;
	const LPVOID baseNombreS0 = (LPVOID)0x0057B216;//0x00597486; //0x0057B216;
	const LPVOID baseOffset0 = (LPVOID)0x0057B222;//0x00597492; //0x0057B222;
	const LPVOID baseOffsetS0 = (LPVOID)0x0057B227;//0x00597497;//0x0057B227;
	const LPVOID baseNombre = (LPVOID)0x0057b281;//0x005974F1; //0x0057b281;
	const LPVOID baseNombreS = (LPVOID)0x0057b286;//0x005974F6; //0x0057b286;
	const LPVOID baseOffset = (LPVOID)0x0057b294;//0x00597504 ; //0x0057b294;
	const LPVOID baseOffsetS = (LPVOID)0x0057b299;//0x00597509;//0x0057b299;
	const LPVOID baseDescomp = (LPVOID)0x005b929b;//0x005F844B; //0x005b929b;
	const LPVOID baseDescompS = (LPVOID)0x005b92a0;//0x005F8450;//0x005b92a0;
#else
	const LPVOID baseNombre0 = (LPVOID)0x0057B211;//lost?
	const LPVOID baseNombreS0 = (LPVOID)0x0057B216;//lost?
	const LPVOID baseOffset0 = (LPVOID)0x0057B222;//lost?
	const LPVOID baseOffsetS0 = (LPVOID)0x0057B227;//lost?;
	const LPVOID baseNombre = (LPVOID)0x005974F1;
	const LPVOID baseNombreS = (LPVOID)0x005974F6;
	const LPVOID baseOffset = (LPVOID)0x00597527;
	const LPVOID baseOffsetS=(LPVOID)0x00597509;
	const LPVOID baseDescomp = (LPVOID)0x005F844B;
	const LPVOID baseDescompS = (LPVOID)0x005F8450;
#endif
	const BYTE int3 = 0xcc; //Breakpoint
	const BYTE baseN = 0xe8; const BYTE baseNS = 0x85;
	const BYTE baseO = 0xe8; const BYTE baseOS = 0x66;
	const BYTE baseD = 0xe8; const BYTE baseDS = 0x66;

	SIZE_T tam = 0;

	#pragma region "Attach debug monitor to process and set breakpoints"

	HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, pr_info->dwThreadId);
	DEBUG_EVENT evt;
	CONTEXT contex;
		ZeroMemory(&contex, sizeof(CONTEXT));
		contex.ContextFlags = CONTEXT_SEGMENTS | CONTEXT_INTEGER | CONTEXT_CONTROL;

	WriteProcessMemory(pr_info->hProcess, baseOffset0, &int3, 1, &tam);
	WriteProcessMemory(pr_info->hProcess, baseNombre0, &int3, 1, &tam);
	WriteProcessMemory(pr_info->hProcess, baseDescomp, &int3, 1, &tam);
	WriteProcessMemory(pr_info->hProcess, baseNombre, &int3, 1, &tam);
	WriteProcessMemory(pr_info->hProcess, baseOffset, &int3, 1, &tam);
	FlushInstructionCache(pr_info->hProcess, 0, 0);

	#pragma endregion

	//Monitor process execution to extract file information
	char archivo1[MAX_PATH];
	char archivo2[MAX_PATH];
	while (true)
	{
		WaitForDebugEvent(&evt, INFINITE);
		if (evt.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT && evt.dwProcessId == pr_info->dwProcessId)
		{
			break;
		}
		else if (evt.dwDebugEventCode == 1 && evt.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
		{
			HANDLE h = OpenThread(THREAD_ALL_ACCESS, FALSE, evt.dwThreadId);
			BOOL ok = GetThreadContext(h, &contex);

			//Decompress function
			if (evt.u.Exception.ExceptionRecord.ExceptionAddress == baseDescomp)
			{
				contex.Eip--;
				//LeerMem(archivo2,&contex);
				ok = WriteProcessMemory(pr_info->hProcess, baseDescomp, &baseD, 1, &tam);
				ok = WriteProcessMemory(pr_info->hProcess, baseDescompS, &int3, 1, &tam);
				ok = SetThreadContext(h, &contex);
				ok = FlushInstructionCache(pr_info->hProcess, 0, 0);
			}
			else if (evt.u.Exception.ExceptionRecord.ExceptionAddress == baseDescompS)
			{
				contex.Eip--;
				ok = WriteProcessMemory(pr_info->hProcess, baseDescompS, &baseDS, 1, &tam);
				ok = WriteProcessMemory(pr_info->hProcess, baseDescomp, &int3, 1, &tam);
				ok = SetThreadContext(h, &contex);
				ok = FlushInstructionCache(pr_info->hProcess, 0, 0);
			}

			// File name
			else if (evt.u.Exception.ExceptionRecord.ExceptionAddress == baseNombre0)
			{
				contex.Eip--;
				char ruta[MAX_PATH];
				ReadProcessMemory(pr_info->hProcess, (LPCVOID)contex.Eax, (LPVOID)ruta, MAX_PATH, &tam);
				strcpy_s(archivo1, ruta);
				ok = WriteProcessMemory(pr_info->hProcess, baseNombre0, &baseN, 1, &tam);
				ok = WriteProcessMemory(pr_info->hProcess, baseNombreS0, &int3, 1, &tam);
				ok = SetThreadContext(h, &contex);
				ok = FlushInstructionCache(pr_info->hProcess, 0, 0);
			}
			else if (evt.u.Exception.ExceptionRecord.ExceptionAddress == baseNombreS0)
			{
				contex.Eip--;
				ok = WriteProcessMemory(pr_info->hProcess, baseNombreS0, &baseNS, 1, &tam);
				ok = WriteProcessMemory(pr_info->hProcess, baseNombre0, &int3, 1, &tam);
				ok = SetThreadContext(h, &contex);
				ok = FlushInstructionCache(pr_info->hProcess, 0, 0);
			}

			else if (evt.u.Exception.ExceptionRecord.ExceptionAddress == baseOffset0)
			{
				contex.Eip--;
				CrearArchivo(archivo1, contex.Eax, contex.Ebx);
				ok = WriteProcessMemory(pr_info->hProcess, baseOffset0, &baseO, 1, &tam);
				ok = WriteProcessMemory(pr_info->hProcess, baseOffsetS0, &int3, 1, &tam);
				ok = SetThreadContext(h, &contex);
				ok = FlushInstructionCache(pr_info->hProcess, 0, 0);
			}
			else if (evt.u.Exception.ExceptionRecord.ExceptionAddress == baseOffsetS0)
			{
				contex.Eip--;
				ok = WriteProcessMemory(pr_info->hProcess, baseOffsetS0, &baseOS, 1, &tam);
				ok = WriteProcessMemory(pr_info->hProcess, baseOffset0, &int3, 1, &tam);
				ok = SetThreadContext(h, &contex);
				ok = FlushInstructionCache(pr_info->hProcess, 0, 0);
			}

			else if (evt.u.Exception.ExceptionRecord.ExceptionAddress == baseNombre)
			{
				contex.Eip--;
				char ruta[MAX_PATH];
				ReadProcessMemory(pr_info->hProcess, (LPCVOID)contex.Eax, ruta, 300, &tam);
				strcpy_s(archivo2, ruta);
				ok = WriteProcessMemory(pr_info->hProcess, baseNombre, &baseN, 1, &tam);
				ok = WriteProcessMemory(pr_info->hProcess, baseNombreS, &int3, 1, &tam);
				ok = SetThreadContext(h, &contex);
				ok = FlushInstructionCache(pr_info->hProcess, 0, 0);
			}
			else if (evt.u.Exception.ExceptionRecord.ExceptionAddress == baseNombreS)
			{
				contex.Eip--;
				ok = WriteProcessMemory(pr_info->hProcess, baseNombreS, &baseNS, 1, &tam);
				ok = WriteProcessMemory(pr_info->hProcess, baseNombre, &int3, 1, &tam);
				ok = SetThreadContext(h, &contex);
				ok = FlushInstructionCache(pr_info->hProcess, 0, 0);
			}

			else if (evt.u.Exception.ExceptionRecord.ExceptionAddress == baseOffset)
			{
				contex.Eip--;
				CrearArchivo(archivo2, contex.Eax, contex.Esi);
				ok = WriteProcessMemory(pr_info->hProcess, baseOffset, &baseO, 1, &tam);
				ok = WriteProcessMemory(pr_info->hProcess, baseOffsetS, &int3, 1, &tam);
				ok = SetThreadContext(h, &contex);
				ok = FlushInstructionCache(pr_info->hProcess, 0, 0);
			}
			else if (evt.u.Exception.ExceptionRecord.ExceptionAddress == baseOffsetS)
			{
				contex.Eip--;
				ok = WriteProcessMemory(pr_info->hProcess, baseOffsetS, &baseOS, 1, &tam);
				ok = WriteProcessMemory(pr_info->hProcess, baseOffset, &int3, 1, &tam);
				ok = SetThreadContext(h, &contex);
				ok = FlushInstructionCache(pr_info->hProcess, 0, 0);
			}
			CloseHandle(h);
		}
		ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE);
	}

	CloseHandle(th);
}

void CProc::CrearArchivo(char* archivo_ansi, DWORD offset, DWORD length)
{
	wchar_t archivo[MAX_PATH];
	ZeroMemory(archivo, MAX_PATH);
	if (0 == MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, archivo_ansi, -1, archivo, MAX_PATH))
	{
		//conversion error
		return;
	}

	//check if file exists
	wchar_t base[] = BASE;
	if (archivo[1] != L':')
	{
		wchar_t full_path[MAX_PATH];
		ZeroMemory(archivo, MAX_PATH);
		wcscpy_s(full_path, base);
		wcscat_s(full_path, archivo);
		wcscpy_s(archivo, full_path);
	}
	HANDLE old_file = CreateFile(archivo, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (old_file != INVALID_HANDLE_VALUE)
	{
		CloseHandle(old_file);
		return;
	}

	//create directories
	if (!CrearRuta(archivo))
	{
		return;
	}

	//update list and create the file
	HANDLE sf = CreateFile(archivo, GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);

	DWORD ret_tam = 0;
	WriteFile(txt_file, archivo, wcslen(archivo) * sizeof(wchar_t), &ret_tam, nullptr); // path & name

	ZeroMemory(archivo, MAX_PATH); //empty string
	wsprintf(archivo, L" %x %x ", offset, length);
	WriteFile(txt_file, archivo, wcslen(archivo) * sizeof(wchar_t), &ret_tam, nullptr); //offset & length

	BYTE* buf = new BYTE[length];
	SetFilePointer(dat_file, offset, nullptr, FILE_BEGIN);
	ReadFile(dat_file, buf, length, &ret_tam, nullptr);
	WriteFile(sf, buf, length, &ret_tam, nullptr);

	WORD cab;
	memcpy(&cab, buf, 2);
	delete[] buf; buf = nullptr;

	CloseHandle(sf);

	if (cab == 0x4152)
	{
		WriteFile(txt_file, L"RA\r\n", 4 * sizeof(wchar_t), &ret_tam, nullptr); //algorithm
	}
	else if (cab == 0x524a)
	{
		WriteFile(txt_file, L"RB\r\n", 4 * sizeof(wchar_t), &ret_tam, nullptr); //algorithm
	}
	else
	{
		WriteFile(txt_file, L"00\r\n", 4 * sizeof(wchar_t), &ret_tam, nullptr); //algorithm
	}
}

bool CProc::CrearRuta(wchar_t* ruta)
{
	*wcsrchr(ruta, L'\\') = L'\0'; //remove file name and extension

	wchar_t path[MAX_PATH];
		ZeroMemory(path, MAX_PATH);
		wcscpy_s(path, &(ruta[3])); //path without drive letter

	if (!SetCurrentDirectoryW(DIR))
	{
		return false;
	}
	
	wchar_t dir[MAX_PATH];
		ZeroMemory(dir, MAX_PATH);

	while (wcslen(path) != 0)
	{	
		if (wcschr(path, L'\\') == nullptr)
		{
			wcscat_s(dir, path);
			if (!CreateDirectoryW(dir, 0))
			{
				return false;
			}
			break;
		}
		else
		{
			wchar_t temp_string[MAX_PATH];
				ZeroMemory(temp_string, MAX_PATH);
			wchar_t* next_part = wcschr(path, L'\\') + 1;
			wcscpy_s(temp_string, next_part); //next path

			*next_part = L'\0'; //take only the first directory
			wcscat_s(dir, path);
			wcscpy_s(path, temp_string);
		}

		if (!CreateDirectoryW(dir, 0))
		{
			return false;
		}
	}

	return true;
}

//void CProc::LeerMem(CString& archivo, CONTEXT* contex)
//{
//	//if(contex->Eax==1) return;
//	//CString archivo;
//	//char path[300];
//	//if(archivo.Right(3)=="SSD")
//	//	int a=0;
//	BYTE* buf = new BYTE[contex->Edx];
//	SIZE_T tam;
//	//ReadProcessMemory(pri.hProcess,(LPCVOID)contex->Eax,buf,contex->Edi,&tam);
//	ReadProcessMemory(pri.hProcess, (LPCVOID)contex->Esi, buf, contex->Edx, &tam);
//	//ReadProcessMemory(pri.hProcess,(LPCVOID)contex->Esi,path,300,&tam);
//
//	//archivo=path;
//
//	CStdioFile f;
//	char base[] = BASE;
//
//	CFile sf;
//	if (archivo.GetAt(1) != ':')
//		archivo.Insert(0, base);
//	//if(sf.Open(archivo.GetBuffer(),CFile::modeRead)) {		
//	//	sf.Close(); return; 
//	//}
//	CrearRuta(archivo.Left(archivo.ReverseFind('\\')).GetBuffer());
//
//	if (sf.Open(archivo.GetBuffer(), CFile::modeRead)) {
//		WORD r;
//		sf.Read(&r, 2);
//		sf.Close();
//		if (r != 0x4152) { delete[] buf; buf = NULL; return; }
//	}
//	sf.Open(archivo.GetBuffer(), CFile::modeCreate | CFile::modeWrite);
//	sf.Write(buf, contex->Edx);
//	delete[] buf; buf = NULL;
//	sf.Close();
//}
