#pragma once

class CProc
{
public:
	CProc();

	void Start();

private:
	HANDLE txt_file;
	HANDLE dat_file;

	void Extraer();
	bool ArrancarExe(PROCESS_INFORMATION* pr_info);
	void DebugLoop(PROCESS_INFORMATION* pr_info);
	void CrearArchivo(char* archivo_ansi, DWORD offset, DWORD length);
	bool CrearRuta(wchar_t* ruta);
};