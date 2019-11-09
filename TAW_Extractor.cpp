// TAW_Extractor.cpp : Define el punto de entrada de la aplicación.
//

#include "framework.h"
#include "TAW_Extractor.h"

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

	CProc* process = new CProc();
	process->Start();
	delete process; process = nullptr;

    return 0;
}
