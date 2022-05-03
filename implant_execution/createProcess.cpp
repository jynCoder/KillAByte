#include <windows.h>
#include <stdio.h>
#include "http.h"

#define BUF_SIZE 4096

int main(int argc, char* argv[]) {
    std::string outData = "";

    if (argc != 3){
        //printf("[ERROR] Usage: .\\createProcess.exe program.exe (args)");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'createProcess.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Usage: .\\createProcess.exe program.exe (args)\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        return 0;
    }

    // parse args
    char* program = argv[1];
    char* args = argv[2];

    // create buffer for cmdline argument
    // copied from previous Q, removing redirect operator
    char* buf = NULL;
    int buf_len = strlen("c:\\windows\\system32\\cmd.exe /c  ") + strlen(program) + strlen(args);
    buf = (char*) malloc(buf_len + 1);

    // Make sure that the program was able to allocate memory with malloc
    if (buf == NULL) {
        //printf("[ERROR] Unable to allocate memory.");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'createProcess.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Unable to allocate memory.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        return 0;
    }

    int check = sprintf(buf, "c:\\windows\\system32\\cmd.exe /c %s %s", program, args);

    if (check < 0) {
        //printf("[ERROR] Unable to create command line.");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'createProcess.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Unable to create command line.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        return 0;
    }

    // Declare handles for StdOut
    HANDLE hStdOutRead, hStdOutWrite;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    // Prevent dead squirrels 
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    // TODO: Set si.dwFlags...
    // HINT Read this and look for anything that talks about handle inheritance :-)
    //  https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    
    si.dwFlags |= STARTF_USESTDHANDLES;

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    // Create process
    // TODO: ensure that the child processes can inherit our handles!

    // Create parent process, 5th arg set to true, child process will inherit handles
    BOOL processTest = CreateProcessA(
            NULL,
            buf,
            &sa,
            &sa,
            TRUE,
            NORMAL_PRIORITY_CLASS,
            NULL,
            NULL,
            &si,
            &pi
        );

    // Make sure parent process was created
    if (processTest == 0) {
        //printf("[ERROR] The parent process could not be created.");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'createProcess.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] The parent process could not be created.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        return 0;
    }

    // TODO: Create a pipe object and share the handle with a child process
    // Use security attributes from parent process pipe, makes sure handle is inheritable
    // SECURITY_ATTRIBUTES sa_pipe;
    // sa_pipe.nLength = sizeof(sa_pipe);
    // sa_pipe.lpSecurityDescriptor = NULL;
    // sa_pipe.bInheritHandle = TRUE;

    // Create a pipe, use BUF_SIZE parameter for buffer size
    BOOL pipeTest = CreatePipe(
            &hStdOutRead,
            &hStdOutWrite,
            &sa,
            BUF_SIZE
        );

    // Make sure pipe was created
    if (pipeTest == 0) {
        //printf("[ERROR] The pipe could not be created.");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'createProcess.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] The pipe could not be created.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        return 0;
    }

    //Make sure read end is not inherited
    BOOL handleInfoCheck = SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);

    //Make sure changes were implemented
    if (handleInfoCheck == 0) {
        //printf("[ERROR] Lack of inheritance for read end of the pipe could not be ensured");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'createProcess.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Lack of inheritance for read end of the pipe could not be ensured.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        return 0;
    }

    // TODO: Set
    // set startupinfo handles
    si.hStdInput = NULL;
    si.hStdError = hStdOutWrite;
    si.hStdOutput = hStdOutWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;

    // Create the child Processes and wait for it to terminate!
    BOOL processChildTest = CreateProcessA(
            NULL,
            buf,
            NULL,
            NULL,
            TRUE,
            NORMAL_PRIORITY_CLASS,
            NULL,
            NULL,
            &si,
            &pi
        );

    // Make sure child process was created
    if (processChildTest == 0) {
        //printf("[ERROR] A child process could not be created.");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'createProcess.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] A child process could not be created.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        return 0;
    }

    // Create buffer to use to read from pipe
    // Not adding one since reading 4095 bytes at a time, need 1 byte for null terminator
    char* pipeBuf = NULL;
    pipeBuf = (char*) malloc(BUF_SIZE);
    DWORD bytesAvailable = 0;
    DWORD bytesRead = 0;
    DWORD bytesLeft = 0;

    //Close write handle to pipe before reading
    BOOL closeCheckPipeWrite = CloseHandle(hStdOutWrite);

    if (closeCheckPipeWrite == 0) {
        //printf("[ERROR] Pipe write handle could not be closed.");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'createProcess.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Pipe write handle could not be closed.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        return 0;
    }

    // Read pipe
    // While my child processes are still alive...
    BOOL breakLoop = FALSE;
    outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'createProcess.exe\', \'status\': \'SUCCESS\', \'output\': \'";
    while (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT && breakLoop == FALSE) {
        // While there is data to read from the pipe...
        while (PeekNamedPipe(hStdOutRead, NULL, 0, NULL, &bytesAvailable, &bytesLeft) && breakLoop == FALSE) {
            // Read data from pipe
            BOOL readTest = ReadFile(
                    hStdOutRead, 
                    pipeBuf, 
                    BUF_SIZE, 
                    &bytesRead, 
                    NULL);
            // Check if pipe is readable
            if (readTest == 0) {
                // Ignore... messes with autograder
                // printf("[ERROR] Pipe could not be read.");
            }
            else if (bytesRead == 0) {
                // Ignore... messes with autograder
                // printf("[ERROR] 0 bytes read from pipe.");
            }
            else {
                //printf("%s", pipeBuf);
                outData.append(pipeBuf);
            }
        }
    }

    outData.append("\'}");
    makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);

    // TODO: perform any cleanup necessary! 
    // The parent processes no longer needs a handle to the child processes, the running thread, or the out file!
    // //your solution here!
    // Finally, print the contents from the pipe!
    
    BOOL closeCheck = CloseHandle(pi.hProcess);

    if (closeCheck == 0) {
        //printf("[ERROR] Process handle could not be closed.");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'createProcess.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Process handle could not be closed.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        return 0;
    }

    BOOL closeCheckPipeRead = CloseHandle(hStdOutRead);

    if (closeCheckPipeRead == 0) {
        //printf("[ERROR] Pipe read handle could not be closed.");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'createProcess.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Pipe read handle could not be closed.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        return 0;
    }

    free(program);
    free(args);
    free(buf);
    free(pipeBuf);

    return 0;
}