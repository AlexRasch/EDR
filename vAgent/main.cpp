#include <stdio.h>
#include <Windows.h>
#include <thread>


void HandleClientConnection(HANDLE hPipe) {
	char buffer[1024];

	DWORD bytesRead;
	BOOL success;

	// Loop to read the data in chunks
	do {
		success = ReadFile(
			hPipe,                // Handle to the pipe
			buffer,               // Buffer to receive data
			sizeof(buffer) - 1,   // Size of buffer (minus 1 for null terminator)
			&bytesRead,           // Number of bytes actually read
			NULL                  // Not using overlapped I/O
		);

		if (success && bytesRead > 0) {
			buffer[bytesRead] = '\0';  // Null-terminate the string to avoid buffer overflow
			printf("Received: %s\n", buffer);
		}
	} while (success && bytesRead > 0);  // Continue reading while data is available

	if (!success && GetLastError() != ERROR_BROKEN_PIPE) {
		printf("ReadFile failed with error code: %d\n", GetLastError());
	}

	CloseHandle(hPipe);
}

void StartNamedPipeServer() {
	while (true) {
		HANDLE hPipe = CreateNamedPipeW(
			TEXT("\\\\.\\pipe\\HookPipe"),
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			1024, 1024, 0, NULL
		);

		if (hPipe == INVALID_HANDLE_VALUE) {
			printf("Failed creating named pipe\n");
			return;
		}

		printf("Waiting for client connection\n");
		BOOL isConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (isConnected) {
			printf("Client connected, spawing handler thread.. \n");
			std::thread clientThread(HandleClientConnection, hPipe);
			clientThread.detach();
		}
		else {
			CloseHandle(hPipe);
		}

	}
}

int main() {
	printf("Starting named pipe server...\n");
	StartNamedPipeServer();

	return 0;
}