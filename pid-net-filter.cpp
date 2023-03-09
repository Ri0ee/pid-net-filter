#include <iostream>
#include <vector>
#include <set>

#include <windivert.h>
#include <Windows.h>

constexpr int MTU = 1500;

typedef struct {
	HANDLE handle;
	int batch;
} Config, *PConfig;

typedef struct {
	uint32_t pid;
	uint32_t destIPv4Address;
} Connection;

static uint32_t NetworkCapture(LPVOID arg);

enum ArgOptions {
	NONE,
	UNKNOWN,
	HELP,
	EXECUTABLE_PATH,
	PROCESS_ID
};

static std::string mainExecutablePath = "";
static std::vector<uint32_t> PIDs;

auto conCmp = [](Connection a, Connection b) {
	return a.destIPv4Address == b.destIPv4Address && a.pid == b.pid;
};
static std::set<Connection, decltype(conCmp)> activeConnections;

static HANDLE flowDetectedEvent;

int main(int argc, char* argv[]) {
	const std::vector<std::string_view> args(argv + 1, argv + argc);
	ArgOptions argType = ArgOptions::NONE;

	try {
		for (const auto& arg : args) {
			switch (argType)
			{
			case HELP:
				std::cout << "-path <path-to-executable> (will create a process)\n-pid <process-id> (multiple values supported)\n";
				break;
			case EXECUTABLE_PATH:
				mainExecutablePath = std::string(arg);
				break;
			case PROCESS_ID:
				PIDs.push_back(std::atoi(arg.data()));
				break;
			case UNKNOWN:
				throw std::exception("argument unknown");
				break;
			default:
				break;
			}
			
			if (arg == "-help" || arg == "-h") {
				argType = ArgOptions::HELP;
				continue;
			}

			if (arg == "-path") {
				argType = ArgOptions::EXECUTABLE_PATH;
				continue;
			}
			
			if (arg == "-pid") {
				argType = ArgOptions::PROCESS_ID;
				continue;
			}

			argType = ArgOptions::UNKNOWN;
		}
	}
	catch (const std::exception& e) {
		std::cerr << e.what() << '\n';
		return 1;
	}
	
	if (!mainExecutablePath.empty()) {
		std::string currentDir = mainExecutablePath.substr(0, mainExecutablePath.find_last_of('\\') + 1);

		std::cout << "mainExecutablePath = " << mainExecutablePath << '\n';
		std::cout << "currentDir = " << currentDir << '\n';

		PROCESS_INFORMATION pInfo{};
		STARTUPINFOA sInfo{};
		if (!CreateProcessA(mainExecutablePath.c_str(), nullptr, nullptr, nullptr, false, DETACHED_PROCESS, nullptr, currentDir.c_str(), &sInfo, &pInfo)) {
			std::cerr << "failed to create process: " << GetLastError() << '\n';
			return 1;
		}

		PIDs.push_back(pInfo.dwProcessId);
		std::cout << "pid = " << pInfo.dwProcessId << '\n';

		CloseHandle(pInfo.hProcess);
		CloseHandle(pInfo.hThread);
	}
	
	if (PIDs.empty()) {
		std::cout << "exiting\n";
		return 1;
	}

	HANDLE winDivertFlowHandle = WinDivertOpen("true", WINDIVERT_LAYER_FLOW, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
	if (winDivertFlowHandle ==	 INVALID_HANDLE_VALUE) {
		std::cerr << "failed to open flow WinDivert device: " << GetLastError() << "\n";
		return 1;
	}

	HANDLE winDivertNetwHandle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);
	if (winDivertNetwHandle == INVALID_HANDLE_VALUE) {
		std::cerr << "failed to open netw WinDivert device: " << GetLastError() << "\n";
		return 1;
	}

	flowDetectedEvent = CreateEvent(nullptr, false, false, L"flowDetectedEvent");
	Config netwCaptureCfg = { winDivertNetwHandle, 1 };
	HANDLE netwCaptureThread = CreateThread(nullptr, 1, (LPTHREAD_START_ROUTINE)NetworkCapture, (LPVOID)&netwCaptureCfg, 0, nullptr);

	uint8_t* packet = new uint8_t[MTU];
	while (true) {
		uint32_t packetLength = MTU;
		WINDIVERT_ADDRESS addr;

		if (!WinDivertRecv(winDivertFlowHandle, packet, packetLength, &packetLength, &addr)) {
			std::cerr << "failed to recieve flow packet: " << GetLastError() << "\n";
			continue;
		}

		if (addr.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED) {
			char* buf = new char(16);
			WinDivertHelperFormatIPv4Address(addr.Flow.RemoteAddr[0], buf, 16);
			std::cout << "flow established, pid: " << addr.Flow.ProcessId << ", dest.ip: " << buf << "\n";

			for (const auto& pid : PIDs) {
				if (pid == addr.Flow.ProcessId) {
					std::cout << "\ttarget process established flow\n";
					activeConnections.insert({ pid, addr.Flow.RemoteAddr[0] });
					SetEvent(flowDetectedEvent);
				}
			}
		}

		if (addr.Event == WINDIVERT_EVENT_FLOW_DELETED) {
			char* buf = new char[16];
			WinDivertHelperFormatIPv4Address(addr.Flow.RemoteAddr[0], buf, 16);
			std::cout << "flow deleted,     pid: " << addr.Flow.ProcessId << ", dest.ip: " << buf << "\n";

			activeConnections.erase({ addr.Flow.ProcessId, addr.Flow.RemoteAddr[0] });
			if (activeConnections.empty()) {
				ResetEvent(flowDetectedEvent);
			}
		}
	}

	return 0;
}

static uint32_t NetworkCapture(LPVOID arg) {
	PConfig cfg = (PConfig)arg;
	uint8_t* packet = new uint8_t[MTU * cfg->batch];

	while (true) {
		WaitForSingleObject(flowDetectedEvent, INFINITE);

		uint32_t packetLength = MTU * cfg->batch;
		uint32_t addrLength = 0;
		WINDIVERT_ADDRESS addr;
		HANDLE handle = cfg->handle;

		if (!WinDivertRecvEx(handle, packet, packetLength, &packetLength, 0, &addr, &addrLength, nullptr)) {
			std::cerr << "failed to recieve network packet: " << GetLastError() << "\n";
			continue;
		}

		if (!WinDivertSendEx(handle, packet, packetLength, nullptr, 0, &addr, addrLength, nullptr)) {
			std::cerr << "failed to forward network packet: " << GetLastError() << "\n";
			continue;
		}
	}
}