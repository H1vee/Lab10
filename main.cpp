#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <thread>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <mutex>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

#define PORT 54000

// Global mutex for audit log writes to prevent race conditions
std::mutex auditLogMutex;

// ======== Audit System =========
void logEvent(const std::string& eventType, const std::string& details, bool success) {
    // Create a lock scope to prevent concurrent writes to the log file
    std::lock_guard<std::mutex> lock(auditLogMutex);
    
    // Get current time
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    
    std::ofstream auditLog("audit_log.txt", std::ios::app);
    if (auditLog.is_open()) {
        struct tm timeinfo;
        localtime_s(&timeinfo, &time_t_now);
        
        // Format: [Date Time] [EventType] [Success/Failure] Details
        auditLog << "[" << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S") << "] "
                 << "[" << eventType << "] "
                 << "[" << (success ? "SUCCESS" : "FAILURE") << "] "
                 << details << std::endl;
        
        auditLog.close();
    }
}

// ======== Token functions =========
bool encryptToFile(const std::string& data, const std::string& outputPath) {
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    HCRYPTKEY hKey = NULL;

    logEvent("TOKEN_CREATION", "Attempting to create encrypted token", true);

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        logEvent("TOKEN_CREATION", "Failed to acquire crypto context", false);
        return false;
    }

    const char* password = "SuperSecretKey123";
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        logEvent("TOKEN_CREATION", "Failed to create hash", false);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    CryptHashData(hHash, (BYTE*)password, strlen(password), 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);

    DWORD dataSize = data.size();
    DWORD bufferSize = dataSize + 16;
    BYTE* buffer = new BYTE[bufferSize];
    memcpy(buffer, data.c_str(), dataSize);

    CryptEncrypt(hKey, 0, TRUE, 0, buffer, &dataSize, bufferSize);

    std::ofstream outFile(outputPath, std::ios::binary);
    outFile.write((char*)buffer, dataSize);
    outFile.close();

    delete[] buffer;
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    logEvent("TOKEN_CREATION", "Token successfully created for output: " + outputPath, true);
    return true;
}

bool decryptFile(const std::string& inputPath, std::string& output) {
    logEvent("TOKEN_DECRYPTION", "Attempting to decrypt token: " + inputPath, true);
    
    HANDLE hFile = CreateFileA(inputPath.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        logEvent("TOKEN_DECRYPTION", "Failed to open token file: " + inputPath, false);
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* buffer = new BYTE[fileSize];
    DWORD bytesRead;

    ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    HCRYPTKEY hKey = NULL;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        logEvent("TOKEN_DECRYPTION", "Failed to acquire crypto context", false);
        delete[] buffer;
        return false;
    }
    
    const char* password = "SuperSecretKey123";

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        logEvent("TOKEN_DECRYPTION", "Failed to create hash", false);
        CryptReleaseContext(hProv, 0);
        delete[] buffer;
        return false;
    }
    
    CryptHashData(hHash, (BYTE*)password, strlen(password), 0);
    
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        logEvent("TOKEN_DECRYPTION", "Failed to derive key", false);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        delete[] buffer;
        return false;
    }

    DWORD dataLen = fileSize;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer, &dataLen)) {
        logEvent("TOKEN_DECRYPTION", "Failed to decrypt data", false);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        delete[] buffer;
        return false;
    }

    output.assign((char*)buffer, dataLen);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    delete[] buffer;

    logEvent("TOKEN_DECRYPTION", "Token successfully decrypted", true);
    return true;
}

// ======== Server =========
void ensureServerDbExists() {
    std::ifstream check("server_db.txt");
    if (!check.good()) {
        std::ofstream create("server_db.txt");
        create << "Artem 12345" << std::endl;
        create << "Alice qwerty" << std::endl;
        create.close();
        std::cout << "[Info] 'server_db.txt' created with default users." << std::endl;
        logEvent("SERVER_DB", "Created server database with default users", true);
    }
}

void runServer() {
    ensureServerDbExists();
    
    WSADATA wsaData;
    SOCKET listening, clientSocket;
    sockaddr_in serverHint, client;
    int clientSize = sizeof(client);

    logEvent("SERVER", "Starting server on port " + std::to_string(PORT), true);

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        logEvent("SERVER", "WSAStartup failed", false);
        return;
    }

    listening = socket(AF_INET, SOCK_STREAM, 0);
    if (listening == INVALID_SOCKET) {
        logEvent("SERVER", "Failed to create listening socket", false);
        WSACleanup();
        return;
    }

    serverHint.sin_family = AF_INET;
    serverHint.sin_port = htons(PORT);
    serverHint.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(listening, (sockaddr*)&serverHint, sizeof(serverHint)) == SOCKET_ERROR) {
        logEvent("SERVER", "Failed to bind to port " + std::to_string(PORT), false);
        closesocket(listening);
        WSACleanup();
        return;
    }

    if (listen(listening, SOMAXCONN) == SOCKET_ERROR) {
        logEvent("SERVER", "Listen failed", false);
        closesocket(listening);
        WSACleanup();
        return;
    }

    std::cout << "[Server] Waiting for connection...\n";
    logEvent("SERVER", "Waiting for connection on port " + std::to_string(PORT), true);

    clientSocket = accept(listening, (sockaddr*)&client, &clientSize);
    if (clientSocket == INVALID_SOCKET) {
        logEvent("SERVER", "Accept failed", false);
        closesocket(listening);
        WSACleanup();
        return;
    }

    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    ZeroMemory(host, NI_MAXHOST);
    ZeroMemory(service, NI_MAXSERV);

    if (getnameinfo((sockaddr*)&client, sizeof(client), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0) {
        logEvent("SERVER", "Client connected: " + std::string(host) + " using port " + std::string(service), true);
    } else {
        inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
        logEvent("SERVER", "Client connected: " + std::string(host) + " using port " + std::to_string(ntohs(client.sin_port)), true);
    }

    char buf[4096];
    ZeroMemory(buf, 4096);

    int bytesReceived = recv(clientSocket, buf, 4096, 0);
    if (bytesReceived > 0) {
        std::string received(buf, 0, bytesReceived);
        size_t delimiterPos = received.find(':');
        std::string id = received.substr(0, delimiterPos);
        std::string password = received.substr(delimiterPos + 1);

        logEvent("AUTHENTICATION", "Authentication attempt for user: " + id, true);

        std::ifstream file("server_db.txt");
        std::string line;
        bool success = false;
        while (std::getline(file, line)) {
            size_t spacePos = line.find(' ');
            std::string dbId = line.substr(0, spacePos);
            std::string dbPassword = line.substr(spacePos + 1);
            if (dbId == id && dbPassword == password) {
                success = true;
                break;
            }
        }

        if (success) {
            logEvent("AUTHENTICATION", "Authentication successful for user: " + id, true);
            send(clientSocket, "Authentication Successful", 26, 0);
        } else {
            logEvent("AUTHENTICATION", "Authentication failed for user: " + id, false);
            send(clientSocket, "Authentication Failed", 21, 0);
        }
    } else {
        logEvent("SERVER", "Error receiving data or connection closed", false);
    }

    closesocket(clientSocket);
    closesocket(listening);
    WSACleanup();
    logEvent("SERVER", "Server stopped", true);
}

// ======== Client =========
void runClient() {
    logEvent("CLIENT", "Starting client", true);
    
    WSADATA wsaData;
    SOCKET sock;
    sockaddr_in hint;
    std::string decryptedData;

    if (!decryptFile("user_credentials.dat", decryptedData)) {
        std::cerr << "[Client] Failed to read or decrypt user credentials.\n";
        logEvent("CLIENT", "Failed to read or decrypt user credentials", false);
        return;
    }

    // Extract user ID for logging
    size_t delimiterPos = decryptedData.find(':');
    std::string userId = "unknown";
    if (delimiterPos != std::string::npos) {
        userId = decryptedData.substr(0, delimiterPos);
    }
    
    logEvent("CLIENT", "Attempting to connect to server as user: " + userId, true);

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        logEvent("CLIENT", "WSAStartup failed", false);
        return;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        logEvent("CLIENT", "Failed to create socket", false);
        WSACleanup();
        return;
    }

    hint.sin_family = AF_INET;
    hint.sin_port = htons(PORT);
    hint.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (sockaddr*)&hint, sizeof(hint)) == SOCKET_ERROR) {
        logEvent("CLIENT", "Failed to connect to server", false);
        closesocket(sock);
        WSACleanup();
        return;
    }

    logEvent("CLIENT", "Connected to server, sending credentials for user: " + userId, true);

    if (send(sock, decryptedData.c_str(), decryptedData.size(), 0) == SOCKET_ERROR) {
        logEvent("CLIENT", "Failed to send credentials", false);
        closesocket(sock);
        WSACleanup();
        return;
    }

    char buf[4096];
    ZeroMemory(buf, 4096);
    int bytesReceived = recv(sock, buf, 4096, 0);

    if (bytesReceived > 0) {
        std::string response(buf, 0, bytesReceived);
        std::cout << "[Client] Server says: " << response << "\n";
        
        if (response.find("Successful") != std::string::npos) {
            logEvent("CLIENT", "Authentication successful for user: " + userId, true);
        } else {
            logEvent("CLIENT", "Authentication failed for user: " + userId, false);
        }
    } else {
        logEvent("CLIENT", "No response received from server", false);
    }

    closesocket(sock);
    WSACleanup();
    logEvent("CLIENT", "Client stopped", true);
}

// ======== Resource Access Control System =========
bool checkResourceAccess(const std::string& userId, const std::string& resourceId) {
    // Simple resource access check functionality
    // In a real system, this would be more complex with proper ACLs
    logEvent("ACCESS_CONTROL", "User " + userId + " attempting to access resource " + resourceId, true);
    
    std::ifstream accessRulesFile("access_rules.txt");
    if (!accessRulesFile.is_open()) {
        // If the file doesn't exist, create it with some default rules
        std::ofstream createRules("access_rules.txt");
        createRules << "Artem file1 read write\n";
        createRules << "Artem file2 read\n";
        createRules << "Alice file1 read\n";
        createRules << "Alice file2 read write\n";
        createRules.close();
        
        // Reopen for reading
        accessRulesFile.open("access_rules.txt");
        if (!accessRulesFile.is_open()) {
            logEvent("ACCESS_CONTROL", "Failed to create or open access rules file", false);
            return false;
        }
    }
    
    std::string line;
    bool accessGranted = false;
    
    while (std::getline(accessRulesFile, line)) {
        // Format: userId resourceId permissions...
        std::stringstream ss(line);
        std::string fileUserId, fileResourceId;
        ss >> fileUserId >> fileResourceId;
        
        if (fileUserId == userId && fileResourceId == resourceId) {
            accessGranted = true;
            break;
        }
    }
    
    accessRulesFile.close();
    
    if (accessGranted) {
        logEvent("ACCESS_CONTROL", "Access GRANTED for user " + userId + " to resource " + resourceId, true);
    } else {
        logEvent("ACCESS_CONTROL", "Access DENIED for user " + userId + " to resource " + resourceId, false);
    }
    
    return accessGranted;
}

// ======== Main =========
int main() {
    // Initialize audit log with header if it's a new file
    {
        std::ifstream checkLog("audit_log.txt");
        if (!checkLog.good()) {
            std::ofstream initLog("audit_log.txt");
            initLog << "=== SECURITY AUDIT LOG STARTED === " << std::endl;
            initLog << "Format: [Date Time] [EventType] [SUCCESS/FAILURE] Details" << std::endl;
            initLog << "==========================================" << std::endl;
            initLog.close();
        }
    }

    logEvent("SYSTEM", "Application started", true);
    
    int choice;
    do {
        std::cout << "\n=== Security System Menu ===\n";
        std::cout << "1. Create token\n";
        std::cout << "2. Start server only\n";
        std::cout << "3. Start server and client in one run\n";
        std::cout << "4. Simulate resource access\n";
        std::cout << "5. View audit log\n";
        std::cout << "0. Exit\n";
        std::cout << "Your choice: ";
        std::cin >> choice;
        std::cin.ignore();

        switch (choice) {
            case 1: {
                std::string id, password;
                std::cout << "Enter user ID: ";
                std::getline(std::cin, id);
                std::cout << "Enter user Password: ";
                std::getline(std::cin, password);
                std::string credentials = id + ":" + password;
                if (encryptToFile(credentials, "user_credentials.dat")) {
                    std::cout << "[Success] Token created and saved to 'user_credentials.dat'.\n";
                } else {
                    std::cout << "[Error] Failed to create token.\n";
                }
                break;
            }
            case 2:
                runServer();
                break;
            case 3: {
                std::cout << "[Info] Starting server in background...\n";
                std::thread serverThread(runServer);
                std::this_thread::sleep_for(std::chrono::seconds(1));
                std::cout << "[Info] Starting client...\n";
                runClient();
                serverThread.join();
                break;
            }
            case 4: {
                std::string userId, resourceId;
                std::cout << "Enter user ID: ";
                std::getline(std::cin, userId);
                std::cout << "Enter resource ID: ";
                std::getline(std::cin, resourceId);
                
                bool hasAccess = checkResourceAccess(userId, resourceId);
                if (hasAccess) {
                    std::cout << "[Access Control] User " << userId << " has access to resource " << resourceId << std::endl;
                } else {
                    std::cout << "[Access Control] User " << userId << " does NOT have access to resource " << resourceId << std::endl;
                }
                break;
            }
            case 5: {
                std::cout << "\n=== Audit Log Contents ===\n";
                std::ifstream auditLog("audit_log.txt");
                if (auditLog.is_open()) {
                    std::string line;
                    while (std::getline(auditLog, line)) {
                        std::cout << line << std::endl;
                    }
                    auditLog.close();
                } else {
                    std::cout << "[Error] Could not open audit log.\n";
                }
                break;
            }
            case 0:
                std::cout << "Exiting...\n";
                logEvent("SYSTEM", "Application exiting", true);
                break;
            default:
                std::cout << "Invalid choice!\n";
                logEvent("SYSTEM", "Invalid menu choice: " + std::to_string(choice), false);
        }

    } while (choice != 0);

    return 0;
}
