#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>

using namespace std;

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================
namespace Config {
    // Maximum percentage of host file that can be used for hidden data
    const double MAX_HIDDEN_SIZE_RATIO = 0.85;  // 85% of host file size
    
    // Minimum host file size (10 KB)
    const size_t MIN_HOST_SIZE = 10240;
    
    // Magic signature for identifying steganography files
    const uint32_t MAGIC_SIGNATURE = 0x5354454E;  // "STEN" in hex
    
    // Version number for compatibility
    const uint16_t VERSION = 0x0001;
    
    // Maximum filename length
    const size_t MAX_FILENAME_LENGTH = 256;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
namespace Utils {
    /**
     * Gets file size in bytes
     * @param filename Path to file
     * @return File size or 0 if error
     */
    size_t getFileSize(const string& filename) {
        struct stat stat_buf;
        int rc = stat(filename.c_str(), &stat_buf);
        return rc == 0 ? stat_buf.st_size : 0;
    }
    
    /**
     * Checks if file exists and is readable
     * @param filename Path to file
     * @return true if file exists and is readable
     */
    bool fileExists(const string& filename) {
        ifstream file(filename, ios::binary);
        return file.good();
    }
    
    /**
     * Formats bytes into human-readable format
     * @param bytes Number of bytes
     * @return Formatted string (e.g., "1.5 MB")
     */
    string formatBytes(size_t bytes) {
        const char* units[] = {"B", "KB", "MB", "GB", "TB"};
        int unitIndex = 0;
        double size = static_cast<double>(bytes);
        
        while (size >= 1024.0 && unitIndex < 4) {
            size /= 1024.0;
            unitIndex++;
        }
        
        ostringstream oss;
        oss << fixed << setprecision(2) << size << " " << units[unitIndex];
        return oss.str();
    }
    
    /**
     * Extracts filename from full path
     * @param fullPath Full file path
     * @return Filename only
     */
    string extractFilename(const string& fullPath) {
        size_t pos = fullPath.find_last_of("/\\");
        return (pos == string::npos) ? fullPath : fullPath.substr(pos + 1);
    }
    
    /**
     * Gets file extension
     * @param filename File name or path
     * @return Extension in lowercase
     */
    string getExtension(const string& filename) {
        size_t pos = filename.find_last_of('.');
        if (pos == string::npos) return "";
        
        string ext = filename.substr(pos);
        transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        return ext;
    }
}

// ============================================================================
// CUSTOM EXCEPTION CLASSES
// ============================================================================
class SteganographyException : public runtime_error {
public:
    explicit SteganographyException(const string& msg) 
        : runtime_error(msg) {}
};

class FileSizeException : public SteganographyException {
public:
    explicit FileSizeException(const string& msg) 
        : SteganographyException(msg) {}
};

class FileAccessException : public SteganographyException {
public:
    explicit FileAccessException(const string& msg) 
        : SteganographyException(msg) {}
};

class InvalidFormatException : public SteganographyException {
public:
    explicit InvalidFormatException(const string& msg) 
        : SteganographyException(msg) {}
};

// ============================================================================
// FILE HEADER STRUCTURE
// ============================================================================
struct StegoHeader {
    uint32_t magic;           // Magic signature for validation
    uint16_t version;         // Version number
    uint32_t hiddenFileSize;  // Size of hidden file
    uint16_t filenameLength;  // Length of original filename
    char filename[Config::MAX_FILENAME_LENGTH];  // Original filename
    uint32_t checksum;        // Simple checksum for integrity
    
    StegoHeader() : magic(Config::MAGIC_SIGNATURE), 
                    version(Config::VERSION),
                    hiddenFileSize(0),
                    filenameLength(0),
                    checksum(0) {
        memset(filename, 0, Config::MAX_FILENAME_LENGTH);
    }
    
    /**
     * Calculates simple checksum for validation
     * @return Checksum value
     */
    uint32_t calculateChecksum() const {
        uint32_t sum = magic + version + hiddenFileSize + filenameLength;
        for (size_t i = 0; i < filenameLength && i < Config::MAX_FILENAME_LENGTH; i++) {
            sum += static_cast<unsigned char>(filename[i]);
        }
        return sum;
    }
    
    /**
     * Validates header integrity
     * @return true if valid
     */
    bool validate() const {
        return magic == Config::MAGIC_SIGNATURE && 
               checksum == calculateChecksum();
    }
};

// ============================================================================
// FILE VALIDATOR CLASS
// ============================================================================
class FileValidator {
public:
    /**
     * Validates that file exists and is accessible
     * @param filename Path to file
     * @param fileType Description of file type (for error messages)
     */
    static void validateFileAccess(const string& filename, const string& fileType) {
        if (filename.empty()) {
            throw FileAccessException(fileType + " path cannot be empty");
        }
        
        if (!Utils::fileExists(filename)) {
            throw FileAccessException(fileType + " not found or not accessible: " + filename);
        }
    }
    
    /**
     * Validates file sizes and calculates allowed hidden size
     * @param hiddenSize Size of file to hide
     * @param hostSize Size of host file
     * @return Maximum allowed size for hidden file
     */
    static size_t validateAndCalculateMaxSize(size_t hiddenSize, size_t hostSize) {
        // Check minimum host size
        if (hostSize < Config::MIN_HOST_SIZE) {
            throw FileSizeException(
                "Host file too small. Minimum size: " + 
                Utils::formatBytes(Config::MIN_HOST_SIZE)
            );
        }
        
        // Calculate maximum allowed hidden size
        size_t maxHiddenSize = static_cast<size_t>(
            hostSize * Config::MAX_HIDDEN_SIZE_RATIO
        );
        
        // Account for header size
        size_t headerSize = sizeof(StegoHeader);
        if (maxHiddenSize < headerSize) {
            throw FileSizeException("Host file too small to hide any data");
        }
        
        maxHiddenSize -= headerSize;
        
        // Check if hidden file fits
        if (hiddenSize > maxHiddenSize) {
            throw FileSizeException(
                "The file to hide exceeds the allowable size.\n" +
                string("  File size: ") + Utils::formatBytes(hiddenSize) + "\n" +
                string("  Maximum allowed: ") + Utils::formatBytes(maxHiddenSize) + "\n" +
                string("  Please choose a smaller file or a larger host file.")
            );
        }
        
        return maxHiddenSize;
    }
};

// ============================================================================
// FILE IO MANAGER CLASS
// ============================================================================
class FileIOManager {
public:
    /**
     * Reads entire file into memory
     * @param filename Path to file
     * @return Vector containing file data
     */
    static vector<unsigned char> readFile(const string& filename) {
        ifstream file(filename, ios::binary);
        if (!file.is_open()) {
            throw FileAccessException("Cannot open file for reading: " + filename);
        }
        
        // Get file size
        file.seekg(0, ios::end);
        size_t size = file.tellg();
        file.seekg(0, ios::beg);
        
        // Read file data
        vector<unsigned char> data(size);
        file.read(reinterpret_cast<char*>(data.data()), size);
        
        if (!file) {
            throw FileAccessException("Error reading file: " + filename);
        }
        
        file.close();
        return data;
    }
    
    /**
     * Writes data to file
     * @param filename Output file path
     * @param data Data to write
     */
    static void writeFile(const string& filename, const vector<unsigned char>& data) {
        ofstream file(filename, ios::binary);
        if (!file.is_open()) {
            throw FileAccessException("Cannot create output file: " + filename);
        }
        
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        
        if (!file) {
            throw FileAccessException("Error writing to file: " + filename);
        }
        
        file.close();
    }
    
    /**
     * Reads file in chunks for memory efficiency
     * @param filename Path to file
     * @param buffer Buffer to store data
     * @param offset Offset to start reading
     * @param size Number of bytes to read
     * @return Number of bytes actually read
     */
    static size_t readFileChunk(const string& filename, vector<unsigned char>& buffer,
                                size_t offset, size_t size) {
        ifstream file(filename, ios::binary);
        if (!file.is_open()) {
            throw FileAccessException("Cannot open file for reading: " + filename);
        }
        
        file.seekg(offset, ios::beg);
        buffer.resize(size);
        file.read(reinterpret_cast<char*>(buffer.data()), size);
        
        return file.gcount();
    }
};

// ============================================================================
// STEGANOGRAPHY ENGINE CLASS
// ============================================================================
class UniversalSteganography {
private:
    string hiddenFilePath;
    string hostFilePath;
    string outputFilePath;
    
    /**
     * Creates steganography header
     * @param hiddenFilename Original filename
     * @param hiddenSize Size of hidden file
     * @return Populated header structure
     */
    StegoHeader createHeader(const string& hiddenFilename, size_t hiddenSize) {
        StegoHeader header;
        header.hiddenFileSize = static_cast<uint32_t>(hiddenSize);
        
        string filename = Utils::extractFilename(hiddenFilename);
        header.filenameLength = min(filename.length(), 
                                    static_cast<size_t>(Config::MAX_FILENAME_LENGTH - 1));
        
        strncpy(header.filename, filename.c_str(), header.filenameLength);
        header.filename[header.filenameLength] = '\0';
        
        header.checksum = header.calculateChecksum();
        
        return header;
    }
    
    /**
     * Serializes header to byte vector
     * @param header Header structure
     * @return Byte vector containing header
     */
    vector<unsigned char> serializeHeader(const StegoHeader& header) {
        vector<unsigned char> buffer(sizeof(StegoHeader));
        memcpy(buffer.data(), &header, sizeof(StegoHeader));
        return buffer;
    }
    
    /**
     * Deserializes header from byte vector
     * @param buffer Byte vector containing header
     * @return Header structure
     */
    StegoHeader deserializeHeader(const vector<unsigned char>& buffer) {
        if (buffer.size() < sizeof(StegoHeader)) {
            throw InvalidFormatException("Invalid header size");
        }
        
        StegoHeader header;
        memcpy(&header, buffer.data(), sizeof(StegoHeader));
        return header;
    }

public:
    /**
     * Constructor
     * @param hiddenFile Path to file to hide
     * @param hostFile Path to host file
     * @param outputFile Path for output file
     */
    UniversalSteganography(const string& hiddenFile, 
                          const string& hostFile,
                          const string& outputFile)
        : hiddenFilePath(hiddenFile),
          hostFilePath(hostFile),
          outputFilePath(outputFile) {}
    
    /**
     * Hides file within host file
     */
    void hideFile() {
        cout << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "  INITIATING FILE HIDING PROCESS" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" << endl;
        
        // Step 1: Validate file access
        cout << "[1/5] Validating file access..." << endl;
        FileValidator::validateFileAccess(hiddenFilePath, "File to hide");
        FileValidator::validateFileAccess(hostFilePath, "Host file");
        cout << "      ✓ Files validated successfully\n" << endl;
        
        // Step 2: Get file sizes
        cout << "[2/5] Analyzing file sizes..." << endl;
        size_t hiddenSize = Utils::getFileSize(hiddenFilePath);
        size_t hostSize = Utils::getFileSize(hostFilePath);
        
        cout << "      • File to hide: " << Utils::formatBytes(hiddenSize) 
             << " (" << Utils::extractFilename(hiddenFilePath) << ")" << endl;
        cout << "      • Host file: " << Utils::formatBytes(hostSize)
             << " (" << Utils::extractFilename(hostFilePath) << ")" << endl;
        
        // Step 3: Validate size constraints
        cout << "\n[3/5] Checking size constraints..." << endl;
        size_t maxAllowed = FileValidator::validateAndCalculateMaxSize(hiddenSize, hostSize);
        double utilizationPercent = (static_cast<double>(hiddenSize) / maxAllowed) * 100.0;
        cout << "      ✓ Size check passed" << endl;
        cout << "      • Capacity utilization: " << fixed << setprecision(1) 
             << utilizationPercent << "%" << endl;
        cout << "      • Remaining capacity: " 
             << Utils::formatBytes(maxAllowed - hiddenSize) << "\n" << endl;
        
        // Step 4: Read files
        cout << "[4/5] Reading files..." << endl;
        vector<unsigned char> hostData = FileIOManager::readFile(hostFilePath);
        vector<unsigned char> hiddenData = FileIOManager::readFile(hiddenFilePath);
        cout << "      ✓ Files loaded into memory\n" << endl;
        
        // Step 5: Create output with embedded data
        cout << "[5/5] Embedding hidden file..." << endl;
        StegoHeader header = createHeader(hiddenFilePath, hiddenSize);
        vector<unsigned char> headerData = serializeHeader(header);
        
        // Construct output: host + header + hidden
        vector<unsigned char> output;
        output.reserve(hostData.size() + headerData.size() + hiddenData.size());
        
        output.insert(output.end(), hostData.begin(), hostData.end());
        output.insert(output.end(), headerData.begin(), headerData.end());
        output.insert(output.end(), hiddenData.begin(), hiddenData.end());
        
        // Write output
        FileIOManager::writeFile(outputFilePath, output);
        
        cout << "      ✓ File embedded successfully" << endl;
        cout << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "  ✓ OPERATION COMPLETED SUCCESSFULLY" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" << endl;
        cout << "Output file: " << outputFilePath << endl;
        cout << "Total size: " << Utils::formatBytes(output.size()) << endl;
        cout << "Hidden file: " << header.filename << " (" 
             << Utils::formatBytes(hiddenSize) << ")" << endl;
    }
    
    /**
     * Extracts hidden file from stego file
     */
    void extractFile() {
        cout << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "  INITIATING FILE EXTRACTION PROCESS" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" << endl;
        
        // Step 1: Validate file access
        cout << "[1/4] Validating file access..." << endl;
        FileValidator::validateFileAccess(hostFilePath, "Stego file");
        cout << "      ✓ File validated\n" << endl;
        
        // Step 2: Read file
        cout << "[2/4] Reading stego file..." << endl;
        vector<unsigned char> data = FileIOManager::readFile(hostFilePath);
        size_t fileSize = data.size();
        cout << "      • File size: " << Utils::formatBytes(fileSize) << "\n" << endl;
        
        // Step 3: Extract and validate header
        cout << "[3/4] Searching for hidden data..." << endl;
        if (data.size() < sizeof(StegoHeader)) {
            throw InvalidFormatException("File too small to contain hidden data");
        }
        
        // Header is located after original host file data
        size_t headerOffset = data.size() - sizeof(StegoHeader);
        
        // Search backwards for header signature
        bool found = false;
        for (size_t i = data.size() - sizeof(StegoHeader); i > 0; i--) {
            vector<unsigned char> potentialHeader(data.begin() + i, 
                                                  data.begin() + i + sizeof(StegoHeader));
            StegoHeader header = deserializeHeader(potentialHeader);
            
            if (header.magic == Config::MAGIC_SIGNATURE && header.validate()) {
                headerOffset = i;
                found = true;
                break;
            }
        }
        
        if (!found) {
            throw InvalidFormatException("No hidden data found in file");
        }
        
        vector<unsigned char> headerData(data.begin() + headerOffset,
                                        data.begin() + headerOffset + sizeof(StegoHeader));
        StegoHeader header = deserializeHeader(headerData);
        
        if (!header.validate()) {
            throw InvalidFormatException("Invalid or corrupted header");
        }
        
        cout << "      ✓ Hidden data located" << endl;
        cout << "      • Original filename: " << header.filename << endl;
        cout << "      • Hidden file size: " 
             << Utils::formatBytes(header.hiddenFileSize) << "\n" << endl;
        
        // Step 4: Extract hidden data
        cout << "[4/4] Extracting hidden file..." << endl;
        size_t hiddenDataOffset = headerOffset + sizeof(StegoHeader);
        
        if (hiddenDataOffset + header.hiddenFileSize > data.size()) {
            throw InvalidFormatException("Corrupted file: size mismatch");
        }
        
        vector<unsigned char> hiddenData(data.begin() + hiddenDataOffset,
                                        data.begin() + hiddenDataOffset + header.hiddenFileSize);
        
        // Generate output filename
        string extractedFilename = outputFilePath.empty() ? 
                                  string("extracted_") + header.filename : 
                                  outputFilePath;
        
        FileIOManager::writeFile(extractedFilename, hiddenData);
        
        cout << "      ✓ File extracted successfully" << endl;
        cout << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "  ✓ EXTRACTION COMPLETED SUCCESSFULLY" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" << endl;
        cout << "Extracted file: " << extractedFilename << endl;
        cout << "File size: " << Utils::formatBytes(hiddenData.size()) << endl;
    }
};

// ============================================================================
// USER INTERFACE CLASS
// ============================================================================
class ConsoleInterface {
private:
    /**
     * Displays program header
     */
    void displayHeader() {
        cout << "\n╔════════════════════════════════════════════════════════════╗" << endl;
        cout << "║                                                            ║" << endl;
        cout << "║        UNIVERSAL FILE STEGANOGRAPHY SYSTEM v1.0            ║" << endl;
        cout << "║                                                            ║" << endl;
        cout << "║     Hide ANY file type within ANY other file type          ║" << endl;
        cout << "║                                                            ║" << endl;
        cout << "╚════════════════════════════════════════════════════════════╝" << endl;
    }
    
    /**
     * Displays menu
     */
    void displayMenu() {
        cout << "\n┌────────────────────────────────────────────────────────────┐" << endl;
        cout << "│  MAIN MENU                                                 │" << endl;
        cout << "├────────────────────────────────────────────────────────────┤" << endl;
        cout << "│  1. Hide file within another file                          │" << endl;
        cout << "│  2. Extract hidden file                                    │" << endl;
        cout << "│  3. View system information                                │" << endl;
        cout << "│  4. Exit program                                           │" << endl;
        cout << "└────────────────────────────────────────────────────────────┘" << endl;
        cout << "\nEnter your choice (1-4): ";
    }
    
    /**
     * Gets user input with prompt
     */
    string getInput(const string& prompt) {
        cout << prompt;
        string input;
        getline(cin, input);
        return input;
    }
    
    /**
     * Handles file hiding operation
     */
    void handleHideFile() {
        cout << "\n" << string(60, '=') << endl;
        cout << "  HIDE FILE OPERATION" << endl;
        cout << string(60, '=') << "\n" << endl;
        cout << string(60, '=') << "\n" << endl;
        
        string hiddenFile = getInput("Enter the path of the file to hide: ");
        string hostFile = getInput("Enter the path of the host file: ");
        string outputFile = getInput("Enter the output file path: ");
        
        if (outputFile.empty()) {
            outputFile = "stego_" + Utils::extractFilename(hostFile);
            cout << "\nUsing default output filename: " << outputFile << endl;
        }
        
        UniversalSteganography stego(hiddenFile, hostFile, outputFile);
        stego.hideFile();
    }
    
    /**
     * Handles file extraction operation
     */
    void handleExtractFile() {
        cout << "\n" << string(60, '=') << endl;
        cout << "  EXTRACT FILE OPERATION" << endl;
        cout << string(60, '=') << "\n" << endl;
        cout << string(60, '=') << "\n" << endl;
        
        string stegoFile = getInput("Enter the path of the stego file: ");
        string outputFile = getInput("Enter output path (press Enter for auto): ");
        
        UniversalSteganography stego("", stegoFile, outputFile);
        stego.extractFile();
    }
    
    /**
     * Displays system information
     */
    void displaySystemInfo() {
        cout << "\n" << string(60, '=') << endl;
        cout << "  SYSTEM INFORMATION" << endl;
        cout << string(60, '=') << "\n" << endl;
        cout << string(60, '=') << "\n" << endl;
        
        cout << "Configuration Settings:" << endl;
        cout << "  • Maximum hidden size ratio: " 
             << (Config::MAX_HIDDEN_SIZE_RATIO * 100) << "%" << endl;
        cout << "  • Minimum host file size: " 
             << Utils::formatBytes(Config::MIN_HOST_SIZE) << endl;
        cout << "  • Magic signature: 0x" << hex << uppercase 
             << Config::MAGIC_SIGNATURE << dec << endl;
        cout << "  • Version: " << Config::VERSION << endl;
        
        cout << "\nSupported Operations:" << endl;
        cout << "  • Hide: ANY file type → ANY host file type" << endl;
        cout << "  • Extract: Retrieve hidden files from stego files" << endl;
        
        cout << "\nFeatures:" << endl;
        cout << "  • Universal format support" << endl;
        cout << "  • Automatic size validation" << endl;
        cout << "  • Data integrity checking" << endl;
        cout << "  • Original filename preservation" << endl;
        cout << "  • Robust error handling" << endl;
    }

public:
    /**
     * Main program loop
     */
    void run() {
        displayHeader();
        
        while (true) {
            try {
                displayMenu();
                
                int choice;
                cin >> choice;
                cin.ignore(); // Clear newline
                
                switch (choice) {
                    case 1:
                        handleHideFile();
                        break;
                        
                    case 2:
                        handleExtractFile();
                        break;
                        
                    case 3:
                        displaySystemInfo();
                        break;
                        
                    case 4:
                        cout << "\n╔════════════════════════════════════════════════════════════╗" << endl;
                        cout << "║  Thank you for using Universal Steganography System!      ║" << endl;
                        cout << "╚════════════════════════════════════════════════════════════╝\n" << endl;
                        return;
                        
                    default:
                        cout << "\n✗ Invalid choice. Please enter 1-4.\n" << endl;
                }
                
            } catch (const FileSizeException& e) {
                cout << "\n╔════════════════════════════════════════════════════════════╗" << endl;
                cout << "║  FILE SIZE ERROR                                           ║" << endl;
                cout << "╚════════════════════════════════════════════════════════════╝" << endl;
                cout << "\n" << e.what() << "\n" << endl;
                
            } catch (const FileAccessException& e) {
                cout << "\n╔════════════════════════════════════════════════════════════╗" << endl;
                cout << "║  FILE ACCESS ERROR                                         ║" << endl;
                cout << "╚════════════════════════════════════════════════════════════╝" << endl;
                cout << "\n✗ " << e.what() << "\n" << endl;
                
            } catch (const InvalidFormatException& e) {
                cout << "\n╔════════════════════════════════════════════════════════════╗" << endl;
                cout << "║  FORMAT ERROR                                              ║" << endl;
                cout << "╚════════════════════════════════════════════════════════════╝" << endl;
                cout << "\n✗ " << e.what() << "\n" << endl;
                
            } catch (const exception& e) {
                cout << "\n╔════════════════════════════════════════════════════════════╗" << endl;
                cout << "║  UNEXPECTED ERROR                                          ║" << endl;
                cout << "╚════════════════════════════════════════════════════════════╝" << endl;
                cout << "\n✗ " << e.what() << "\n" << endl;
            }
        }
    }
};

// ============================================================================
// MAIN FUNCTION
// ============================================================================
int main() {
    try {
        ConsoleInterface interface;
        interface.run();
        
    } catch (const exception& e) {
        cerr << "\n✗ Fatal error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}