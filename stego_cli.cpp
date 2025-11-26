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
namespace Config
{
    const double MAX_HIDDEN_SIZE_RATIO = 0.85;
    const size_t MIN_HOST_SIZE = 10240;
    const uint32_t MAGIC_SIGNATURE = 0x5354454E;
    const uint16_t VERSION = 0x0001;
    const size_t MAX_FILENAME_LENGTH = 256;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
namespace Utils
{
    size_t getFileSize(const string &filename)
    {
        struct stat stat_buf;
        int rc = stat(filename.c_str(), &stat_buf);
        return rc == 0 ? stat_buf.st_size : 0;
    }

    bool fileExists(const string &filename)
    {
        ifstream file(filename, ios::binary);
        return file.good();
    }

    string formatBytes(size_t bytes)
    {
        const char *units[] = {"B", "KB", "MB", "GB", "TB"};
        int unitIndex = 0;
        double size = static_cast<double>(bytes);

        while (size >= 1024.0 && unitIndex < 4)
        {
            size /= 1024.0;
            unitIndex++;
        }

        ostringstream oss;
        oss << fixed << setprecision(2) << size << " " << units[unitIndex];
        return oss.str();
    }

    string extractFilename(const string &fullPath)
    {
        size_t pos = fullPath.find_last_of("/\\");
        return (pos == string::npos) ? fullPath : fullPath.substr(pos + 1);
    }

    string getExtension(const string &filename)
    {
        size_t pos = filename.find_last_of('.');
        if (pos == string::npos)
            return "";

        string ext = filename.substr(pos);
        transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        return ext;
    }

    string generateOutputFilename(const string &userProvidedPath, const string &originalFilename)
    {
        if (userProvidedPath.empty())
        {
            // No output path specified, use original filename with prefix
            return string("extracted_") + originalFilename;
        }

        // Check if user-provided path already has an extension
        size_t outputDotPos = userProvidedPath.find_last_of('.');
        size_t outputSlashPos = userProvidedPath.find_last_of("/\\");

        // Determine if output path has a valid extension
        bool hasExtension = (outputDotPos != string::npos) &&
                            (outputSlashPos == string::npos || outputDotPos > outputSlashPos);

        if (hasExtension)
        {
            // User provided complete filename with extension
            return userProvidedPath;
        }
        else
        {
            // User provided path without extension, append original extension
            string originalExt = getExtension(originalFilename);
            return userProvidedPath + originalExt;
        }
    }
}

// ============================================================================
// EXCEPTION CLASSES
// ============================================================================
class SteganographyException : public runtime_error
{
public:
    explicit SteganographyException(const string &msg) : runtime_error(msg) {}
};

class FileSizeException : public SteganographyException
{
public:
    explicit FileSizeException(const string &msg) : SteganographyException(msg) {}
};

class FileAccessException : public SteganographyException
{
public:
    explicit FileAccessException(const string &msg) : SteganographyException(msg) {}
};

class InvalidFormatException : public SteganographyException
{
public:
    explicit InvalidFormatException(const string &msg) : SteganographyException(msg) {}
};

// ============================================================================
// FILE HEADER STRUCTURE
// ============================================================================
struct StegoHeader
{
    uint32_t magic;
    uint16_t version;
    uint32_t hiddenFileSize;
    uint16_t filenameLength;
    char filename[Config::MAX_FILENAME_LENGTH];
    uint32_t checksum;

    StegoHeader() : magic(Config::MAGIC_SIGNATURE),
                    version(Config::VERSION),
                    hiddenFileSize(0),
                    filenameLength(0),
                    checksum(0)
    {
        memset(filename, 0, Config::MAX_FILENAME_LENGTH);
    }

    uint32_t calculateChecksum() const
    {
        uint32_t sum = magic + version + hiddenFileSize + filenameLength;
        for (size_t i = 0; i < filenameLength && i < Config::MAX_FILENAME_LENGTH; i++)
        {
            sum += static_cast<unsigned char>(filename[i]);
        }
        return sum;
    }

    bool validate() const
    {
        return magic == Config::MAGIC_SIGNATURE && checksum == calculateChecksum();
    }
};

// ============================================================================
// FILE VALIDATOR CLASS
// ============================================================================
class FileValidator
{
public:
    static void validateFileAccess(const string &filename, const string &fileType)
    {
        if (filename.empty())
        {
            throw FileAccessException(fileType + " path cannot be empty");
        }

        if (!Utils::fileExists(filename))
        {
            throw FileAccessException(fileType + " not found or not accessible: " + filename);
        }
    }

    static size_t validateAndCalculateMaxSize(size_t hiddenSize, size_t hostSize)
    {
        // Check minimum host size
        if (hostSize < Config::MIN_HOST_SIZE)
        {
            throw FileSizeException(
                "Host file too small. Minimum size: " +
                Utils::formatBytes(Config::MIN_HOST_SIZE));
        }

        // Calculate maximum allowed hidden size
        size_t maxHiddenSize = static_cast<size_t>(
            hostSize * Config::MAX_HIDDEN_SIZE_RATIO);

        // Account for header size
        size_t headerSize = sizeof(StegoHeader);
        if (maxHiddenSize < headerSize)
        {
            throw FileSizeException("Host file too small to hide any data");
        }

        maxHiddenSize -= headerSize;

        // Check if hidden file fits
        if (hiddenSize > maxHiddenSize)
        {
            throw FileSizeException(
                "The file to hide exceeds the allowable size.\n" +
                string("  File size: ") + Utils::formatBytes(hiddenSize) + "\n" +
                string("  Maximum allowed: ") + Utils::formatBytes(maxHiddenSize) + "\n" +
                string("  Please choose a smaller file or a larger host file."));
        }

        return maxHiddenSize;
    }
};

// ============================================================================
// FILE IO MANAGER CLASS
// ============================================================================
class FileIOManager
{
public:
    static vector<unsigned char> readFile(const string &filename)
    {
        ifstream file(filename, ios::binary);
        if (!file.is_open())
        {
            throw FileAccessException("Cannot open file for reading: " + filename);
        }

        // Get file size
        file.seekg(0, ios::end);
        size_t size = file.tellg();
        file.seekg(0, ios::beg);

        // Read file data
        vector<unsigned char> data(size);
        file.read(reinterpret_cast<char *>(data.data()), size);

        if (!file)
        {
            throw FileAccessException("Error reading file: " + filename);
        }

        file.close();
        return data;
    }

    static void writeFile(const string &filename, const vector<unsigned char> &data)
    {
        ofstream file(filename, ios::binary);
        if (!file.is_open())
        {
            throw FileAccessException("Cannot create output file: " + filename);
        }

        file.write(reinterpret_cast<const char *>(data.data()), data.size());

        if (!file)
        {
            throw FileAccessException("Error writing to file: " + filename);
        }

        file.close();
    }
};

// ============================================================================
// STEGANOGRAPHY ENGINE CLASS
// ============================================================================
class UniversalSteganography
{
private:
    string hiddenFilePath;
    string hostFilePath;
    string outputFilePath;

    StegoHeader createHeader(const string &hiddenFilename, size_t hiddenSize)
    {
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

    vector<unsigned char> serializeHeader(const StegoHeader &header)
    {
        vector<unsigned char> buffer(sizeof(StegoHeader));
        memcpy(buffer.data(), &header, sizeof(StegoHeader));
        return buffer;
    }

    StegoHeader deserializeHeader(const vector<unsigned char> &buffer)
    {
        if (buffer.size() < sizeof(StegoHeader))
        {
            throw InvalidFormatException("Invalid header size");
        }

        StegoHeader header;
        memcpy(&header, buffer.data(), sizeof(StegoHeader));
        return header;
    }

public:
    UniversalSteganography(const string &hiddenFile,
                           const string &hostFile,
                           const string &outputFile)
        : hiddenFilePath(hiddenFile),
          hostFilePath(hostFile),
          outputFilePath(outputFile) {}

    void hideFile()
    {
        cout << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "  INITIATING FILE HIDING PROCESS" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
             << endl;

        // Step 1: Validate file access
        cout << "[1/5] Validating file access..." << endl;
        FileValidator::validateFileAccess(hiddenFilePath, "File to hide");
        FileValidator::validateFileAccess(hostFilePath, "Host file");
        cout << "      ✓ Files validated successfully\n"
             << endl;

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
             << Utils::formatBytes(maxAllowed - hiddenSize) << "\n"
             << endl;

        // Step 4: Read files
        cout << "[4/5] Reading files..." << endl;
        vector<unsigned char> hostData = FileIOManager::readFile(hostFilePath);
        vector<unsigned char> hiddenData = FileIOManager::readFile(hiddenFilePath);
        cout << "      ✓ Files loaded into memory\n"
             << endl;

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

        // Ensure output file has same extension as cover/host file
        string finalOutputPath = Utils::generateOutputFilename(outputFilePath, Utils::extractFilename(hostFilePath));

        // Write output
        FileIOManager::writeFile(finalOutputPath, output);

        cout << "      ✓ File embedded successfully" << endl;
        cout << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "  ✓ OPERATION COMPLETED SUCCESSFULLY" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
             << endl;
        cout << "Output file: " << finalOutputPath << endl;
        cout << "Total size: " << Utils::formatBytes(output.size()) << endl;
        cout << "Hidden file: " << header.filename << " ("
             << Utils::formatBytes(hiddenSize) << ")" << endl;
    }

    void extractFile()
    {
        cout << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "  INITIATING FILE EXTRACTION PROCESS" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
             << endl;

        // Step 1: Validate file access
        cout << "[1/4] Validating file access..." << endl;
        FileValidator::validateFileAccess(hostFilePath, "Stego file");
        cout << "      ✓ File validated\n"
             << endl;

        // Step 2: Read file
        cout << "[2/4] Reading stego file..." << endl;
        vector<unsigned char> data = FileIOManager::readFile(hostFilePath);
        size_t fileSize = data.size();
        cout << "      • File size: " << Utils::formatBytes(fileSize) << "\n"
             << endl;

        // Step 3: Extract and validate header
        cout << "[3/4] Searching for hidden data..." << endl;
        if (data.size() < sizeof(StegoHeader))
        {
            throw InvalidFormatException("File too small to contain hidden data");
        }

        // Header is located after original host file data
        size_t headerOffset = data.size() - sizeof(StegoHeader);

        // Search backwards for header signature
        bool found = false;
        for (size_t i = data.size() - sizeof(StegoHeader); i > 0; i--)
        {
            vector<unsigned char> potentialHeader(data.begin() + i,
                                                  data.begin() + i + sizeof(StegoHeader));
            StegoHeader header = deserializeHeader(potentialHeader);

            if (header.magic == Config::MAGIC_SIGNATURE && header.validate())
            {
                headerOffset = i;
                found = true;
                break;
            }
        }

        if (!found)
        {
            throw InvalidFormatException("No hidden data found in file");
        }

        vector<unsigned char> headerData(data.begin() + headerOffset,
                                         data.begin() + headerOffset + sizeof(StegoHeader));
        StegoHeader header = deserializeHeader(headerData);

        if (!header.validate())
        {
            throw InvalidFormatException("Invalid or corrupted header");
        }

        cout << "      ✓ Hidden data located" << endl;
        cout << "      • Original filename: " << header.filename << endl;
        cout << "      • Hidden file size: "
             << Utils::formatBytes(header.hiddenFileSize) << "\n"
             << endl;

        // Step 4: Extract hidden data
        cout << "[4/4] Extracting hidden file..." << endl;
        size_t hiddenDataOffset = headerOffset + sizeof(StegoHeader);

        if (hiddenDataOffset + header.hiddenFileSize > data.size())
        {
            throw InvalidFormatException("Corrupted file: size mismatch");
        }

        vector<unsigned char> hiddenData(data.begin() + hiddenDataOffset,
                                         data.begin() + hiddenDataOffset + header.hiddenFileSize);

        // Generate output filename with proper extension preservation
        string extractedFilename = Utils::generateOutputFilename(outputFilePath, header.filename);

        FileIOManager::writeFile(extractedFilename, hiddenData);

        cout << "      ✓ File extracted successfully" << endl;
        cout << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "  ✓ EXTRACTION COMPLETED SUCCESSFULLY" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
             << endl;
        cout << "Extracted file: " << extractedFilename << endl;
        cout << "File size: " << Utils::formatBytes(hiddenData.size()) << endl;
    }
};

// ============================================================================
// MAIN FUNCTION - Command Line Interface
// ============================================================================
void printUsage()
{
    cout << "Usage:" << endl;
    cout << "  Encode: stego encode <cover_image> <secret_file> <output_image>" << endl;
    cout << "  Decode: stego decode <stego_image> <output_file>" << endl;
}

int main(int argc, char *argv[])
{
    try
    {
        if (argc < 2)
        {
            printUsage();
            return 1;
        }

        string mode = argv[1];

        if (mode == "encode")
        {
            if (argc != 5)
            {
                cerr << "ERROR: Encode requires 3 arguments" << endl;
                printUsage();
                return 1;
            }

            string coverImage = argv[2];
            string secretFile = argv[3];
            string outputImage = argv[4];

            UniversalSteganography stego(secretFile, coverImage, outputImage);
            stego.hideFile();
        }
        else if (mode == "decode")
        {
            if (argc != 4)
            {
                cerr << "ERROR: Decode requires 2 arguments" << endl;
                printUsage();
                return 1;
            }

            string stegoImage = argv[2];
            string outputFile = argv[3];

            UniversalSteganography stego("", stegoImage, outputFile);
            stego.extractFile();
        }
        else
        {
            cerr << "ERROR: Invalid mode. Use 'encode' or 'decode'" << endl;
            printUsage();
            return 1;
        }
    }
    catch (const SteganographyException &e)
    {
        cerr << "ERROR: " << e.what() << endl;
        return 1;
    }
    catch (const exception &e)
    {
        cerr << "FATAL ERROR: " << e.what() << endl;
        return 1;
    }

    return 0;
}
