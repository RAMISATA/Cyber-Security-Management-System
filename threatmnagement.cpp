#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <map>
#include <iomanip>
#include <fstream>

using namespace std;

// ANSI Colors
const string COLOR_RESET = "\033[0m";
const string COLOR_BRIGHT_BLUE = "\033[94m";
const string COLOR_BRIGHT_GREEN = "\033[92m";
const string COLOR_BRIGHT_YELLOW = "\033[93m";
const string COLOR_BRIGHT_RED = "\033[91m";
const string COLOR_BRIGHT_CYAN = "\033[96m";
const string COLOR_BRIGHT_MAGENTA = "\033[95m";

struct Threat {
    int id = 0;
    int baseSeverity = 0;
    int resourceCost = 1; // positive hours needed to handle
    int severity = 0;
    int preDeformPercent = 0;

    string ip;
    string type;     // e.g., DDoS, Malware, Virus
    string location; // derived from IP
    string status;   // e.g., Detected, Responded, Critical
};

// Map IP to location (simple heuristic)
string getLocationFromIP(const string& ip) {
    if (ip.rfind("192.", 0) == 0) return "USA";
    if (ip.rfind("10.", 0) == 0) return "Germany";
    if (ip.rfind("172.", 0) == 0) return "China";
    if (ip.rfind("8.", 0) == 0) return "USA";
    return "Unknown";
}

// Heuristic to auto-detect type based on IP pattern and base severity
string detectType(const string& ip, int baseSeverity, int preDeform) {
    if (ip.rfind("192.", 0) == 0) return "DDoS";
    if (ip.rfind("10.", 0) == 0) return "Malware";
    if (ip.rfind("172.", 0) == 0) return "Virus";
    if (baseSeverity >= 80 || preDeform > 50) return "Ransomware";
    if (baseSeverity >= 50) return "Malware";
    return "Spyware";
}

// Heuristic to determine status
string detectStatus(int severity, int preDeform) {
    if (severity >= 85 || preDeform > 60) return "Critical";
    if (severity >= 60 || preDeform > 30) return "Active";
    return "Monitored";
}

// Compute severity with your rules (base + pre-deformation percent + extras)
void computeSeverity(Threat& t) {
    t.severity = t.baseSeverity + (t.baseSeverity * t.preDeformPercent / 100);

    if (t.type == "Malware" || t.type == "Virus" || t.type == "Ransomware") {
        t.severity += 15;
    } else if (t.type == "DDoS") {
        t.severity += 10;
    } else if (t.type == "Spyware") {
        t.severity += 5;
    }

    if (t.severity > 100) t.severity = 100;

    if (t.severity >= 90) t.status = "Critical";
}

// Print a box with colored border for lines
void printBox(const vector<string>& lines, const string& color = COLOR_BRIGHT_BLUE) {
    int maxLen = 0;
    for (const auto& line : lines)
        maxLen = max(maxLen, (int)line.length());

    string border = "+" + string(maxLen + 2, '-') + "+";

    cout << color << border << COLOR_RESET << "\n";
    for (const auto& line : lines) {
        cout << color << "| " << COLOR_RESET
             << line << string(maxLen - line.length(), ' ')
             << color << " |" << COLOR_RESET << "\n";
    }
    cout << color << border << COLOR_RESET << "\n\n";
}

// Append lines of text to file (append mode)
void appendTextToFile(const string& filename, const vector<string>& lines) {
    ofstream fout(filename, ios::app);
    if (!fout) {
        cerr << "Error opening file for writing.\n";
        return;
    }
    fout << "------------------------------\n";
    for (const auto& line : lines)
        fout << line << "\n";
    fout << "\n";
    fout.close();
}

// Display threats in box & save to file
void displayThreats(const vector<Threat>& threats, const string& header = "Threats Sorted by ID:", const string& color = COLOR_BRIGHT_CYAN) {
    vector<string> lines;
    lines.push_back(header);
    for (const auto& t : threats) {
        lines.push_back("ID: " + to_string(t.id) + ", Severity: " + to_string(t.severity) + ", Hours: " + to_string(t.resourceCost));
        lines.push_back("IP: " + t.ip + ", Type: " + t.type + ", Location: " + t.location + ", Status: " + t.status);
    }
    printBox(lines, color);
    appendTextToFile("ThreatsReport.txt", lines);
}

// Greedy based on severity/cost ratio, display & save
bool compareEfficiency(const Threat& a, const Threat& b) {
    double ra = (a.resourceCost > 0) ? (double)a.severity / a.resourceCost : (double)a.severity;
    double rb = (b.resourceCost > 0) ? (double)b.severity / b.resourceCost : (double)b.severity;
    if (ra == rb) return a.id < b.id;
    return ra > rb;
}

void runGreedy(const vector<Threat>& threats, int resourceLimit) {
    vector<Threat> sortedThreats = threats;
    sort(sortedThreats.begin(), sortedThreats.end(), compareEfficiency);

    int totalSeverity = 0, totalUsed = 0;
    vector<Threat> chosen;

    for (const auto& t : sortedThreats) {
        if (totalUsed + t.resourceCost <= resourceLimit) {
            totalUsed += t.resourceCost;
            totalSeverity += t.severity;
            chosen.push_back(t);
        }
    }

    vector<string> lines;
    lines.push_back("Greedy Selection (Severity/Cost Ratio):");
    lines.push_back("Total Severity: " + to_string(totalSeverity) + ", Hours Used: " + to_string(totalUsed));
    lines.push_back("Chosen Threats:");
    for (const auto& t : chosen) {
        lines.push_back("ID: " + to_string(t.id) + ", Severity: " + to_string(t.severity) + ", Hours: " + to_string(t.resourceCost));
        lines.push_back("IP: " + t.ip + ", Type: " + t.type + ", Location: " + t.location + ", Status: " + t.status);
    }
    printBox(lines, COLOR_BRIGHT_YELLOW);
    appendTextToFile("ThreatsReport.txt", lines);

    if (totalUsed > 30) {
        cout << COLOR_BRIGHT_RED << "⚠  ALERT: Greedy response takes more than 30 hours! Consider reviewing selection.\n" << COLOR_RESET;
    }
}

// DP knapsack optimization
int optimizeResponse(const vector<Threat>& threats, int resourceLimit, vector<int>& chosenIndices, int& totalUsed) {
    int n = (int)threats.size();
    if (n == 0) return 0;
    vector<vector<int>> dp(n + 1, vector<int>(resourceLimit + 1, 0));

    for (int i = 1; i <= n; i++) {
        int cost = threats[i - 1].resourceCost;
        int sev = threats[i - 1].severity;
        for (int r = 0; r <= resourceLimit; r++) {
            if (cost <= r)
                dp[i][r] = max(dp[i - 1][r], dp[i - 1][r - cost] + sev);
            else
                dp[i][r] = dp[i - 1][r];
        }
    }

    int r = resourceLimit;
    totalUsed = 0;
    chosenIndices.clear();
    for (int i = n; i > 0; i--) {
        if (dp[i][r] != dp[i - 1][r]) {
            chosenIndices.push_back(i - 1);
            r -= threats[i - 1].resourceCost;
            totalUsed += threats[i - 1].resourceCost;
        }
    }
    reverse(chosenIndices.begin(), chosenIndices.end());
    return dp[n][resourceLimit];
}

void runDP(const vector<Threat>& threats, int resourceLimit) {
    vector<int> chosenIndices;
    int totalUsed = 0;
    int maxSeverity = optimizeResponse(threats, resourceLimit, chosenIndices, totalUsed);

    vector<string> lines;
    lines.push_back("Dynamic Programming Optimization:");
    lines.push_back("Max Severity: " + to_string(maxSeverity) + ", Hours Used: " + to_string(totalUsed));
    lines.push_back("Chosen Threats:");
    for (int idx : chosenIndices) {
        const Threat& t = threats[idx];
        lines.push_back("ID: " + to_string(t.id) + ", Severity: " + to_string(t.severity) + ", Hours: " + to_string(t.resourceCost));
        lines.push_back("IP: " + t.ip + ", Type: " + t.type + ", Location: " + t.location + ", Status: " + t.status);
    }
    printBox(lines, COLOR_BRIGHT_GREEN);
    appendTextToFile("ThreatsReport.txt", lines);

    if (totalUsed > 30) {
        cout << COLOR_BRIGHT_RED << "⚠  ALERT: DP response takes more than 30 hours! Consider revising resource allocation.\n" << COLOR_RESET;
    }
}

// Merge Sort for sorting Threats by id
void merge(vector<Threat>& threats, int left, int mid, int right) {
    int n1 = mid - left + 1;
    int n2 = right - mid;

    vector<Threat> L(n1);
    vector<Threat> R(n2);

    for (int i = 0; i < n1; ++i)
        L[i] = threats[left + i];
    for (int j = 0; j < n2; ++j)
        R[j] = threats[mid + 1 + j];

    int i = 0, j = 0, k = left;
    while (i < n1 && j < n2) {
        if (L[i].id <= R[j].id)
            threats[k++] = L[i++];
        else
            threats[k++] = R[j++];
    }

    while (i < n1)
        threats[k++] = L[i++];
    while (j < n2)
        threats[k++] = R[j++];
}

void mergeSort(vector<Threat>& threats, int left, int right) {
    if (left < right) {
        int mid = left + (right - left) / 2;
        mergeSort(threats, left, mid);
        mergeSort(threats, mid + 1, right);
        merge(threats, left, mid, right);
    }
}

// Show Top N most severe threats & save
void showTopN(const vector<Threat>& threats) {
    if (threats.empty()) {
        cout << COLOR_BRIGHT_RED << "No threats data available.\n" << COLOR_RESET;
        return;
    }
    int N;
    cout << "Enter N to show top N most severe threats: ";
    cin >> N;
    if (N <= 0) {
        cout << COLOR_BRIGHT_RED << "Invalid number.\n" << COLOR_RESET;
        return;
    }

    vector<Threat> sortedThreats = threats;
    sort(sortedThreats.begin(), sortedThreats.end(), [](const Threat& a, const Threat& b) {
        if (a.severity == b.severity) return a.id < b.id;
        return a.severity > b.severity;
    });

    vector<string> lines;
    lines.push_back("Top " + to_string(N) + " Most Severe Threats:");
    for (int i = 0; i < N && i < (int)sortedThreats.size(); i++) {
        const Threat& t = sortedThreats[i];
        lines.push_back("ID: " + to_string(t.id) + ", Severity: " + to_string(t.severity) + ", Hours: " + to_string(t.resourceCost));
        lines.push_back("IP: " + t.ip + ", Type: " + t.type + ", Location: " + t.location + ", Status: " + t.status);
    }
    printBox(lines, COLOR_BRIGHT_BLUE);
    appendTextToFile("ThreatsReport.txt", lines);
}

// Search Threat by IP & save
void searchByIP(const vector<Threat>& threats) {
    if (threats.empty()) {
        cout << COLOR_BRIGHT_RED << "No threats data available.\n" << COLOR_RESET;
        return;
    }
    string searchIP;
    cout << "Enter IP Address to search: ";
    cin >> searchIP;

    vector<string> lines;
    lines.push_back("Search Results for IP: " + searchIP);
    bool found = false;
    for (const auto& t : threats) {
        if (t.ip == searchIP) {
            lines.push_back("ID: " + to_string(t.id) + ", Severity: " + to_string(t.severity) + ", Hours: " + to_string(t.resourceCost));
            lines.push_back("Type: " + t.type + ", Location: " + t.location + ", Status: " + t.status);
            found = true;
        }
    }
    if (!found) {
        cout << COLOR_BRIGHT_YELLOW << "No threat found with IP " << searchIP << ".\n" << COLOR_RESET;
        return;
    }
    printBox(lines, COLOR_BRIGHT_GREEN);
    appendTextToFile("ThreatsReport.txt", lines);
}

// Count threats by type & save
void countByType(const vector<Threat>& threats) {
    if (threats.empty()) {
        cout << COLOR_BRIGHT_RED << "No threats data available.\n" << COLOR_RESET;
        return;
    }
    map<string, int> counts;
    for (const auto& t : threats)
        counts[t.type]++;

    vector<string> lines;
    lines.push_back("Threat Counts by Type:");
    for (auto& [type, count] : counts) {
        lines.push_back(type + ": " + to_string(count));
    }
    printBox(lines, COLOR_BRIGHT_BLUE);
    appendTextToFile("ThreatsReport.txt", lines);
}

// Show system summary & save
void showSummary(const vector<Threat>& threats, int totalResources) {
    if (threats.empty()) {
        cout << COLOR_BRIGHT_RED << "No threats data available.\n" << COLOR_RESET;
        return;
    }
    int totalHours = 0, totalSeverity = 0;
    for (const auto& t : threats) {
        totalHours += t.resourceCost;
        totalSeverity += t.severity;
    }

    vector<string> lines;
    lines.push_back("System Summary:");
    lines.push_back("Total Threats: " + to_string((int)threats.size()));
    lines.push_back("Total Response Hours Needed: " + to_string(totalHours));
    lines.push_back("Total Severity Score: " + to_string(totalSeverity));
    lines.push_back("Available Response Hours: " + to_string(totalResources));

    printBox(lines, COLOR_BRIGHT_YELLOW);
    appendTextToFile("ThreatsReport.txt", lines);
}

// Save all threats to file (full report)
void saveThreatsToFile(const vector<Threat>& threats, const string& filename) {
    ofstream fout(filename);
    if (!fout) {
        cerr << "Error opening file for writing.\n";
        return;
    }

    fout << "========= Threats Report =========\n\n";
    for (const auto& t : threats) {
        fout << "ID: " << t.id << "\n";
        fout << "Base Severity: " << t.baseSeverity << "\n";
        fout << "Response Time (hours): " << t.resourceCost << "\n";
        fout << "IP Address: " << t.ip << "\n";
        fout << "Location: " << t.location << "\n";
        fout << "Type: " << t.type << "\n";
        fout << "Pre-Deformation %: " << t.preDeformPercent << "\n";
        fout << "Computed Severity: " << t.severity << "\n";
        fout << "Status: " << t.status << "\n";
        fout << "-------------------------\n";
    }
    fout.close();
    cout << COLOR_BRIGHT_GREEN << "Threat data saved to " << filename << "\n" << COLOR_RESET;
}

int main() {
    vector<Threat> threats;
    int totalResources = 0;

    // Clear or create file on start to avoid appending old data repeatedly
    ofstream ofs("ThreatsReport.txt");
    ofs.close();

    while (true) {
        cout << COLOR_BRIGHT_CYAN
             << "\n================= CYBER THREAT RESPONSE SYSTEM =================\n"
             << COLOR_RESET;

        cout << COLOR_BRIGHT_MAGENTA
             << "1. Input Threat Data\n"
             << "2. Display All Threats\n"
             << "3. Run Greedy Optimization\n"
             << "4. Run Dynamic Programming Optimization\n"
             << "5. Show Top N Most Severe Threats\n"
             << "6. Search Threat by IP Address\n"
             << "7. Count Threats by Type\n"
             << "8. Show System Summary\n"
             << "9. Exit\n"
             << COLOR_RESET;

        cout << "Enter your choice: ";
        int choice;
        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << COLOR_BRIGHT_RED << "Invalid input. Try again.\n" << COLOR_RESET;
            continue;
        }

        if (choice == 1) {
            int n;
            cout << "Enter number of detected threats: ";
            if (!(cin >> n) || n <= 0) {
                cout << COLOR_BRIGHT_RED << "Invalid number.\n" << COLOR_RESET;
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                continue;
            }

            threats.clear();
            threats.resize(n);

                     for (int i = 0; i < n; ++i) {
                cout << "\n--- Threat " << (i + 1) << " ---\n";
                cout << "ID: ";
                while (!(cin >> threats[i].id)) {
                    cout << "Invalid ID. Enter integer: ";
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                }

                cout << "Base Severity (0-100): ";
                while (!(cin >> threats[i].baseSeverity) || threats[i].baseSeverity < 0) {
                    cout << "Invalid severity. Enter non-negative integer: ";
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                }

                cout << "Response Time (hours, positive): ";
                while (!(cin >> threats[i].resourceCost) || threats[i].resourceCost <= 0) {
                    cout << "Resource cost must be positive. Enter integer (>0): ";
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                }

                cout << "IP Address: ";
                cin >> threats[i].ip;
                threats[i].location = getLocationFromIP(threats[i].ip);

                cout << "Pre-Deformation Percentage (0 if none): ";
                while (!(cin >> threats[i].preDeformPercent) || threats[i].preDeformPercent < 0) {
                    cout << "Invalid percentage. Enter non-negative integer: ";
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                }

                // Auto-detect type and status
                threats[i].type = detectType(threats[i].ip, threats[i].baseSeverity, threats[i].preDeformPercent);
                threats[i].status = detectStatus(threats[i].baseSeverity + (threats[i].baseSeverity * threats[i].preDeformPercent / 100), threats[i].preDeformPercent);

                // Compute final severity (which may update status for very high severity)
                computeSeverity(threats[i]);

                // Re-evaluate status after computing severity
                if (threats[i].status != "Critical")
                    threats[i].status = detectStatus(threats[i].severity, threats[i].preDeformPercent);
            }

            cout << "Enter total available resource limit (hours): ";
            while (!(cin >> totalResources) || totalResources <= 0) {
                cout << "Invalid resource limit. Enter positive integer: ";
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }

            // Sort threats by ID using merge sort
            if (!threats.empty())
                mergeSort(threats, 0, (int)threats.size() - 1);

            // Save initial full data to file (overwrite)
            saveThreatsToFile(threats, "ThreatsReport.txt");

            // Display and save reports after input
            displayThreats(threats);
            runGreedy(threats, totalResources);
            runDP(threats, totalResources);

            cout << COLOR_BRIGHT_GREEN << "Threat data input and analysis complete.\n" << COLOR_RESET;
        }
        else if (choice == 2) {
            if (threats.empty()) {
                cout << COLOR_BRIGHT_RED << "No threat data available. Please input data first.\n" << COLOR_RESET;
            } else {
                displayThreats(threats);
            }
        }
        else if (choice == 3) {
            if (threats.empty()) {
                cout << COLOR_BRIGHT_RED << "No threat data available. Please input data first.\n" << COLOR_RESET;
            } else {
                runGreedy(threats, totalResources);
            }
        }
        else if (choice == 4) {
            if (threats.empty()) {
                cout << COLOR_BRIGHT_RED << "No threat data available. Please input data first.\n" << COLOR_RESET;
            } else {
                runDP(threats, totalResources);
            }
        }
        else if (choice == 5) {
            showTopN(threats);
        }
        else if (choice == 6) {
            searchByIP(threats);
        }
        else if (choice == 7) {
            countByType(threats);
        }
        else if (choice == 8) {
            showSummary(threats, totalResources);
        }
        else if (choice == 9) {
            cout << COLOR_BRIGHT_BLUE << "Exiting program. Goodbye!\n" << COLOR_RESET;
            break;
        }
        else {
            cout << COLOR_BRIGHT_RED << "Invalid choice! Please enter a valid option.\n" << COLOR_RESET;
        }
    }

    return 0;
}

