#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <map>
#include <iomanip>
#include <fstream>  // for file operations

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
    int id;
    int baseSeverity;
    int resourceCost; // hours needed to handle
    int severity;
    int preDeformPercent;

    string ip;
    string type;     // e.g., DDoS, Malware, Virus
    string location; // derived from IP
    string status;   // e.g., Detected, Responded, Critical
};

// Map IP to location
string getLocationFromIP(const string& ip) {
    if (ip.find("192.") == 0) return "USA";
    if (ip.find("10.") == 0) return "Germany";
    if (ip.find("172.") == 0) return "China";
    return "Unknown";
}

// Compute severity with given rules
void computeSeverity(Threat& t) {
    t.severity = t.baseSeverity + (t.baseSeverity * t.preDeformPercent / 100);

    if (t.type == "Malware" || t.type == "Virus") {
        t.severity += 15;
        if (t.preDeformPercent > 40) {
            t.status = "Critical";
        }
    }
}

bool compareByID(const Threat& a, const Threat& b) {
    return a.id < b.id;
}

// Greedy based on severity/cost ratio
bool compareEfficiency(const Threat& a, const Threat& b) {
    return (double)a.severity / a.resourceCost > (double)b.severity / b.resourceCost;
}

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

void displayThreats(const vector<Threat>& threats, const string& header = "Threats Sorted by ID:", const string& color = COLOR_BRIGHT_CYAN) {
    vector<string> lines;
    lines.push_back(header);
    for (const auto& t : threats) {
        lines.push_back("ID: " + to_string(t.id) + ", Severity: " + to_string(t.severity) + ", Hours: " + to_string(t.resourceCost));
        lines.push_back("IP: " + t.ip + ", Type: " + t.type + ", Location: " + t.location + ", Status: " + t.status);
    }
    printBox(lines, color);
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

    if (totalUsed > 30) {
        cout << COLOR_BRIGHT_RED << "⚠  ALERT: Greedy response takes more than 30 hours! Consider reviewing selection.\n" << COLOR_RESET;
    }
}

int optimizeResponse(const vector<Threat>& threats, int resourceLimit, vector<int>& chosenIndices, int& totalUsed) {
    int n = (int)threats.size();
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

    if (totalUsed > 30) {
        cout << COLOR_BRIGHT_RED << "⚠  ALERT: DP response takes more than 30 hours! Consider revising resource allocation.\n" << COLOR_RESET;
    }
}

// Merge Sort Functions
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
}

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
}

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
}

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
}

void saveThreatsToFile(const vector<Threat>& threats, int totalResources, const string& filename = "threat_data.txt") {
    ofstream fout(filename);
    if (!fout.is_open()) {
        cout << COLOR_BRIGHT_RED << "Error opening file for writing.\n" << COLOR_RESET;
        return;
    }

    fout << "Total Available Resource Limit (hours): " << totalResources << "\n\n";
    fout << "Threat Data:\n";

    for (const auto& t : threats) {
        fout << "ID: " << t.id << "\n";
        fout << "Base Severity: " << t.baseSeverity << "\n";
        fout << "Response Time (hours): " << t.resourceCost << "\n";
        fout << "IP Address: " << t.ip << "\n";
        fout << "Location: " << t.location << "\n";
        fout << "Type: " << t.type << "\n";
        fout << "Status: " << t.status << "\n";
        fout << "Pre-Deformation Percentage: " << t.preDeformPercent << "\n";
        fout << "Computed Severity: " << t.severity << "\n";
        fout << "---------------------------------------\n";
    }

    fout.close();
    cout << COLOR_BRIGHT_GREEN << "Threat data saved successfully to " << filename << "\n" << COLOR_RESET;
}

int main() {
    vector<Threat> threats;
    int totalResources = 0;

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
        cin >> choice;

        if (choice == 1) {
            int n;
            cout << "Enter number of detected threats: ";
            cin >> n;
            if (n <= 0) {
                cout << "Invalid number.\n";
                continue;
            }

            threats.clear();
            threats.resize(n);

            for (int i = 0; i < n; ++i) {
                cout << "\n--- Threat " << (i + 1) << " ---\n";
                cout << "ID: ";
                cin >> threats[i].id;
                cout << "Base Severity: ";
                cin >> threats[i].baseSeverity;
                cout << "Response Time (hours): ";
                cin >> threats[i].resourceCost;
                if (threats[i].resourceCost <= 0) {
                    cout << "Resource cost must be positive.\n";
                    i--; // retry input for this threat
                    continue;
                }
                cout << "IP Address: ";
                cin >> threats[i].ip;
                threats[i].location = getLocationFromIP(threats[i].ip);
                cout << "Type (Malware/DDOS/etc): ";
                cin >> threats[i].type;
                cout << "Status (Detected/Responded/etc): ";
                cin >> threats[i].status;
                cout << "Pre-Deformation Percentage (0 if none): ";
                cin >> threats[i].preDeformPercent;

                computeSeverity(threats[i]);
            }

            cout << "Enter total available resource limit (hours): ";
            cin >> totalResources;
            if (totalResources <= 0) {
                cout << "Invalid resource limit.\n";
                continue;
            }

            mergeSort(threats, 0, (int)threats.size() - 1);

            displayThreats(threats);
            runGreedy(threats, totalResources);
            runDP(threats, totalResources);

            // Save to file here
            saveThreatsToFile(threats, totalResources);

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
