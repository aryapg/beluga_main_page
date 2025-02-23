from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import pefile
import hashlib
import oletools.olevba as olevba
from collections import Counter
import math
import PyPDF2
import zipfile
import concurrent.futures
import time
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from fpdf import FPDF

app = Flask(__name__)
CORS(app)

# Define suspicious keywords at the top level
suspicious_keywords = ["cmd.exe", "powershell.exe", "wscript.shell", "regsvr32", "certutil"]

# Regex patterns to replace YARA rules
REGEX_PATTERNS = {
    "SuspiciousPE": [
        r"MZ.{2}PE",  # More specific PE file signature
        r"This program cannot be run in DOS mode.",
        r"cmd\.exe\s*[-/].*",
        r"powershell\.exe\s*[-/].*",
        r"CreateProcess\s*\(",
        r"WinExec\s*\(",
        r"ShellExecute\s*\(",
        r"wscript\.shell\s*\.",
        r"regsvr32\s*[-/].*",
        r"certutil\s*[-/].*",
    ],
    "SuspiciousScript": [
        r"eval\s*\(",
        r"base64_decode\s*\(",
        r"shell_exec\s*\(",
        r"exec\s*\(",
    ],
}

# Initialize counters
total_scans = 0
true_positives = 0
true_negatives = 0
false_positives = 0
false_negatives = 0

# Maximum file size limit (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

def sanitize_filename(filename):
    """Sanitizes the file name to prevent directory traversal and other attacks."""
    return re.sub(r"[^\w\-.]", "", filename)

def scan_file(file_path, is_malicious):
    """Scans a file for malware indicators."""
    global total_scans, true_positives, true_negatives, false_positives, false_negatives

    total_scans += 1
    results = {"file_name": os.path.basename(file_path), "malicious": False, "indicators": [], "risk_score": 0}

    print(f"\nScanning file: {file_path}")

    # Input validation
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return results

    if not os.path.isfile(file_path):
        print(f"Path is not a file: {file_path}")
        return results

    # Check file size
    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        results["indicators"].append(f"File size exceeds limit: {file_size} bytes")
        print(f"File size exceeds limit: {file_size} bytes")
        return results

    # Regex-based pattern matching
    with open(file_path, "rb") as f:
        file_content = f.read().decode(errors="ignore")  # Decode for regex matching

        for rule_name, patterns in REGEX_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, file_content, re.IGNORECASE):
                    results["malicious"] = True
                    results["indicators"].append(f"Regex matched: {pattern} (Rule: {rule_name})")
                    results["risk_score"] += 30  # Increase risk score for regex matches
                    print(f"Regex matched: {pattern} (Rule: {rule_name})")

    # EICAR test file check
    if b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in file_content.encode():
        results["malicious"] = True
        results["indicators"].append("EICAR test file detected.")
        results["risk_score"] += 100  # Maximum risk score for EICAR
        print("EICAR test file detected.")

    # Check for suspicious content in .txt files
    if file_path.endswith(".txt"):
        for keyword in suspicious_keywords:
            if keyword.encode() in file_content.encode():
                results["malicious"] = True
                results["indicators"].append(f"Suspicious keyword detected: {keyword}")
                results["risk_score"] += 20  # Increase risk score for suspicious keywords
                print(f"Suspicious keyword detected: {keyword}")

    # Enhanced PDF analysis
    if file_path.endswith(".pdf"):
        pdf_analysis_result = analyze_pdf_file(file_path)
        if pdf_analysis_result["malicious"]:
            results["malicious"] = True
            results["indicators"].append(pdf_analysis_result["indicators"])
            results["risk_score"] += 30  # Increase risk score for PDF analysis

    # PE File Analysis (for .exe and .dll files)
    if file_path.endswith((".exe", ".dll")):
        pe_analysis_result = analyze_pe_file(file_path)
        if pe_analysis_result["malicious"]:
            results["malicious"] = True
            results["indicators"].append(pe_analysis_result["indicators"])
            results["risk_score"] += 40  # Increase risk score for PE analysis

    # Macro Analysis (for .docx, .xlsm, .pptm files)
    if file_path.endswith((".docx", ".xlsm", ".pptm")):
        macro_analysis_result = analyze_office_file(file_path)
        if macro_analysis_result["malicious"]:
            results["malicious"] = True
            results["indicators"].append(macro_analysis_result["indicators"])
            results["risk_score"] += 50  # Increase risk score for macro analysis

    # ZIP File Analysis
    if file_path.endswith(".zip"):
        zip_analysis_result = analyze_zip_file(file_path)
        if zip_analysis_result["malicious"]:
            results["malicious"] = True
            results["indicators"].append(zip_analysis_result["indicators"])
            results["risk_score"] += 30  # Increase risk score for ZIP analysis

    # Hash Check (Example: Add known malware hashes here)
    malware_hashes = ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]  # Example hash
    file_hash = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
    if file_hash in malware_hashes:
        results["malicious"] = True
        results["indicators"].append(f"Known malware hash detected: {file_hash}")
        results["risk_score"] += 100  # Maximum risk score for known malware hash
        print(f"Known malware hash detected: {file_hash}")

    # Cap risk score at 100
    results["risk_score"] = min(results["risk_score"], 100)

    # Update accuracy counters
    if results["malicious"]:
        if is_malicious:
            true_positives += 1  # Correct detection
        else:
            false_positives += 1  # Wrong detection
    else:
        if is_malicious:
            false_negatives += 1  # Missed detection
        else:
            true_negatives += 1  # Correct detection

    return results

def calculate_entropy(pe):
    """Calculates entropy of a PE file."""
    data = b"".join(section.get_data() for section in pe.sections)
    counter = Counter(data)
    
    entropy = -sum((count / len(data)) * math.log2(count / len(data)) for count in counter.values())
    return entropy

def analyze_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)
        suspicious_imports = ["LoadLibrary", "GetProcAddress", "VirtualAlloc", "CreateRemoteThread", "CreateProcess", "WinExec", "ShellExecute"]
        imported_functions = [
            imp.name.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT for imp in entry.imports if imp.name
        ]
        found_imports = [imp for imp in imported_functions if imp in suspicious_imports]
        
        if found_imports:
            return {"malicious": True, "indicators": f"Suspicious API calls: {found_imports}"}
        
        # Check for high entropy sections
        high_entropy_sections = []
        for section in pe.sections:
            entropy = calculate_entropy(section.get_data())
            if entropy > 7.5:
                high_entropy_sections.append(section.Name.decode().strip('\x00'))
        
        if high_entropy_sections:
            return {"malicious": True, "indicators": f"High entropy sections: {high_entropy_sections}"}
    
    except Exception as e:
        return {"malicious": False, "indicators": f"PE analysis failed: {str(e)}"}
    
    return {"malicious": False, "indicators": "No suspicious indicators found."}

def analyze_pdf_file(file_path):
    try:
        pdf_file = open(file_path, "rb")
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        extracted_text = ""
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            extracted_text += page.extract_text() if page.extract_text() else ""
        
        if extracted_text:
            # Check for suspicious patterns (e.g., long strings of random characters)
            if any(len(word) > 50 for word in extracted_text.split()):
                return {"malicious": True, "indicators": "Suspicious pattern detected in PDF."}
            
            # Check for embedded JavaScript
            if "/JS" in extracted_text or "/JavaScript" in extracted_text:
                return {"malicious": True, "indicators": "Embedded JavaScript detected in PDF."}
    
    except Exception as e:
        return {"malicious": False, "indicators": f"PDF analysis failed: {str(e)}"}
    
    return {"malicious": False, "indicators": "No suspicious indicators found."}

def analyze_office_file(file_path):
    try:
        vba_parser = olevba.VBA_Parser(file_path)
        if vba_parser.detect_vba_macros():
            macros = [macro[3] for macro in vba_parser.extract_macros()]
            if any("AutoOpen" in macro or "Document_Open" in macro for macro in macros):
                return {"malicious": True, "indicators": "Suspicious macros found."}
    
    except Exception as e:
        return {"malicious": False, "indicators": f"Macro analysis failed: {str(e)}"}
    
    return {"malicious": False, "indicators": "No suspicious indicators found."}

def analyze_zip_file(file_path):
    try:
        with zipfile.ZipFile(file_path, "r") as zip_ref:
            for file in zip_ref.namelist():
                if file.endswith((".exe", ".dll", ".vbs")):
                    return {"malicious": True, "indicators": f"Suspicious file in ZIP: {file}"}
    
    except Exception as e:
        return {"malicious": False, "indicators": f"ZIP analysis failed: {str(e)}"}
    
    return {"malicious": False, "indicators": "No suspicious indicators found."}

def process_files_concurrently(file_paths):
    """Processes multiple files concurrently."""
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(scan_file, file_path, is_malicious) for file_path, is_malicious in file_paths]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            print("\n==== Scan Result ====")
            print(f"File: {result['file_name']}")
            print(f"Verdict: {'Malicious' if result['malicious'] else 'Clean'}")
            print(f"Risk Score: {result['risk_score']}/100")
            if result["indicators"]:
                print("Indicators:")
                for indicator in result["indicators"]:
                    print(f"  - {indicator}")

def get_detection_accuracy():
    """Calculates detection accuracy and false positive/negative rates."""
    if total_scans == 0:
        return {"accuracy": "N/A", "false_positive_rate": "N/A", "false_negative_rate": "N/A"}

    accuracy = ((true_positives + true_negatives) / total_scans) * 100
    false_positive_rate = (false_positives / total_scans) * 100
    false_negative_rate = (false_negatives / total_scans) * 100

    return {
        "accuracy": accuracy,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate
    }

@app.route('/scan', methods=['POST'])
def scan_files():
    try:
        files = request.files.getlist('files')
        is_malicious = request.form.get('is_malicious', False) == 'true'
        results = []

        for file in files:
            file_path = os.path.join('/tmp', sanitize_filename(file.filename))
            file.save(file_path)
            result = scan_file(file_path, is_malicious)
            results.append(result)
            os.remove(file_path)

        # Print detection statistics
        stats = get_detection_accuracy()
        print("\n==== Detection Statistics ====")
        print(f"Total Scans: {total_scans}")
        print(f"Detection Accuracy: {stats['accuracy']:.2f}%")
        print(f"False Positive Rate: {stats['false_positive_rate']:.2f}%")
        print(f"False Negative Rate: {stats['false_negative_rate']:.2f}%")

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/advanced_scan', methods=['POST'])
def advanced_scan():
    try:
        files = request.files.getlist('files')
        email = request.form.get('email')
        is_malicious = request.form.get('is_malicious', False) == 'true'
        results = []

        start_time = time.time()
        for file in files:
            file_path = os.path.join('/tmp', sanitize_filename(file.filename))
            file.save(file_path)
            result = scan_file(file_path, is_malicious)
            results.append(result)
            os.remove(file_path)

        end_time = time.time()
        total_time = end_time - start_time

        # Print detection statistics
        stats = get_detection_accuracy()
        print("\n==== Detection Statistics ====")
        print(f"Total Scans: {total_scans}")
        print(f"Detection Accuracy: {stats['accuracy']:.2f}%")
        print(f"False Positive Rate: {stats['false_positive_rate']:.2f}%")
        print(f"False Negative Rate: {stats['false_negative_rate']:.2f}%")

        accuracy = get_detection_accuracy()
        report = {
            "accuracy": accuracy,
            "total_time": total_time,
            "results": results
        }

        # Generate PDF report
        pdf_report = generate_pdf_report(report, files)

        # Send PDF report to user's email
        send_email(email, pdf_report)

        return jsonify({"message": "Advanced scan completed and report sent to your email."})

    except Exception as e:
        return jsonify({"error": str(e)})

def generate_pdf_report(report, files):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=15)
    pdf.cell(200, 10, txt="Advanced Malware Detection Report", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Files Scanned: {', '.join([file.filename for file in files])}", ln=True, align='L')
    pdf.cell(200, 10, txt=f"Total Time: {report['total_time']:.2f} seconds", ln=True, align='L')
    pdf.cell(200, 10, txt=f"Detection Accuracy: {report['accuracy']['accuracy']:.2f}%", ln=True, align='L')
    pdf.cell(200, 10, txt=f"False Positive Rate: {report['accuracy']['false_positive_rate']:.2f}%", ln=True, align='L')
    pdf.cell(200, 10, txt=f"False Negative Rate: {report['accuracy']['false_negative_rate']:.2f}%", ln=True, align='L')
    pdf.ln(10)

    for result in report['results']:
        pdf.cell(200, 10, txt=f"File: {result['file_name']}", ln=True, align='L')
        pdf.cell(200, 10, txt=f"Verdict: {'Malicious' if result['malicious'] else 'Clean'}", ln=True, align='L')
        pdf.cell(200, 10, txt=f"Risk Score: {result['risk_score']}/100", ln=True, align='L')
        if result['indicators']:
            pdf.cell(200, 10, txt="Indicators:", ln=True, align='L')
            for indicator in result['indicators']:
                pdf.cell(200, 10, txt=f"  - {indicator}", ln=True, align='L')
        pdf.ln(10)

    pdf_report_path = "/tmp/report.pdf"
    pdf.output(pdf_report_path)
    return pdf_report_path

def send_email(email, pdf_report_path):
    msg = MIMEMultipart()
    msg['From'] = 'your_email@example.com'
    msg['To'] = email
    msg['Subject'] = 'Advanced Malware Detection Report'

    body = "Please find the attached malware detection report."
    msg.attach(MIMEText(body, 'plain'))

    with open(pdf_report_path, 'rb') as f:
        part = MIMEApplication(f.read(), Name=os.path.basename(pdf_report_path))
    part['Content-Disposition'] = 'attachment; filename="report.pdf"'
    msg.attach(part)

    server = smtplib.SMTP('smtp.example.com', 587)
    server.starttls()
    server.login('your_email@example.com', 'your_password')
    server.sendmail('your_email@example.com', email, msg.as_string())
    server.quit()

if __name__ == '__main__':
    app.run(debug=True)