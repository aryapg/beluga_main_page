# Beluga Malware Detection Web Application

## Overview
Beluga is a web-based malware detection tool designed to provide fast, accurate, and user-friendly malware analysis. It performs static analysis on uploaded files to identify potential threats without executing the file. This project bridges the gap between traditional antivirus solutions and modern web technologies, offering a robust and scalable solution for everyday users and security enthusiasts alike.

## Features
- **Static Analysis:** Scans files for suspicious patterns using PE file analysis and entropy calculation.
- **User-Friendly Interface:** Simple and intuitive UI for easy file uploads.
- **Security Measures:** Input validation, file size limits, and restricted file types to prevent exploitation.
- **Additional Features:**
  - **File Hash Comparison:** Quickly identify known threats via SHA-256 hash matching.
  - **Report Export & Sharing:** Generate downloadable reports for security teams.
  - **Dark Mode & Accessibility:** Improve UI experience with a night-friendly theme.

## Tech Stack
### Frontend
- React.js (for an interactive UI)
- Tailwind CSS (for styling)
- Axios (for API calls)

### Backend
- Python (Flask/FastAPI for server-side processing)
- PEFile (for analyzing Windows executables)
- SQLite/PostgreSQL (for storing scan logs - optional)

### Security & Performance Enhancements
- **File Validation:** Restrict file types and sizes
- **Concurrency Handling:** Async processing for handling multiple requests
- **Scalability:** Deploying on AWS/GCP with load balancing

## Getting Started
### Prerequisites
- Node.js (for frontend development)
- Python (for backend development)
- Flask (Python web framework)
- PEFile (Python library for analyzing Windows executables)
- SQLite/PostgreSQL (for storing scan logs)
- Firebase API Keys (for authentication)

### Firebase API Key Setup
To enable authentication, create Firebase API keys and add them to the `.env` file.
1. Go to [Firebase Console](https://console.firebase.google.com/).
2. Create a new project and navigate to **Project Settings**.
3. Under the **General** tab, find the **Web API Key**.
4. Create a `.env` file in the project root and add:
   ```env
   REACT_APP_FIREBASE_API_KEY=your-api-key
   REACT_APP_FIREBASE_AUTH_DOMAIN=your-auth-domain
   REACT_APP_FIREBASE_PROJECT_ID=your-project-id
   REACT_APP_FIREBASE_STORAGE_BUCKET=your-storage-bucket
   REACT_APP_FIREBASE_MESSAGING_SENDER_ID=your-messaging-sender-id
   REACT_APP_FIREBASE_APP_ID=your-app-id
   ```
5. Restart the application for changes to take effect.

## Installation
### Clone the repository:
```bash
git clone https://github.com/your-repo/beluga-malware-detector.git
cd beluga-malware-detector
```

### Install frontend dependencies:
```bash
npm install
```

### Install backend dependencies:
```bash
cd ../server
pip install -r requirements.txt
```

## Running the Application
Start the backend server:
```bash
cd server
python server.py
```
Start the frontend server:
```bash
npm start
```

## Requirements.txt
Below are the necessary Python packages required to run the backend server.

```plaintext
# requirements.txt
Flask==2.2.2
flask-cors==3.0.10
pefile==2022.5.30
oletools==0.56
PyPDF2==1.26.0
zipfile==1.0
concurrent.futures==3.0.3
time==1.0
re==2.2.1
smtplib==1.0
email==5.1.1
fpdf==1.7.2
axios
```

### Explanation of Dependencies:
- **Flask:** The web framework used to create the backend server.
- **flask-cors:** Allows Cross-Origin Resource Sharing (CORS) for the Flask app.
- **pefile:** A Python library for analyzing Windows executable files.
- **oletools:** A collection of tools for analyzing OLE files (e.g., Office documents).
- **PyPDF2:** A library for reading and writing PDF files.
- **zipfile:** A module for working with ZIP files.
- **concurrent.futures:** A module for running tasks concurrently.
- **time:** A module for working with time-related functions.
- **re:** A module for working with regular expressions.
- **smtplib:** A module for sending emails.
- **email:** A module for working with email messages.
- **fpdf:** A library for generating PDF files.

### Install the dependencies:
```bash
pip install -r requirements.txt
```

## Usage
1. **Upload a file:** Navigate to the Beluga web application and upload a suspicious file.
2. **Scan the file:** Click the "Scan" button to perform static analysis on the uploaded file.
3. **View results:** The application will display the verdict ("Malicious" or "Clean") along with any detected indicators.
4. **Generate report:** Optionally, generate a downloadable report for further analysis.

## Contributing
Contributions are welcome! Please follow these guidelines:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes and push to your fork.
4. Submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contact
For any questions or feedback, please contact us at:
- **Email:** beluga@gmail.com
- **Phone:** +91 9988776655


