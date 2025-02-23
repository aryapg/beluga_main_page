import React, { useState, useEffect } from 'react';
import axios from 'axios';

function App() {
  const [darkMode, setDarkMode] = useState(() => {
    return localStorage.getItem("theme") === "dark";
  });

  const [selectedFiles, setSelectedFiles] = useState([]);
  const [typingText, setTypingText] = useState("");
  const fullText = " Detect, Analyze and Stay Secure....";
  const [index, setIndex] = useState(0);
  const [scanResults, setScanResults] = useState([]);
  const [isLoggedIn, setIsLoggedIn] = useState(() => {
    return localStorage.getItem("isLoggedIn") === "true"; // Persist login state
  });
  const [showSecurityTips, setShowSecurityTips] = useState(false);
  const [showScanHistory, setShowScanHistory] = useState(false);
  const [scanHistory, setScanHistory] = useState(() => {
    return JSON.parse(localStorage.getItem("scanHistory")) || [];
  });

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
    localStorage.setItem("theme", darkMode ? "light" : "dark");
  };

  useEffect(() => {
    if (darkMode) {
      document.body.classList.add("dark-mode");
    } else {
      document.body.classList.remove("dark-mode");
    }
  }, [darkMode]);

  useEffect(() => {
    const interval = setInterval(() => {
      if (index < fullText.length) {
        setTypingText((prev) => prev + fullText[index]);
        setIndex((prev) => prev + 1);
      } else {
        setTimeout(() => {
          setTypingText("");
          setIndex(0);
        }, 1000);
      }
    }, 130);
    return () => clearInterval(interval);
  }, [index]);

  const handleFileChange = (event) => {
    const newFiles = Array.from(event.target.files);
    setSelectedFiles((prevFiles) => [...prevFiles, ...newFiles]);
  };

  const removeFile = (index) => {
    setSelectedFiles((prevFiles) => prevFiles.filter((_, idx) => idx !== index));
  };

  const scrollToSection = (id) => {
    const section = document.getElementById(id);
    if (section) {
      section.scrollIntoView({ behavior: "smooth" });
    } else {
      console.warn(`Section with ID ${id} not found.`);
    }
  };

  const handleEasyScan = async () => {
    const formData = new FormData();
    selectedFiles.forEach(file => formData.append('files', file));

    try {
      const response = await axios.post('http://localhost:5000/scan', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });
      setScanResults(response.data);
      updateScanHistory(response.data); // Update scan history for all users
    } catch (error) {
      console.error('Error:', error);
      setScanResults([{ error: "Error occurred during scan" }]);
    }
  };

  const handleLogin = () => {
    // Redirect to the external login page
    window.location.href = "https://beluga-login.vercel.app/";
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    localStorage.setItem("isLoggedIn", "false"); // Clear login state
  };

  const updateScanHistory = (newResults) => {
    const resultsArray = Array.isArray(newResults) ? newResults : [newResults];
    const updatedHistory = resultsArray.concat(scanHistory);
    const trimmedHistory = updatedHistory.length > 5 ? updatedHistory.slice(0, 5) : updatedHistory;
    setScanHistory(trimmedHistory);
    localStorage.setItem("scanHistory", JSON.stringify(trimmedHistory));
  };

  useEffect(() => {
    // Check for login token in URL
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    if (token) {
      setIsLoggedIn(true);
      localStorage.setItem("isLoggedIn", "true");
      // Optionally, you can remove the token from the URL
      window.history.replaceState({}, document.title, "/");
    }
  }, []);

  return (
    <div 
      className={`min-h-screen flex flex-col items-center font-['Inter'] transition-colors duration-500 ease-in-out 
                  ${darkMode ? "bg-[#121212] text-white" : "bg-[#f8f9fc] text-black"}`}
    >
      
      {/* Navbar */}
      <header
        className={`fixed top-0 w-full p-4 flex justify-between items-center shadow-md transition-colors duration-500 ease-in-out 
                    ${darkMode ? "bg-[#1f1f1f] dark-mode-glow" : "bg-white"}`}
      >
        <h1 className="text-3xl font-bold text-[#1a73e8] flex items-center">
          Beluga <span className="ml-2">🐳</span>
        </h1>
        <nav className="space-x-6 font-semibold">
          <button 
            onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })} 
            className="px-3 py-2 text-lg transition duration-300 hover:text-[#1a73e8]"
          >
            Home
          </button>
          <button 
            onClick={() => scrollToSection("about")} 
            className="px-3 py-2 text-lg transition duration-300 hover:text-[#1a73e8]"
          >
            About
          </button>
          <button 
            onClick={() => scrollToSection("contact")} 
            className="px-3 py-2 text-lg transition duration-300 hover:text-[#1a73e8]"
          >
            Contact
          </button>
          {isLoggedIn ? (
            <button 
              onClick={handleLogout} 
              className="px-3 py-2 text-lg transition duration-300 hover:text-[#1a73e8]"
            >
              Sign Out
            </button>
          ) : (
            <button 
              onClick={handleLogin} 
              className="px-3 py-2 text-lg transition duration-300 hover:text-[#1a73e8]"
            >
              Login/Sign-Up
            </button>
          )}
        </nav>
        <button
          onClick={toggleDarkMode}
          className="ml-4 text-2xl transition duration-300 ease-in-out hover:scale-110"
        >
          {darkMode ? "☀" : "☾"}
        </button>
      </header>
      
      <div className="h-screen w-full flex items-center justify-center text-center overflow-hidden">
        <h1 className="text-6xl font-bold mt-[-50px] animate-loop">{typingText}</h1>
      </div>
      <div className="absolute bottom-10 flex flex-col items-center animate-bounce">
        <p className="text-lg mt-2 text-gray-500">Scroll Down</p>
        <button
          onClick={() => scrollToSection("main-content")}
          className="text-4xl hover:text-[#1a73e8] transition duration-300"
        >
          ↓
        </button>
      </div>
      <div className="mt-16 text-center" id="main-content">
        <h2 className="text-3xl font-bold text-[#1a73e8] mb-8">Malware Scanner!</h2>
        <p className={`italic mb-12 transition-colors duration-500 ease-in-out 
                      ${darkMode ? "text-white" : "text-black"}`}>
          Upload your files and check for malware
        </p>
        <div
          className={`p-6 mt-6 rounded-lg shadow-md w-96 transition-colors duration-500 ease-in-out hover-scale 
                      ${darkMode ? "bg-[#1f1f1f] dark-mode-glow" : "bg-white"}`}
        >
          <input
            type="file"
            multiple
            onChange={handleFileChange}
            id="file-upload"
            className="hidden"
          />
          <label
            htmlFor="file-upload"
            className={`flex items-center justify-center cursor-pointer border rounded-md w-full p-3 text-xl 
                        transition duration-300 hover:text-[#1a73e8] hover:scale-105 
                        ${darkMode ? "border-gray-400 text-gray-300" : "border-blue-900 text-blue-900"}`}
          >
            📂 Upload your file
          </label>
          {selectedFiles.length > 0 && (
            <div className="mt-4 text-left">
              <p className="font-semibold">Selected Files ({selectedFiles.length}):</p>
              <ul className="mt-2 text-sm">
                {selectedFiles.map((file, index) => (
                  <li key={index} className="flex items-center justify-between text-gray-500 dark:text-gray-300">
                    📄 {file.name}
                    <button
                      onClick={() => removeFile(index)}
                      className="ml-2 text-red-500 hover:text-red-700"
                    >
                      ❌
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="flex justify-center mt-6 space-x-6">
            <button
              onClick={handleEasyScan}
              className="futuristic-gradient px-6 py-2 rounded-md shadow-md"
            >
              Easy
            </button>
          </div>
        </div>
      </div>

      {/* Display Scan Results */}
      {scanResults.length > 0 && (
        <div
          className={`mt-8 w-full max-w-4xl p-6 rounded-lg shadow-md transition-colors duration-500 ease-in-out ${
            darkMode ? "bg-[#1f1f1f] dark-mode-glow" : "bg-white"
          }`}
        >
          <h3 className="text-2xl font-bold text-[#1a73e8] mb-4">Scan Results</h3>
          {scanResults.map((result, index) => (
            <div key={index} className="mb-6">
              <h4 className="text-xl font-semibold">{result.file_name}</h4>
              <p className={`text-lg ${result.malicious ? "text-red-600" : "text-green-600"}`}>
                Verdict: {result.malicious ? "Malicious" : "Clean"}
              </p>
              <p>Risk Score: {result.risk_score}/100</p>
              {result.indicators && result.indicators.length > 0 && (
                <div className="mt-2">
                  <p className="font-semibold">Indicators:</p>
                  <ul className="list-disc list-inside">
                    {result.indicators.map((indicator, idx) => (
                      <li key={idx} className="text-sm">{indicator}</li>
                    ))}
                  </ul>
                </div>
              )}
              {result.error && (
                <p className="text-red-600">{result.error}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Security Tips and Scan History Sections */}
      <div className="flex justify-center mt-20 space-x-12 mb-24">
        <div
          className={`p-8 rounded-lg shadow-md w-96 text-center transition-colors duration-500 ease-in-out hover-scale 
                      ${darkMode ? "bg-[#1f1f1f] dark-mode-glow" : "bg-white"}`}
        >
          <h3 className="text-xl font-bold text-[#1a73e8] mb-4">Security Tips🛡️</h3>
          <p className={`mb-6 transition-colors duration-500 ease-in-out ${darkMode ? "text-white" : "text-black"}`}>
            Learn how to protect your files and devices from malware.
          </p>
          <button
            onClick={() => setShowSecurityTips(!showSecurityTips)}
            className="futuristic-gradient px-4 py-2 rounded-md shadow-md"
          >
            Learn More
          </button>

          {showSecurityTips && (
            <div className={`mt-4 text-left transition-colors duration-500 ease-in-out ${darkMode ? "text-white" : "text-black"}`}>
              <p className="font-semibold">Here are some security tips:</p>
              <ul className="list-disc list-inside mt-2">
                <li>Always keep your software and operating system up to date.</li>
                <li>Use strong, unique passwords for all your accounts.</li>
                <li>Avoid clicking on suspicious links or downloading unknown attachments.</li>
                <li>Enable two-factor authentication (2FA) wherever possible.</li>
                <li>Regularly back up your important files to a secure location.</li>
              </ul>
            </div>
          )}
        </div>

        <div
          className={`p-8 rounded-lg shadow-md w-96 text-center transition-colors duration-500 ease-in-out hover-scale 
                      ${darkMode ? "bg-[#1f1f1f] dark-mode-glow" : "bg-white"}`}
        >
          <h3 className="text-xl font-bold text-[#1a73e8] mb-4">Scan History🔍</h3>
          <p className={`mb-6 transition-colors duration-500 ease-in-out ${darkMode ? "text-white" : "text-black"}`}>
            View the scan history of the previous 5 uploaded files.
          </p>
          <button
            onClick={() => setShowScanHistory(!showScanHistory)}
            className="futuristic-gradient px-4 py-2 rounded-md shadow-md"
          >
            View History
          </button>

          {showScanHistory && (
            <div className={`mt-4 text-left transition-colors duration-500 ease-in-out ${darkMode ? "text-white" : "text-black"}`}>
              <p className="font-semibold">View Latest Scans⬇️</p>
              <ul className="list-disc list-inside mt-2">
                {scanHistory.map((history, idx) => (
                  <li key={idx} className="text-sm">
                    {history.file_name} - {history.malicious ? "Malicious" : "Clean"} (Risk Score: {history.risk_score}/100)
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* About Section */}
      <div id="about" className="mt-32 text-center max-w-2xl mx-auto">
        <h3 className="text-2xl font-bold text-[#1a73e8] mb-4">About Us</h3>
        <p className="mt-2">
          <strong>At Beluga</strong>, we are committed to providing <strong>cutting-edge malware detection</strong> and <strong>analysis solutions</strong> to safeguard your digital assets. Our platform is designed to <strong>identify, analyze, and mitigate security threats</strong> with precision and efficiency.
        </p>
        <p className="mt-4">
          With a focus on <strong>advanced threat intelligence</strong>, we utilize <strong>real-time scanning, behavioral analysis</strong> to ensure comprehensive protection against evolving cyber threats. Whether you’re an individual user or an enterprise, our goal is to empower you with <strong>robust security tools</strong> that enhance your cybersecurity posture.
        </p>
        <p className="mt-4">
          <strong>Join us</strong> in creating a safer digital world, where <strong>security is proactive</strong>, threats are neutralized, and your data remains protected.
        </p>
      </div>

      {/* Contact Section */}
      <div id="contact" className="mt-32 text-center max-w-2xl mx-auto">
        <h3 className="text-2xl font-bold text-[#1a73e8] mb-4">Contact Us</h3>
        <p>Email: <a href="mailto:beluga@gmail.com" className="underline text-[#1a73e8] hover:text-[#0057b7]">beluga@gmail.com</a></p>
        <p>Phone: <a href="tel:+919988776655" className="underline text-[#1a73e8] hover:text-[#0057b7]">+91 9988776655</a></p>
      </div>

      {/* Footer */}
      <footer className="w-full bg-[#1a73e8] text-white text-center p-4 mt-32">
        © 2025 <span className="font-bold">Beluga</span> |
        <a href="#" className="underline mx-2">Instagram</a> |
        <a href="#" className="underline mx-2">Terms of Use</a> |
        <a href="#" className="underline mx-2">Privacy Policy</a>
      </footer>
    </div>
  );
}

export default App;