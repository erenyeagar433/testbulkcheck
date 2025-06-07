from flask import Flask, request, jsonify, render_template_string, send_from_directory
from flask_cors import CORS
import asyncio
import aiohttp
import ipaddress
import json
import time

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# HTML template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Reputation Lookup Tool</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
        }

        .header h1 {
            color: #333;
            font-size: 2.5rem;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header p {
            color: #666;
            font-size: 1.1rem;
        }

        .input-section {
            background: #f8f9ff;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            border: 2px dashed #667eea;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }

        input[type="text"], textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 14px;
            transition: all 0.3s ease;
        }

        input[type="text"]:focus, textarea:focus {
            border-color: #667eea;
            outline: none;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        textarea {
            resize: vertical;
            min-height: 120px;
            font-family: monospace;
        }

        .api-inputs {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        .btn {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 50px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }

        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .results-section {
            display: none;
            margin-top: 30px;
        }

        .export-buttons {
            margin-bottom: 20px;
            text-align: center;
        }

        .export-buttons .btn {
            margin: 0 10px;
            background: linear-gradient(45deg, #28a745, #20c997);
        }

        .results-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }

        .results-table th {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }

        .results-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }

        .results-table tr:hover {
            background: #f8f9ff;
        }

        .risk-high {
            background: linear-gradient(45deg, #dc3545, #e74c3c) !important;
            color: white;
        }

        .risk-medium {
            background: linear-gradient(45deg, #ffc107, #f39c12) !important;
            color: black;
        }

        .risk-low {
            background: linear-gradient(45deg, #28a745, #27ae60) !important;
            color: white;
        }

        .risk-clean {
            background: linear-gradient(45deg, #28a745, #27ae60) !important;
            color: white;
        }

        .risk-unknown {
            background: #6c757d !important;
            color: white;
        }

        .error-message {
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border: 1px solid #f5c6cb;
        }

        .success-message {
            background: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border: 1px solid #c3e6cb;
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: #f0f0f0;
            border-radius: 4px;
            overflow: hidden;
            margin: 10px 0;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(45deg, #667eea, #764ba2);
            width: 0%;
            transition: width 0.3s ease;
        }

        @media (max-width: 768px) {
            .api-inputs {
                grid-template-columns: 1fr;
            }
            
            .results-table {
                font-size: 12px;
            }
            
            .results-table th,
            .results-table td {
                padding: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 IP Reputation Lookup</h1>
            <p>Analyze IP addresses using VirusTotal and AbuseIPDB APIs</p>
        </div>

        <div class="input-section">
            <div class="form-group">
                <label for="ipList">IP Addresses (one per line)</label>
                <textarea id="ipList" placeholder="192.168.1.1\n10.0.0.1\n8.8.8.8">8.8.8.8
1.1.1.1
208.67.222.222
91.196.152.50</textarea>
            </div>

            <div class="api-inputs">
                <div class="form-group">
                    <label for="vtApi">VirusTotal API Key</label>
                    <input type="text" id="vtApi" placeholder="Enter your VT API key">
                </div>
                <div class="form-group">
                    <label for="aipdbApi">AbuseIPDB API Key</label>
                    <input type="text" id="aipdbApi" placeholder="Enter your AbuseIPDB API key">
                </div>
            </div>

            <div style="text-align: center; margin-top: 20px;">
                <button class="btn" onclick="analyzeIPs()">🔍 Analyze IPs</button>
            </div>
        </div>

        <div class="loading">
            <div class="spinner"></div>
            <p>Analyzing IP addresses...</p>
            <div class="progress-bar">
                <div class="progress-fill" id="progressFill"></div>
            </div>
            <p id="progressText">Preparing analysis...</p>
        </div>

        <div class="results-section" id="resultsSection">
            <div class="export-buttons">
                <button class="btn" onclick="exportCSV()">📄 Export as CSV</button>
                <button class="btn" onclick="exportExcel()">📊 Export as Excel</button>
            </div>
            <table class="results-table" id="resultsTable">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>VT Malicious</th>
                        <th>AbuseIPDB Score</th>
                        <th>ISP</th>
                        <th>Country</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody id="resultsBody">
                </tbody>
            </table>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
    <script>
        let resultsData = [];

        // Simple country code to full name mapping
        const countryCodes = {
            "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AS": "American Samoa", "AD": "Andorra",
            "AO": "Angola", "AI": "Anguilla", "AQ": "Antarctica", "AG": "Antigua and Barbuda", "AR": "Argentina",
            "AM": "Armenia", "AW": "Aruba", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan",
            "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh", "BB": "Barbados", "BY": "Belarus",
            "BE": "Belgium", "BZ": "Belize", "BJ": "Benin", "BM": "Bermuda", "BT": "Bhutan",
            "BO": "Bolivia", "BA": "Bosnia and Herzegovina", "BW": "Botswana", "BR": "Brazil",
            "IO": "British Indian Ocean Territory", "BN": "Brunei Darussalam", "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi",
            "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada", "CV": "Cape Verde", "KY": "Cayman Islands",
            "CF": "Central African Republic", "TD": "Chad", "CL": "Chile", "CN": "China", "CX": "Christmas Island",
            "CC": "Cocos (Keeling) Islands", "CO": "Colombia", "KM": "Comoros", "CG": "Congo", "CD": "Congo, The Democratic Republic of the",
            "CK": "Cook Islands", "CR": "Costa Rica", "CI": "Cote D'Ivoire", "HR": "Croatia", "CU": "Cuba",
            "CY": "Cyprus", "CZ": "Czech Republic", "DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica",
            "DO": "Dominican Republic", "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea",
            "ER": "Eritrea", "EE": "Estonia", "ET": "Ethiopia", "FK": "Falkland Islands (Malvinas)", "FO": "Faroe Islands",
            "FJ": "Fiji", "FI": "Finland", "FR": "France", "GF": "French Guiana", "PF": "French Polynesia",
            "TF": "French Southern Territories", "GA": "Gabon", "GM": "Gambia", "GE": "Georgia", "DE": "Germany",
            "GH": "Ghana", "GI": "Gibraltar", "GR": "Greece", "GL": "Greenland", "GD": "Grenada",
            "GP": "Guadeloupe", "GU": "Guam", "GT": "Guatemala", "GN": "Guinea", "GW": "Guinea-Bissau",
            "GY": "Guyana", "HT": "Haiti", "HM": "Heard Island and Mcdonald Islands", "VA": "Holy See (Vatican City State)", "HN": "Honduras",
            "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland", "IN": "India", "ID": "Indonesia",
            "IR": "Iran, Islamic Republic Of", "IQ": "Iraq", "IE": "Ireland", "IL": "Israel", "IT": "Italy",
            "JM": "Jamaica", "JP": "Japan", "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya",
            "KI": "Kiribati", "KP": "Korea, Democratic People's Republic of", "KR": "Korea, Republic of", "KW": "Kuwait", "KG": "Kyrgyzstan",
            "LA": "Lao People's Democratic Republic", "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia",
            "LY": "Libyan Arab Jamahiriya", "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg", "MO": "Macao",
            "MK": "Macedonia, The Former Yugoslav Republic of", "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia", "MV": "Maldives",
            "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands", "MQ": "Martinique", "MR": "Mauritania",
            "MU": "Mauritius", "YT": "Mayotte", "MX": "Mexico", "FM": "Micronesia, Federated States of", "MD": "Moldova, Republic of",
            "MC": "Monaco", "MN": "Mongolia", "MS": "Montserrat", "MA": "Morocco", "MZ": "Mozambique",
            "MM": "Myanmar", "NA": "Namibia", "NR": "Nauru", "NP": "Nepal", "NL": "Netherlands",
            "AN": "Netherlands Antilles", "NC": "New Caledonia", "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger",
            "NG": "Nigeria", "NU": "Niue", "NF": "Norfolk Island", "MP": "Northern Mariana Islands", "NO": "Norway",
            "OM": "Oman", "PK": "Pakistan", "PW": "Palau", "PS": "Palestinian Territory, Occupied", "PA": "Panama",
            "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru", "PH": "Philippines", "PN": "Pitcairn",
            "PL": "Poland", "PT": "Portugal", "PR": "Puerto Rico", "QA": "Qatar", "RE": "Reunion",
            "RO": "Romania", "RU": "Russian Federation", "RW": "Rwanda", "SH": "Saint Helena", "KN": "Saint Kitts and Nevis",
            "LC": "Saint Lucia", "PM": "Saint Pierre and Miquelon", "VC": "Saint Vincent and the Grenadines", "WS": "Samoa", "SM": "San Marino",
            "ST": "Sao Tome and Principe", "SA": "Saudi Arabia", "SN": "Senegal", "SC": "Seychelles", "SL": "Sierra Leone",
            "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia", "SB": "Solomon Islands", "SO": "Somalia",
            "ZA": "South Africa", "GS": "South Georgia and the South Sandwich Islands", "ES": "Spain", "LK": "Sri Lanka", "SD": "Sudan",
            "SR": "Suriname", "SJ": "Svalbard and Jan Mayen", "SZ": "Swaziland", "SE": "Sweden", "CH": "Switzerland",
            "SY": "Syrian Arab Republic", "TW": "Taiwan, Province of China", "TJ": "Tajikistan", "TZ": "Tanzania, United Republic of", "TH": "Thailand",
            "TL": "Timor-Leste", "TG": "Togo", "TK": "Tokelau", "TO": "Tonga", "TT": "Trinidad and Tobago",
            "TN": "Tunisia", "TR": "Turkey", "TM": "Turkmenistan", "TC": "Turks and Caicos Islands", "TV": "Tuvalu",
            "UG": "Uganda", "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States",
            "UM": "United States Minor Outlying Islands", "UY": "Uruguay", "UZ": "Uzbekistan", "VU": "Vanuatu", "VE": "Venezuela",
            "VN": "Viet Nam", "VG": "Virgin Islands, British", "VI": "Virgin Islands, U.S.", "WF": "Wallis and Futuna", "EH": "Western Sahara",
            "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe", "XK": "Kosovo" # Kosovo is often included, though not universally recognized ISO 3166
        };

        function showMessage(message, type = 'error') {
            const existingMsg = document.querySelector('.error-message, .success-message');
            if (existingMsg) existingMsg.remove();

            const msgDiv = document.createElement('div');
            msgDiv.className = type === 'error' ? 'error-message' : 'success-message';
            msgDiv.textContent = message;
            
            const inputSection = document.querySelector('.input-section');
            inputSection.appendChild(msgDiv);
            
            setTimeout(() => msgDiv.remove(), 5000);
        }

        function getRiskText(level) {
            const texts = {
                'high': 'High Risk',
                'medium': 'Medium Risk', 
                'low': 'Low Risk',
                'clean': 'Clean',
                'unknown': 'Unknown'
            };
            return texts[level] || 'Unknown';
        }

        function getFullCountryName(countryCode) {
            return countryCodes[countryCode] || countryCode || 'Unknown';
        }

        async function analyzeIPs() {
            console.log("Analyze IPs button clicked!");
            const ipListText = document.getElementById('ipList').value.trim();
            const vtApi = document.getElementById('vtApi').value.trim();
            const aipdbApi = document.getElementById('aipdbApi').value.trim();

            console.log("IPs raw text:", ipListText);
            console.log("VT API Key (first 5 chars):", vtApi.substring(0, 5));
            console.log("AIPDB API Key (first 5 chars):", aipdbApi.substring(0, 5));

            if (!ipListText) {
                showMessage('Please enter IP addresses to analyze');
                console.error("Error: No IP addresses provided.");
                return;
            }

            if (!vtApi || !aipdbApi) {
                showMessage('Please enter both API keys');
                console.error("Error: Both API keys are required.");
                return;
            }

            // Corrected: Uses '\n' for splitting text area content
            const ips = ipListText.split('\n') 
                .map(ip => ip.trim())
                .filter(ip => ip.length > 0);

            console.log("Parsed IPs:", ips);

            document.querySelector('.loading').style.display = 'block';
            document.querySelector('.results-section').style.display = 'none';
            document.querySelector('#progressText').textContent = 'Sending request to server...';

            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        ips: ips,
                        vt_api: vtApi,
                        aipdb_api: aipdbApi
                    })
                });

                if (!response.ok) {
                    const errorBody = await response.text();
                    throw new Error(`Server error: ${response.status} - ${errorBody}`);
                }

                const data = await response.json();
                console.log("Server response:", data);
                if (data.error) {
                    throw new Error(data.error);
                }

                resultsData = data.results;
                displayResults();
                
            } catch (error) {
                console.error('Error during analysis:', error);
                showMessage(`Error: ${error.message}`);
            }

            document.querySelector('.loading').style.display = 'none';
        }

        function displayResults() {
            const tbody = document.getElementById('resultsBody');
            tbody.innerHTML = '';

            resultsData.forEach(result => {
                const row = document.createElement('tr');
                row.className = `risk-${result.riskLevel}`;
                
                row.innerHTML = `
                    <td>${result.ip}</td>
                    <td>${result.vtMalicious === -1 ? 'Error' : result.vtMalicious}</td>
                    <td>${result.abuseScore === -1 ? 'Error' : result.abuseScore}%</td>
                    <td>${result.isp}</td>
                    <td>${getFullCountryName(result.country)}</td>
                    <td>${getRiskText(result.riskLevel)}</td>
                `;
                
                tbody.appendChild(row);
            });

            document.querySelector('.results-section').style.display = 'block';
            showMessage(`Analysis completed! Found ${resultsData.length} results.`, 'success');
        }

        function exportCSV() {
            if (resultsData.length === 0) {
                showMessage('No data to export');
                return;
            }

            const headers = ['IP Address', 'VT Malicious', 'AbuseIPDB Score', 'ISP', 'Country', 'Risk Level'];
            const csvContent = [
                headers.join(','),
                ...resultsData.map(row => [
                    row.ip,
                    row.vtMalicious,
                    row.abuseScore,
                    `"${row.isp}"`,
                    `"${getFullCountryName(row.country)}"`,
                    getRiskText(row.riskLevel)
                ].join(','))
            ].join('\n');

            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ip_reputation_analysis_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            window.URL.revokeObjectURL(url);
        }

        function exportExcel() {
            if (resultsData.length === 0) {
                showMessage('No data to export');
                return;
            }

            const worksheet = XLSX.utils.json_to_sheet(resultsData.map(row => ({
                'IP Address': row.ip,
                'VT Malicious': row.vtMalicious,
                'AbuseIPDB Score': row.abuseScore,
                'ISP': row.isp,
                'Country': getFullCountryName(row.country),
                'Risk Level': getRiskText(row.riskLevel)
            })));

            const workbook = XLSX.utils.book_new();
            XLSX.utils.book_append_sheet(workbook, worksheet, 'IP Analysis');
            XLSX.writeFile(workbook, `ip_reputation_analysis_${new Date().toISOString().split('T')[0]}.xlsx`);
        }
    </script>
</body>
</html>
'''

# Simple country code to full name mapping
COUNTRY_CODE_TO_NAME = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AS": "American Samoa", "AD": "Andorra",
    "AO": "Angola", "AI": "Anguilla", "AQ": "Antarctica", "AG": "Antigua and Barbuda", "AR": "Argentina",
    "AM": "Armenia", "AW": "Aruba", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan",
    "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh", "BB": "Barbados", "BY": "Belarus",
    "BE": "Belgium", "BZ": "Belize", "BJ": "Benin", "BM": "Bermuda", "BT": "Bhutan",
    "BO": "Bolivia", "BA": "Bosnia and Herzegovina", "BW": "Botswana", "BR": "Brazil",
    "IO": "British Indian Ocean Territory", "BN": "Brunei Darussalam", "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi",
    "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada", "CV": "Cape Verde", "KY": "Cayman Islands",
    "CF": "Central African Republic", "TD": "Chad", "CL": "Chile", "CN": "China", "CX": "Christmas Island",
    "CC": "Cocos (Keeling) Islands", "CO": "Colombia", "KM": "Comoros", "CG": "Congo", "CD": "Congo, The Democratic Republic of the",
    "CK": "Cook Islands", "CR": "Costa Rica", "CI": "Cote D'Ivoire", "HR": "Croatia", "CU": "Cuba",
    "CY": "Cyprus", "CZ": "Czech Republic", "DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica",
    "DO": "Dominican Republic", "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea",
    "ER": "Eritrea", "EE": "Estonia", "ET": "Ethiopia", "FK": "Falkland Islands (Malvinas)", "FO": "Faroe Islands",
    "FJ": "Fiji", "FI": "Finland", "FR": "France", "GF": "French Guiana", "PF": "French Polynesia",
    "TF": "French Southern Territories", "GA": "Gabon", "GM": "Gambia", "GE": "Georgia", "DE": "Germany",
    "GH": "Ghana", "GI": "Gibraltar", "GR": "Greece", "GL": "Greenland", "GD": "Grenada",
    "GP": "Guadeloupe", "GU": "Guam", "GT": "Guatemala", "GN": "Guinea", "GW": "Guinea-Bissau",
    "GY": "Guyana", "HT": "Haiti", "HM": "Heard Island and Mcdonald Islands", "VA": "Holy See (Vatican City State)", "HN": "Honduras",
    "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland", "IN": "India", "ID": "Indonesia",
    "IR": "Iran, Islamic Republic Of", "IQ": "Iraq", "IE": "Ireland", "IL": "Israel", "IT": "Italy",
    "JM": "Jamaica", "JP": "Japan", "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya",
    "KI": "Kiribati", "KP": "Korea, Democratic People's Republic of", "KR": "Korea, Republic of", "KW": "Kuwait", "KG": "Kyrgyzstan",
    "LA": "Lao People's Democratic Republic", "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia",
    "LY": "Libyan Arab Jamahiriya", "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg", "MO": "Macao",
    "MK": "Macedonia, The Former Yugoslav Republic of", "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia", "MV": "Maldives",
    "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands", "MQ": "Martinique", "MR": "Mauritania",
    "MU": "Mauritius", "YT": "Mayotte", "MX": "Mexico", "FM": "Micronesia, Federated States of", "MD": "Moldova, Republic of",
    "MC": "Monaco", "MN": "Mongolia", "MS": "Montserrat", "MA": "Morocco", "MZ": "Mozambique",
    "MM": "Myanmar", "NA": "Namibia", "NR": "Nauru", "NP": "Nepal", "NL": "Netherlands",
    "AN": "Netherlands Antilles", "NC": "New Caledonia", "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger",
    "NG": "Nigeria", "NU": "Niue", "NF": "Norfolk Island", "MP": "Northern Mariana Islands", "NO": "Norway",
    "OM": "Oman", "PK": "Pakistan", "PW": "Palau", "PS": "Palestinian Territory, Occupied", "PA": "Panama",
    "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru", "PH": "Philippines", "PN": "Pitcairn",
    "PL": "Poland", "PT": "Portugal", "PR": "Puerto Rico", "QA": "Qatar", "RE": "Reunion",
    "RO": "Romania", "RU": "Russian Federation", "RW": "Rwanda", "SH": "Saint Helena", "KN": "Saint Kitts and Nevis",
    "LC": "Saint Lucia", "PM": "Saint Pierre and Miquelon", "VC": "Saint Vincent and the Grenadines", "WS": "Samoa", "SM": "San Marino",
    "ST": "Sao Tome and Principe", "SA": "Saudi Arabia", "SN": "Senegal", "SC": "Seychelles", "SL": "Sierra Leone",
    "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia", "SB": "Solomon Islands", "SO": "Somalia",
    "ZA": "South Africa", "GS": "South Georgia and the South Sandwich Islands", "ES": "Spain", "LK": "Sri Lanka", "SD": "Sudan",
    "SR": "Suriname", "SJ": "Svalbard and Jan Mayen", "SZ": "Swaziland", "SE": "Sweden", "CH": "Switzerland",
    "SY": "Syrian Arab Republic", "TW": "Taiwan, Province of China", "TJ": "Tajikistan", "TZ": "Tanzania, United Republic of", "TH": "Thailand",
    "TL": "Timor-Leste", "TG": "Togo", "TK": "Tokelau", "TO": "Tonga", "TT": "Trinidad and Tobago",
    "TN": "Tunisia", "TR": "Turkey", "TM": "Turkmenistan", "TC": "Turks and Caicos Islands", "TV": "Tuvalu",
    "UG": "Uganda", "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States",
    "UM": "United States Minor Outlying Islands", "UY": "Uruguay", "UZ": "Uzbekistan", "VU": "Vanuatu", "VE": "Venezuela",
    "VN": "Viet Nam", "VG": "Virgin Islands, British", "VI": "Virgin Islands, U.S.", "WF": "Wallis and Futuna", "EH": "Western Sahara",
    "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe", "XK": "Kosovo"
}

def get_full_country_name(country_code):
    """Maps a two-letter country code to a full country name."""
    return COUNTRY_CODE_TO_NAME.get(country_code, country_code)

async def check_virustotal(session, ip, api_key):
    """Check IP against VirusTotal API"""
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": api_key}
        
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0)
                }
            else:
                print(f"VT API Error for {ip}: {response.status}")
                return {'malicious': -1, 'suspicious': -1}
    except Exception as e:
        print(f"VT Exception for {ip}: {str(e)}")
        return {'malicious': -1, 'suspicious': -1}

async def check_abuseipdb(session, ip, api_key):
    """Check IP against AbuseIPDB API."""
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        
        async with session.get(url, headers=headers, params=params) as response:
            if response.status == 200:
                data = await response.json()
                if 'data' in data:
                    return {
                        'abuseConfidence': data['data'].get('abuseConfidenceScore', 0),
                        'isp': data['data'].get('isp', 'Unknown'),
                        'countryCode': data['data'].get('countryCode', 'Unknown')
                    }
            else:
                print(f"AIPDB API Error for {ip}: {response.status}")
                return {'abuseConfidence': -1, 'isp': 'Unknown', 'countryCode': 'Unknown'}
    except Exception as e:
        print(f"AIPDB Exception for {ip}: {str(e)}")
        return {'abuseConfidence': -1, 'isp': 'Unknown', 'countryCode': 'Unknown'}

def is_valid_ip(ip):
    """Validate IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_private_ip(ip):
    """Check if IP is private"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return True

def get_risk_level(vt_malicious, abuse_confidence_score):
    """Determine risk level based on scores"""
    if vt_malicious == -1 and abuse_confidence_score == -1:
        return 'unknown'
    if vt_malicious > 5 or abuse_confidence_score > 75:
        return 'high'
    if vt_malicious > 2 or abuse_confidence_score > 25:
        return 'medium'
    if vt_malicious > 0 or abuse_confidence_score > 0:
        return 'low'
    return 'clean'

@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/favicon.ico')
def favicon():
    """Serve favicon from a static directory.
    Note: For Codespaces, you might need to create a 'static' folder
    in your repository root and place favicon.ico inside it."""
    # This assumes a 'static' folder exists at the same level as your app.py
    return send_from_directory('static', 'favicon.ico')

@app.route('/analyze', methods=['POST'])
def analyze_ips():
    """Analyze IP addresses using both APIs"""
    try:
        data = request.get_json()
        print("Received data:", data) # Added print for debugging
        ips = data.get('ips', [])
        vt_api = data.get('vt_api', '')
        aipdb_api = data.get('aipdb_api', '')
        
        if not ips:
            return jsonify({'error': 'No IP addresses provided'}), 400
        
        if not vt_api or not aipdb_api:
            return jsonify({'error': 'Both API keys are required'}), 400
        
        valid_ips = []
        for ip in ips:
            if not is_valid_ip(ip):
                print(f"Skipping invalid IP: {ip}") # Added print for debugging
                continue
            if is_private_ip(ip):
                print(f"Skipping private IP: {ip}") # Added print for debugging
                continue
            valid_ips.append(ip)
        
        if not valid_ips:
            return jsonify({'error': 'No valid public IP addresses found'}), 400
        
        results = asyncio.run(analyze_ips_async(valid_ips, vt_api, aipdb_api))
        
        return jsonify({'results': results})
        
    except Exception as e:
        print(f"Error in analyze_ips: {str(e)}") # Added print for debugging
        return jsonify({'error': f'Server error: {str(e)}'}), 500

async def analyze_ips_async(ips, vt_api, aipdb_api):
    """Async function to analyze IPs"""
    results = []
    
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for ip in ips:
            print(f"Analyzing {ip}...") # Added print for debugging
            
            vt_result, aipdb_result = await asyncio.gather(
                check_virustotal(session, ip, vt_api),
                check_abuseipdb(session, ip, aipdb_api)
            )
            
            risk_level = get_risk_level(
                vt_result['malicious'], 
                aipdb_result['abuseConfidence']
            )
            
            results.append({
                'ip': ip,
                'vtMalicious': vt_result['malicious'],
                'vtSuspicious': vt_result.get('suspicious', 0),
                'abuseScore': aipdb_result['abuseConfidence'],
                'isp': aipdb_result['isp'],
                'country': aipdb_result['countryCode'], # Ensure this uses countryCode from AIPDB result
                'riskLevel': risk_level
            })
            
            # Small delay to avoid rate limiting
            await asyncio.sleep(0.2)
    
    # Sort by risk level
    risk_order = {'high': 4, 'medium': 3, 'low': 2, 'clean': 1, 'unknown': 0}
    results.sort(key=lambda x: risk_order.get(x['riskLevel'], 0), reverse=True)
    
    return results

if __name__ == '__main__':
    print("Starting IP Reputation Lookup Server...")
    print("Open your browser and go to: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
