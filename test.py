<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Reputation Lookup Tool</title>
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
                <textarea id="ipList" placeholder="192.168.1.1
10.0.0.1
8.8.8.8">8.8.8.8
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
                <button class="btn" onclick="analyzeIPs()">
                    🔍 Analyze IPs
                </button>
            </div>
        </div>

        <div class="loading 윶

System: To complete the response and ensure the VirusTotal (VT) score is displayed as a string in the format "(vt extracted value)/94" in the output, I'll provide the updated HTML template with the necessary change in the `displayResults` function. The modification will be in the JavaScript code within the HTML template, specifically in the `row.innerHTML` section where the VT malicious score is displayed. I'll use the same `artifact_id` as provided ("c4a5e6f7-8b9a-4c1d-b2e3-f8a7c9d2e1a0") since this is an update to the previous artifact, and I'll include the full artifact content as required.

<xaiArtifact artifact_id="20aae75c-b7e0-4069-8074-d03ca58cb453" artifact_version_id="c360303e-5b89-4daa-82ac-c6b7973a28b7" title="index.html" contentType="text/html">
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Reputation Lookup Tool</title>
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
            font peri-size: 14px;
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
                <textarea id="ipList" placeholder="192.168.1.1
10.0.0.1
8.8.8.8">8.8.8.8
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
                <button class="btn" onclick="analyzeIPs()">
                    🔍 Analyze IPs
                </button>
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
            "BO": "Bolivia", "BA": "Bosnia and Herzegovina", "BW": "Botswana", "BV": "Bouvet Island", "BR": "Brazil",
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
            "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe"
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
            const ipListText = document.getElementById('ipList').value.trim();
            const vtApi = document.getElementById('vtApi').value.trim();
            const aipdbApi = document.getElementById('aipdbApi').value.trim();

            if (!ipListText) {
                showMessage('Please enter IP addresses to analyze');
                return;
            }

            if (!vtApi || !aipdbApi) {
                showMessage('Please enter both API keys');
                return;
            }

            const ips = ipListText.split('\n')
                .map(ip => ip.trim())
                .filter(ip => ip.length > 0);

            // Show loading
            document.querySelector('.loading').style.display = 'block';
            document.querySelector('.results-section').style.display = 'none';
            document.getElementById('progressText').textContent = 'Sending request to server...';
            
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
                    throw new Error(`Server error: ${response.status}`);
                }

                const data = await response.json();
                
                if (data.error) {
                    throw new Error(data.error);
                }

                resultsData = data.results;
                displayResults();
                
            } catch (error) {
                console.error('Error:', error);
                showMessage(`Error: ${error.message}`);
            }

            // Hide loading
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
                    <td>${result.vtMalicious === -1 ? 'Error' : `${result.vtMalicious}/94`}</td>
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
                    row.vtMalicious === -1 ? 'Error' : `${row.vtMalicious}/94`,
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
                'VT Malicious': row.vtMalicious === -1 ? 'Error' : `${row.vtMalicious}/94`,
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
