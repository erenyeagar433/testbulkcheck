from flask import Flask, request, jsonify, render_template_string, send_file
from flask_cors import CORS
import asyncio
import aiohttp
import ipaddress
import json
import time
import pandas as pd
from dotenv import load_dotenv
import os
import io

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Load API keys from .env
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
AIPDB_API_KEY = os.getenv("AIPDB_API_KEY")

     # HTML template
     HTML_TEMPLATE = '''
     <!DOCTYPE html>
     <html lang="en">
     <head>
         <meta charset="UTF-8">
         <meta name="viewport" content="width=device-width, initial-scale=1.0">
         <title>IP Reputation Lookup</title>
         <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
         <link href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css" rel="stylesheet">
         <style>
             body { background-color: #f8f9fa; }
             .container { max-width: 800px; margin-top: 20px; }
             textarea { width: 100%; height: 150px; }
             #loading { display: none; text-align: center; margin: 20px 0; }
             #results-section { display: none; }
         </style>
     </head>
     <body>
         <div class="container">
             <h1 class="text-center mb-4">🌐 IP Reputation Lookup</h1>
             <p class="text-center mb-4">Analyze IP addresses using VirusTotal and AbuseIPDB APIs</p>

             <div class="card mb-4">
                 <div class="card-body">
                     <div class="mb-3">
                         <label for="ip-input" class="form-label">IP Addresses (one per line)</label>
                         <textarea id="ip-input" class="form-control" placeholder="8.8.8.8
1.1.1.1
208.67.222.222
91.196.152.50"></textarea>
                     </div>
                     <div class="mb-3">
                         <p>API keys are loaded from the server configuration.</p>
                     </div>
                     <button onclick="analyzeIPs()" class="btn btn-primary">🔍 Analyze IPs</button>
                 </div>
             </div>

             <div id="loading">
                 <div class="spinner-border text-primary" role="status"></div>
                 <p id="progress-text">Analyzing IP addresses...</p>
             </div>

             <div id="results-section">
                 <div class="mb-3">
                     <button id="export-csv" class="btn btn-primary me-2">📄 Export as CSV</button>
                     <a href="#" class="btn btn-primary">📊 Export as Excel</a>
                 </div>
                 <table id="results-table" class="table table-striped">
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
                     <tbody></tbody>
                 </table>
             </div>
         </div>

         <script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>
         <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
         <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
         <script src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>
         <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
         <script>
             function displayResults(results) {
                 const table = $('#results-table').DataTable({
                     destroy: true,
                     data: results,
                     columns: [
                         { data: 'ip' },
                         { data: 'vtMalicious' },
                         { data: 'abuseScore' },
                         { data: 'isp' },
                         { data: 'country' },
                         { data: 'riskLevel' }
                     ],
                     pageLength: 10
                 });
             }

             function analyzeIPs() {
                 const ipInput = $('#ip-input').val().trim();
                 const ips = ipInput.split('\n').map(ip => ip.trim()).filter(ip => ip);
                 $('#loading').show();
                 $('#results-section').hide();
                 $('#progress-text').text('Analyzing IP addresses...');

                 $.ajax({
                     url: '/analyze',
                     method: 'POST',
                     contentType: 'application/json',
                     data: JSON.stringify({ ips: ips }),
                     success: function(response) {
                         $('#loading').hide();
                         if (response.error) {
                             let errorMsg = 'Error: ' + response.error;
                             if (response.invalid_ips && response.invalid_ips.length) {
                                 errorMsg += '\nInvalid IPs: ' + response.invalid_ips.join(', ');
                             }
                             alert(errorMsg);
                             return;
                         }
                         displayResults(response.results);
                         if (response.invalid_ips && response.invalid_ips.length) {
                             alert('Some IPs were invalid: ' + response.invalid_ips.join(', '));
                         }
                         $('#results-section').show();
                     },
                     error: function(xhr) {
                         $('#loading').hide();
                         alert('Error analyzing IPs: ' + (xhr.responseJSON?.error || 'Unknown error'));
                     }
                 });
             }

             $('#export-csv').click(function() {
                 const results = $('#results-table').DataTable().data().toArray();
                 $.ajax({
                     url: '/export/csv',
                     method: 'POST',
                     contentType: 'application/json',
                     data: JSON.stringify({ results: results }),
                     xhrFields: {
                         responseType: 'blob'
                     },
                     success: function(data) {
                         const blob = new Blob([data], { type: 'text/csv' });
                         const url = window.URL.createObjectURL(blob);
                         const a = document.createElement('a');
                         a.href = url;
                         a.download = 'ip_analysis.csv';
                         a.click();
                         window.URL.revokeObjectURL(url);
                     },
                     error: function(xhr) {
                         alert('Error exporting CSV: ' + (xhr.responseJSON?.error || 'Unknown error'));
                     }
                 });
             });
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
         "BO": "Bolivia", "BA": "Bosnia and Herzegovina", "BW": "Botswana", "BR": "Brazil", "IO": "British Indian Ocean Territory",
         "BN": "Brunei Darussalam", "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi", "KH": "Cambodia",
         "CM": "Cameroon", "CA": "Canada", "CV": "Cape Verde", "KY": "Cayman Islands", "CF": "Central African Republic",
         "TD": "Chad", "CL": "Chile", "CN": "China", "CX": "Christmas Island", "CC": "Cocos (Keeling) Islands",
         "CO": "Colombia", "KM": "Comoros", "CG": "Congo", "CD": "Congo, The Democratic Republic of the", "CK": "Cook Islands",
         "CR": "Costa Rica", "CI": "Cote D'Ivoire", "HR": "Croatia", "CU": "Cuba", "CY": "Cyprus",
         "CZ": "Czech Republic", "DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica", "DO": "Dominican Republic",
         "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea", "ER": "Eritrea",
         "EE": "Estonia", "ET": "Ethiopia", "FK": "Falkland Islands (Malvinas)", "FO": "Faroe Islands", "FJ": "Fiji",
         "FI": "Finland", "FR": "France", "GF": "French Guiana", "PF": "French Polynesia", "TF": "French Southern Territories",
         "GA": "Gabon", "GM": "Gambia", "GE": "Georgia", "DE": "Germany", "GH": "Ghana",
         "GI": "Gibraltar", "GR": "Greece", "GL": "Greenland", "GD": "Grenada", "GP": "Guadeloupe",
         "GU": "Guam", "GT": "Guatemala", "GN": "Guinea", "GW": "Guinea-Bissau", "GY": "Guyana",
         "HT": "Haiti", "HM": "Heard Island and Mcdonald Islands", "VA": "Holy See (Vatican City State)", "HN": "Honduras", "HK": "Hong Kong",
         "HU": "Hungary", "IS": "Iceland", "IN": "India", "ID": "Indonesia", "IR": "Iran, Islamic Republic Of",
         "IQ": "Iraq", "IE": "Ireland", "IL": "Israel", "IT": "Italy", "JM": "Jamaica",
         "JP": "Japan", "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya", "KI": "Kiribati",
         "KP": "Korea, Democratic People's Republic of", "KR": "Korea, Republic of", "KW": "Kuwait", "KG": "Kyrgyzstan", "LA": "Lao People's Democratic Republic",
         "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia", "LY": "Libyan Arab Jamahiriya",
         "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg", "MO": "Macao", "MK": "Macedonia, The Former Yugoslav Republic of",
         "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia", "MV": "Maldives", "ML": "Mali",
         "MT": "Malta", "MH": "Marshall Islands", "MQ": "Martinique", "MR": "Mauritania", "MU": "Mauritius",
         "YT": "Mayotte", "MX": "Mexico", "FM": "Micronesia, Federated States of", "MD": "Moldova, Republic of", "MC": "Monaco",
         "MN": "Mongolia", "MS": "Montserrat", "MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar",
         "NA": "Namibia", "NR": "Nauru", "NP": "Nepal", "NL": "Netherlands", "AN": "Netherlands Antilles",
         "NC": "New Caledonia", "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria",
         "NU": "Niue", "NF": "Norfolk Island", "MP": "Northern Mariana Islands", "NO": "Norway", "OM": "Oman",
         "PK": "Pakistan", "PW": "Palau", "PS": "Palestinian Territory, Occupied", "PA": "Panama", "PG": "Papua New Guinea",
         "PY": "Paraguay", "PE": "Peru", "PH": "Philippines", "PN": "Pitcairn", "PL": "Poland",
         "PT": "Portugal", "PR": "Puerto Rico", "QA": "Qatar", "RE": "Reunion", "RO": "Romania",
         "RU": "Russian Federation", "RW": "Rwanda", "SH": "Saint Helena", "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia",
         "PM": "Saint Pierre and Miquelon", "VC": "Saint Vincent and the Grenadines", "WS": "Samoa", "SM": "San Marino", "ST": "Sao Tome and Principe",
         "SA": "Saudi Arabia", "SN": "Senegal", "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore",
         "SK": "Slovakia", "SI": "Slovenia", "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa",
         "GS": "South Georgia and the South Sandwich Islands", "ES": "Spain", "LK": "Sri Lanka", "SD": "Sudan", "SR": "Suriname",
         "SJ": "Svalbard and Jan Mayen", "SZ": "Swaziland", "SE": "Sweden", "CH": "Switzerland", "SY": "Syrian Arab Republic",
         "TW": "Taiwan, Province of China", "TJ": "Tajikistan", "TZ": "Tanzania, United Republic of", "TH": "Thailand", "TL": "Timor-Leste",
         "TG": "Togo", "TK": "Tokelau", "TO": "Tonga", "TT": "Trinidad and Tobago", "TN": "Tunisia",
         "TR": "Turkey", "TM": "Turkmenistan", "TC": "Turks and Caicos Islands", "TV": "Tuvalu", "UG": "Uganda",
         "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States", "UM": "United States Minor Outlying Islands",
         "UY": "Uruguay", "UZ": "Uzbekistan", "VU": "Vanuatu", "VE": "Venezuela", "VN": "Viet Nam",
         "VG": "Virgin Islands, British", "VI": "Virgin Islands, U.S.", "WF": "Wallis and Futuna", "EH": "Western Sahara", "YE": "Yemen",
         "ZM": "Zambia", "ZW": "Zimbabwe", "XK": "Kosovo"
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
         """Check IP against AbuseIPDB API"""
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

     @app.route('/analyze', methods=['POST'])
     def analyze_ips():
         """Analyze IP addresses using both APIs"""
         try:
             data = request.get_json()
             ips = data.get('ips', [])
             invalid_ips = []
             valid_ips = []
             
             if not ips:
                 return jsonify({'error': 'No IP addresses provided'}), 400
             
             if not VT_API_KEY or not AIPDB_API_KEY:
                 return jsonify({'error': 'API keys not configured in .env'}), 500
             
             for ip in ips:
                 if not is_valid_ip(ip):
                     invalid_ips.append(ip)
                     continue
                 if is_private_ip(ip):
                     invalid_ips.append(ip + ' (private IP)')
                     continue
                 valid_ips.append(ip)
             
             if not valid_ips:
                 return jsonify({'error': 'No valid public IP addresses found', 'invalid_ips': invalid_ips}), 400
             
             results = asyncio.run(analyze_ips_async(valid_ips, VT_API_KEY, AIPDB_API_KEY))
             
             return jsonify({'results': results, 'invalid_ips': invalid_ips})
         
         except Exception as e:
             print(f"Error in analyze_ips: {str(e)}")
             return jsonify({'error': f'Server error: {str(e)}'}), 500

     @app.route('/export/csv', methods=['POST'])
     def export_csv():
         """Export results as CSV"""
         try:
             data = request.get_json()
             results = data.get('results', [])
             if not results:
                 return jsonify({'error': 'No results to export'}), 400
             
             df = pd.DataFrame(results)
             buffer = io.StringIO()
             df.to_csv(buffer, index=False)
             buffer.seek(0)
             return send_file(
                 buffer,
                 as_attachment=True,
                 download_name='ip_analysis.csv',
                 mimetype='text/csv'
             )
         except Exception as e:
             print(f"Error in export_csv: {str(e)}")
             return jsonify({'error': f'Server error: {str(e)}'}), 500

     async def analyze_ips_async(ips, vt_api, aipdb_api):
         """Async function to analyze IPs"""
         results = []
         
         timeout = aiohttp.ClientTimeout(total=30)
         async with aiohttp.ClientSession(timeout=timeout) as session:
             for ip in ips:
                 print(f"Analyzing {ip}...")
                 
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
                     'country': get_full_country_name(aipdb_result['countryCode']),
                     'riskLevel': risk_level
                 })
                 
                 await asyncio.sleep(0.2)
         
         risk_order = {'high': 4, 'medium': 3, 'low': 2, 'clean': 1, 'unknown': 0}
         results.sort(key=lambda x: risk_order.get(x['riskLevel'], 0), reverse=True)
         
         return results

     if __name__ == '__main__':
         print("Starting IP Reputation Lookup Server...")
         print("Open your browser and go to the Codespaces forwarded port URL")
         app.run(debug=True, host='0.0.0.0', port=5000)
