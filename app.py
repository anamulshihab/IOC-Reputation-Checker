import requests
import json
import re
from flask import Flask, render_template, request

app = Flask(__name__)


def vt(ip):
    API_KEY = "ef2cd034d5460cbb4c0703e1730f4c18d689a31ca6c7e94789f6c06fa5f687df"
    IP_ADDRESS = ip

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}"
    headers = {"x-apikey": API_KEY}

    response = requests.get(url, headers=headers)
    decodedResponse = json.loads(response.text)

    ip_address = decodedResponse['data']['id']
    malicious_count = decodedResponse['data']['attributes'].get('last_analysis_stats', {}).get('malicious', 0)
    harmless = decodedResponse['data']['attributes'].get('last_analysis_stats', {}).get('harmless', 0)
    suspicious = decodedResponse['data']['attributes'].get('last_analysis_stats', {}).get('suspicious', 0)

    undetected = decodedResponse['data']['attributes'].get('last_analysis_stats', {}).get('undetected', 0)

    Total_engines = malicious_count + harmless + suspicious + undetected
    output = f"This IP {ip_address} is detected as Malicious by {malicious_count} out of {Total_engines} Engines"

    return {
        "Total_engines": Total_engines,
        "malicious_count": malicious_count,
        "output": output
    }

    #return f"This IP {ip_address} is detected as Malicious by {malicious_count} out of {Total_engines} Engines"


def abuse(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': '3d429b66d80990145e970c2f4bd91b97f344eac7ed7966f54aa2d0bd2b796a4433d53dbb22f0f8fd'
    }

    response = requests.get(url, headers=headers, params=querystring)
    decodedResponse = json.loads(response.text)

    ip_address = decodedResponse['data']['ipAddress']
    abuse_confidence_score = decodedResponse['data']['abuseConfidenceScore']
    total_reports = decodedResponse['data']['totalReports']
    last_reported_at = decodedResponse['data']['lastReportedAt']

    output = f"ip_address: {ip_address}\n"
    output += f"abuse_confidence_score: {abuse_confidence_score}\n"
    output += f"total_reports: {total_reports}\n"
    output += f"last_reported_at: {last_reported_at}\n"

    return output

def is_valid_ipv4(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        octets = ip.split('.')
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                return False
        return True
    else:
        return False


@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        ip_address = request.form['ip']
        if is_valid_ipv4(ip_address):
            vt_result = vt(ip_address)
            abuse_result = abuse(ip_address)
            return render_template('index.html', vt_result=vt_result, abuse_result=abuse_result)
        else:
            error_message = "Invalid IPv4 address"
            return render_template('index.html', error_message=error_message)
    else:
        return render_template('index.html')

