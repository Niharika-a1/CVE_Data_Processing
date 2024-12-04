import requests
import mysql.connector
import pandas as pd
import re
from datetime import datetime

# Utility function for validating CVE ID
def validate_cve_id(cve_id):
    pattern = r'^CVE-\d{4}-\d+$'  # CVE format: CVE-YYYY-NNNNN
    if not re.match(pattern, cve_id):
        raise ValueError("Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN.")

# Utility function for validating severity
def validate_severity(severity):
    valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    if severity.upper() not in valid_severities:
        raise ValueError(f"Invalid severity level. Choose from: {', '.join(valid_severities)}.")

# Utility function for validating date
def validate_date(date_string):
    try:
        datetime.strptime(date_string, '%Y-%m-%d')
    except ValueError:
        raise ValueError("Invalid date format. Expected format: YYYY-MM-DD.")

# Database connection
def connect_to_database():
    connection = mysql.connector.connect(host='localhost',user='root',password='19121997' ,database='cve_database')
    return connection

# Table creation
def create_table(connection):
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_entries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            cve_id VARCHAR(50),
            description TEXT,
            published_date DATETIME,
            last_modified_date DATETIME,
            cvss_base_score FLOAT,
            cvss_severity VARCHAR(20)
        )
    """)
    connection.commit()

# Fetch CVE data from NVD API
def fetch_cve_data():
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    total_to_fetch = 5  # Number of CVE entries you want to fetch

    params = {
        'resultsPerPage': total_to_fetch,
        'startIndex': 0
    }

    headers = {
        'apiKey': '9967c9e8-52d5-4de6-9fc9-33c1369f8633',          
        'User-Agent': 'niharika.ambojipet@gmail.com' 
    }

    response = requests.get(base_url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        if not vulnerabilities:
            print("No vulnerabilities found.")
            return []
        else:
            print(f"Fetched {len(vulnerabilities)} CVE entries.")
            return vulnerabilities
    else:
        print(f"Error fetching data: {response.status_code}")
        print(f"Response content: {response.text}")
        return []

def is_cve_id_fetched(connection, cve_id):
    cursor = connection.cursor(dictionary=True)
    query = "SELECT COUNT(*) as count FROM cve_entries WHERE cve_id = %s"
    cursor.execute(query, (cve_id,))
    result = cursor.fetchone()
    return result['count'] > 0

def insert_cve_entries(connection, cve_items):
    cursor = connection.cursor()
    insert_query = """
        INSERT INTO cve_entries (cve_id, description, published_date, last_modified_date, cvss_base_score, cvss_severity)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    for item in cve_items:
        cve = item.get('cve', {})
        cve_id = cve.get('id')

        # Skip if the CVE ID is already in the database
        if is_cve_id_fetched(connection, cve_id):
            print(f"Skipping duplicate CVE ID: {cve_id}")
            continue

        published_date = cve.get('published')
        last_modified_date = cve.get('lastModified')

        # Get English description
        descriptions = cve.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value')
                break

        # Get CVSS data (v3.1, v3.0, v2.0)
        cvss_base_score = None
        cvss_severity = None
        metrics = cve.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            cvss_metrics = metrics['cvssMetricV31']
            if cvss_metrics:
                cvss_data = cvss_metrics[0].get('cvssData', {})
                cvss_base_score = cvss_data.get('baseScore')
                cvss_severity = cvss_data.get('baseSeverity')
        elif 'cvssMetricV30' in metrics:
            cvss_metrics = metrics['cvssMetricV30']
            if cvss_metrics:
                cvss_data = cvss_metrics[0].get('cvssData', {})
                cvss_base_score = cvss_data.get('baseScore')
                cvss_severity = cvss_data.get('baseSeverity')
        elif 'cvssMetricV2' in metrics:
            cvss_metrics = metrics['cvssMetricV2']
            if cvss_metrics:
                cvss_data = cvss_metrics[0].get('cvssData', {})
                cvss_base_score = cvss_data.get('baseScore')
                cvss_severity = cvss_data.get('severity')
                if not cvss_severity and cvss_base_score:
                    base_score = float(cvss_base_score)
                    if 0.0 <= base_score <= 3.9:
                        cvss_severity = 'LOW'
                    elif 4.0 <= base_score <= 6.9:
                        cvss_severity = 'MEDIUM'
                    elif 7.0 <= base_score <= 10.0:
                        cvss_severity = 'HIGH'

        data_tuple = (
            cve_id,
            description,
            published_date,
            last_modified_date,
            cvss_base_score,
            cvss_severity
        )
        cursor.execute(insert_query, data_tuple)
    connection.commit()

# Search functions with validation and error handling
def search_by_cve_id(connection, cve_id):
    try:
        validate_cve_id(cve_id)
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM cve_entries WHERE cve_id = %s"
        cursor.execute(query, (cve_id,))
        result = cursor.fetchall()
        if not result:
            print(f"No results found for CVE ID: {cve_id}")
        return result
    except ValueError as ve:
        print(f"Validation Error: {ve}")
    except mysql.connector.Error as e:
        print(f"Database Error: {e}")
    return []

def search_by_severity(connection, severity):
    try:
        validate_severity(severity)
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM cve_entries WHERE cvss_severity = %s"
        cursor.execute(query, (severity.upper(),))
        result = cursor.fetchall()
        if not result:
            print(f"No results found for severity: {severity.upper()}")
        return result
    except ValueError as ve:
        print(f"Validation Error: {ve}")
    except mysql.connector.Error as e:
        print(f"Database Error: {e}")
    return []

def search_by_date_range(connection, start_date, end_date):
    try:
        validate_date(start_date)
        validate_date(end_date)
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM cve_entries WHERE published_date BETWEEN %s AND %s"
        cursor.execute(query, (start_date, end_date))
        result = cursor.fetchall()
        if not result:
            print(f"No results found between {start_date} and {end_date}")
        return result
    except ValueError as ve:
        print(f"Validation Error: {ve}")
    except mysql.connector.Error as e:
        print(f"Database Error: {e}")
    return []

def search_by_keyword(connection, keyword):
    try:
        if not keyword.strip():
            raise ValueError("Keyword cannot be empty.")
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM cve_entries WHERE description LIKE %s"
        cursor.execute(query, ('%' + keyword + '%',))
        result = cursor.fetchall()
        if not result:
            print(f"No results found containing keyword: '{keyword}'")
        return result
    except ValueError as ve:
        print(f"Validation Error: {ve}")
    except mysql.connector.Error as e:
        print(f"Database Error: {e}")
    return []

# Main function
def main():
    connection = connect_to_database()
    create_table(connection)

    print("Fetching CVE data from NVD API...")
    cve_items = fetch_cve_data()
    print(f"Fetched {len(cve_items)} CVE entries.")

    if not cve_items:
        print("No data retrieved from the API.")
        return

    print("Inserting data into the database...")
    insert_cve_entries(connection, cve_items)
    print("Data insertion complete.")

    print("\nSearch by CVE ID:")
    cve_id = input("Enter CVE ID to search: ")
    results = search_by_cve_id(connection, cve_id)
    for row in results:
        print(row)

    print("\nSearch by Severity:")
    severity = input("Enter severity level (LOW, MEDIUM, HIGH, CRITICAL): ")
    results = search_by_severity(connection, severity)
    print(f"Found {len(results)} entries with severity {severity.upper()}.")
    for row in results:
        print(row)

    print("\nSearch by Date Range:")
    start_date = input("Enter start date (YYYY-MM-DD): ")
    end_date = input("Enter end date (YYYY-MM-DD): ")
    results = search_by_date_range(connection, start_date, end_date)
    print(f"Found {len(results)} entries between {start_date} and {end_date}.")
    for row in results:
        print(row)

    print("\nSearch by Description Keyword:")
    keyword = input("Enter keyword to search in descriptions: ")
    results = search_by_keyword(connection, keyword)
    print(f"Found {len(results)} entries containing keyword '{keyword}'.")
    for row in results:
        print(row)

    connection.close()

if __name__ == '__main__':
    main()
