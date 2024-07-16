#!/usr/bin/python

import requests   # HTTPS request library
import hashlib    # Hashing library
import logging    # Logging library
import os         # Handles file paths
import tkinter as tk
from tkinter import messagebox

# Configure logging to write to a file named 'results.log'
logging.basicConfig(filename='results.log', level=logging.INFO, format='%(asctime)s - %(message)s')  # The format includes the time and the message with logging level set to Information

# Function to read API key from a file
def returncreds(file_path):
    try:
        with open(file_path, "r") as mycreds:  # Open the file containing the credentials
            lines = mycreds.readlines()  # Read all lines from the file
            return {
                "HIBP_API_KEY": lines[0].strip(),
                "ABUSEIPDB_API_KEY": lines[1].strip(),  # Second line for AbuseIPDB API key
                "HUNTER_API_KEY": lines[2].strip()  # Third line for Hunter API key
            }
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return None
    except Exception as e:
        print(f"Error reading the API key from {file_path}: {e}")
        return None

# Path to the file containing the API key
file_path = "/home/clifford/tlg/havei"

# Get the API key from the file
api_keys = returncreds(file_path)

# Ensure API keys are read successfully
if not api_keys:
    raise ValueError("API keys are required and were not found in the specified file.")

# Constants to store API keys
HIBP_API_KEY = api_keys["HIBP_API_KEY"]
ABUSEIPDB_API_KEY = api_keys["ABUSEIPDB_API_KEY"]
HUNTER_API_KEY = api_keys["HUNTER_API_KEY"]

# Set up the headers for the API request
HEADERS_HIBP = {
    'hibp-api-key': HIBP_API_KEY,
    'User-Agent': 'python-requests'  # User-Agent header to identify the client
}

HEADERS_ABUSEIPDB = {
    'Key': ABUSEIPDB_API_KEY,
    'Accept': 'application/json'
}

HEADERS_HUNTER = { 
    'Authorization': f'Bearer {HUNTER_API_KEY}'
}

# Function to check if an email has been breached
def check_email_breach(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"  # API endpoint for checking email breaches
    try:
        response = requests.get(url, headers=HEADERS_HIBP)  # Send GET request to the API
        if response.status_code == 200:  # If the request was successful
            breaches = response.json()  # Parse the JSON response
            logging.info(f"{email} has been found in the following breaches: {[breach['Name'] for breach in breaches]}")
            return breaches  # Return the list of breaches
        elif response.status_code == 404:  # If the email was not found in any breaches
            logging.info(f"{email} has not been found in any breaches.")
            return None
        elif response.status_code == 401:  # If the API key is invalid
            logging.error("Unauthorized: Check your API key.")
            return None
        elif response.status_code == 429:  # If the rate limit has been exceeded
            logging.error("Rate limit exceeded. Please try again later.")
            return None
        else:  # For any other errors
            logging.error(f"Error: {response.status_code} - {response.text}")
            return None
    except requests.RequestException as e:  # Catch any network-related errors
        logging.error(f"Network error: {e}")
        return None

# Function to check if a password has been breached using k-Anonymity
def check_password_breach(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            hashes = response.text.splitlines()
            for h in hashes:
                hash_suffix, count = h.split(':')
                if hash_suffix == suffix:
                    logging.info(f"Password has been found {count} times in data breaches.")
                    return True
            logging.info("Password has not been found in any breaches.")
            return False
        else:
            logging.error(f"Error: {response.status_code} - {response.text}")
            return False
    except requests.RequestException as e:
        logging.error(f"Network error: {e}")
        return False

# Function to check if an IP address is flagged as spam
def check_ip_spam(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    try:
        response = requests.get(url, headers=HEADERS_ABUSEIPDB)
        if response.status_code == 200:
            data = response.json()
            if data['data']['abuseConfidenceScore'] > 0:
                logging.info(f"IP {ip} is flagged with abuse confidence score: {data['data']['abuseConfidenceScore']}")
                return data['data']
            else:
                logging.info(f"IP {ip} is not flagged for spam.")
                return None
        else:
            logging.error(f"Error: {response.status_code} - {response.text}")
            return None
    except requests.RequestException as e:
        logging.error(f"Network error: {e}")
        return None

# Function to check if an email is flagged as spam
def check_email_spam(email):
    url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={HUNTER_API_KEY}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data['data']['result'] == 'deliverable':
                logging.info(f"Email {email} is deliverable.")
                return data['data']
            else:
                logging.info(f"Email {email} is flagged with status: {data['data']['result']}")
                return data['data']
        else:
            logging.error(f"Error: {response.status_code} - {response.text}")
            return None
    except requests.RequestException as e:
        logging.error(f"Network error: {e}")
        return None

def banner():
    print("""
    #####################################################################
    #                     Welcome to Security Checker                   #
    #                      by Clifford Nyamongo                         #
    #                                                                   #
    #     This tool checks for:                                         #
    #     - Email breaches                                              #
    #     - Password breaches                                           #
    #     - IP spam                                                     #
    #     - Email spam                                                  #
    #                                                                   #
    #     Using APIs from:                                              #
    #     - Have I Been Pwned                                           #
    #     - AbuseIPDB                                                   #
    #     - Hunter.io                                                   #
    #####################################################################
    """)

# GUI application class
class SecurityCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Security Checker")

        self.label = tk.Label(self, text="Select an option and enter the required information:")
        self.label.pack(pady=10)

        self.email_breach_button = tk.Button(self, text="Check Email Breach", command=self.check_email_breach)
        self.email_breach_button.pack(pady=5)

        self.password_breach_button = tk.Button(self, text="Check Password Breach", command=self.check_password_breach)
        self.password_breach_button.pack(pady=5)

        self.ip_spam_button = tk.Button(self, text="Check IP Spam", command=self.check_ip_spam)
        self.ip_spam_button.pack(pady=5)

        self.email_spam_button = tk.Button(self, text="Check Email Spam", command=self.check_email_spam)
        self.email_spam_button.pack(pady=5)

        self.entry_label = tk.Label(self, text="Enter the required information:")
        self.entry_label.pack(pady=10)

        self.entry = tk.Entry(self)
        self.entry.pack(pady=5)

    def check_email_breach(self):
        email = self.entry.get().strip()
        if email:
            breaches = check_email_breach(email)
            if breaches:
                result_text = f"{email} has been found in the following breaches:\n" + "\n".join([f" - {breach['Name']}" for breach in breaches])
            else:
                result_text = f"{email} has not been found in any breaches."
            messagebox.showinfo("Email Breach Check", result_text)
        else:
            messagebox.showwarning("Input Error", "Please enter an email address.")

    def check_password_breach(self):
        password = self.entry.get().strip()
        if password:
            if check_password_breach(password):
                result_text = "Password has been found in data breaches."
            else:
                result_text = "Password has not been found in any breaches."
            messagebox.showinfo("Password Breach Check", result_text)
        else:
            messagebox.showwarning("Input Error", "Please enter a password.")

    def check_ip_spam(self):
        ip = self.entry.get().strip()
        if ip:
            result = check_ip_spam(ip)
            if result:
                result_text = f"IP {ip} is flagged with abuse confidence score: {result['abuseConfidenceScore']}"
            else:
                result_text = f"IP {ip} is not flagged for spam."
            messagebox.showinfo("IP Spam Check", result_text)
        else:
            messagebox.showwarning("Input Error", "Please enter an IP address.")

    def check_email_spam(self):
        email = self.entry.get().strip()
        if email:
            result = check_email_spam(email)
            if result:
                result_text = f"Email {email} is flagged with status: {result['result']}"
            else:
                result_text = f"Email {email} is deliverable."
            messagebox.showinfo("Email Spam Check", result_text)
        else:
            messagebox.showwarning("Input Error", "Please enter an email address.")

# Main function to run the application
def main():
    app = SecurityCheckerApp()
    app.mainloop()

if __name__ == "__main__":
    main()
