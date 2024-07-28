import os
import re
import ssl
import socket
import requests
import whois
import dns.resolver
import threading
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from tkinter import filedialog, messagebox
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
import customtkinter as ctk

class URLAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced URL Analyzer")
        self.root.geometry("1000x600")

        self.create_widgets()

    def create_widgets(self):
        self.url_label = ctk.CTkLabel(self.root, text="Enter URL:")
        self.url_label.pack(pady=10)

        self.url_entry = ctk.CTkEntry(self.root, width=600)
        self.url_entry.pack(pady=10)

        self.analyze_button = ctk.CTkButton(self.root, text="Analyze URL", command=self.start_analysis)
        self.analyze_button.pack(pady=10)

        self.result_text = ctk.CTkTextbox(self.root, width=800, height=400)
        self.result_text.pack(pady=10)

        self.save_button = ctk.CTkButton(self.root, text="Save Results", command=self.save_results)
        self.save_button.pack(pady=10)

        self.create_additional_tools()

    def create_additional_tools(self):
        self.ssl_button = ctk.CTkButton(self.root, text="Check SSL Info", command=self.check_ssl_info)
        self.ssl_button.pack(side="left", padx=10, pady=10)

        self.dns_button = ctk.CTkButton(self.root, text="Check DNS Info", command=self.check_dns_info)
        self.dns_button.pack(side="left", padx=10, pady=10)

        self.whois_button = ctk.CTkButton(self.root, text="Check WHOIS Info", command=self.check_whois_info)
        self.whois_button.pack(side="left", padx=10, pady=10)

        self.performance_button = ctk.CTkButton(self.root, text="Check Performance", command=self.check_performance)
        self.performance_button.pack(side="left", padx=10, pady=10)

    def start_analysis(self):
        url = self.url_entry.get()
        self.result_text.delete("1.0", ctk.END)
        self.result_text.insert(ctk.END, "Analyzing URL...\n")
        threading.Thread(target=self.analyze_url, args=(url,)).start()

    def analyze_url(self, url):
        results = []
        results.append(self.validate_url(url))
        results.append(self.check_url_availability(url))
        results.append(self.detect_phishing(url))
        results.append(self.analyze_resources(url))
        results.append(self.get_ssl_info(url))
        results.append(self.get_dns_info(url))
        results.append(self.get_whois_info(url))
        results.append(self.analyze_performance(url))
        results.append(self.analyze_redirects(url))

        self.result_text.delete("1.0", ctk.END)
        for result in results:
            self.result_text.insert(ctk.END, result)

    def validate_url(self, url):
        pattern = re.compile(
            r'^(?:http|ftp)s?://' 
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' 
            r'localhost|' 
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' 
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' 
            r'(?::\d+)?' 
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        if re.match(pattern, url):
            return "URL format is valid.\n"
        else:
            return "Invalid URL format.\n"

    def check_url_availability(self, url):
        try:
            response = requests.get(url, timeout=10)
            return f"URL is available. Status Code: {response.status_code}\n"
        except requests.RequestException as e:
            return f"URL is not available. Error: {e}\n"

    def detect_phishing(self, url):
        common_phishing_terms = ['update', 'login', 'secure', 'account', 'banking']
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()

        score = 0
        for term in common_phishing_terms:
            if term in domain or term in path:
                score += 1

        if score >= 2:
            return "High possibility of phishing URL detected.\n"
        else:
            return "URL is unlikely to be phishing.\n"

    def analyze_resources(self, url):
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')

            images = len(soup.find_all('img'))
            links = len(soup.find_all('a'))
            scripts = len(soup.find_all('script'))
            iframes = len(soup.find_all('iframe'))

            return f"Resource Analysis:\nImages: {images}\nLinks: {links}\nScripts: {scripts}\nIframes: {iframes}\n"
        except requests.RequestException as e:
            return f"Error retrieving resources: {e}\n"

    def get_ssl_info(self, url):
        try:
            hostname = urlparse(url).hostname
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.connect((hostname, 443))
                cert = s.getpeercert()
                issued_to = cert.get('subject', ((('commonName', 'N/A'),),))[0][0][1]
                issued_by = cert.get('issuer', ((('commonName', 'N/A'),),))[0][0][1]
                valid_from = cert.get('notBefore', 'N/A')
                valid_to = cert.get('notAfter', 'N/A')
                return f"Issued To: {issued_to}\nIssued By: {issued_by}\nValid From: {valid_from}\nValid To: {valid_to}\n"
        except Exception as e:
            return f"Error retrieving SSL Certificate details: {e}\n"

    def get_dns_info(self, url):
        try:
            domain = re.match(r'http[s]?://([^/]+)', url).group(1)
            result = ""
            for record_type in ['A', 'NS', 'CNAME', 'MX', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for answer in answers:
                        result += f"{record_type} Record: {answer}\n"
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
            return result
        except Exception as e:
            return f"Error retrieving DNS information: {e}\n"

    def get_whois_info(self, url):
        try:
            domain = re.match(r'http[s]?://([^/]+)', url).group(1)
            whois_info = whois.whois(domain)
            return f"Domain Name: {whois_info.domain_name}\nRegistrar: {whois_info.registrar}\nCreation Date: {whois_info.creation_date}\nExpiration Date: {whois_info.expiration_date}\n"
        except Exception as e:
            return f"Error retrieving WHOIS information: {e}\n"

    def analyze_performance(self, url):
        options = Options()
        options.headless = True
        service = ChromeService(executable_path="/path/to/chromedriver")  # Update this path

        driver = None
        try:
            driver = webdriver.Chrome(service=service, options=options)
            driver.get(url)
            performance = driver.execute_script("return window.performance.timing")
            load_time = performance['loadEventEnd'] - performance['navigationStart']
            return f"Page Load Time: {load_time} ms\n"
        except Exception as e:
            return f"Error retrieving page performance: {e}\n"
        finally:
            if driver:
                driver.quit()

    def analyze_redirects(self, url):
        try:
            session = requests.Session()
            response = session.get(url, timeout=10)
            if len(response.history) > 0:
                result = "Redirect Chain:\n"
                for resp in response.history:
                    result += f"{resp.status_code} - {resp.url}\n"
                result += f"{response.status_code} - {response.url}\n"
                return result
            else:
                return "No redirects found.\n"
        except requests.RequestException as e:
            return f"Error analyzing redirects: {e}\n"

    def save_results(self):
        result_text = self.result_text.get("1.0", ctk.END)
        if not result_text.strip():
            messagebox.showwarning("Warning", "No results to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(result_text)
            messagebox.showinfo("Success", "Results saved successfully.")

    def check_ssl_info(self):
        url = self.url_entry.get()
        self.result_text.delete("1.0", ctk.END)
        self.result_text.insert(ctk.END, "Checking SSL Info...\n")
        threading.Thread(target=lambda: self.result_text.insert(ctk.END, self.get_ssl_info(url))).start()

    def check_dns_info(self):
        url = self.url_entry.get()
        self.result_text.delete("1.0", ctk.END)
        self.result_text.insert(ctk.END, "Checking DNS Info...\n")
        threading.Thread(target=lambda: self.result_text.insert(ctk.END, self.get_dns_info(url))).start()

    def check_whois_info(self):
        url = self.url_entry.get()
        self.result_text.delete("1.0", ctk.END)
        self.result_text.insert(ctk.END, "Checking WHOIS Info...\n")
        threading.Thread(target=lambda: self.result_text.insert(ctk.END, self.get_whois_info(url))).start()

    def check_performance(self):
        url = self.url_entry.get()
        self.result_text.delete("1.0", ctk.END)
        self.result_text.insert(ctk.END, "Checking Performance...\n")
        threading.Thread(target=lambda: self.result_text.insert(ctk.END, self.analyze_performance(url))).start()

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    app = URLAnalyzerApp(root)
    root.mainloop()

