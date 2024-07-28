# URL-analyzer-Python-GUI
URL analyzer 
# URLAnalyzerApp

URLAnalyzerApp is a comprehensive tool for analyzing various aspects of a given URL. It checks the URL's format, availability, potential phishing risks, resources, SSL certificate, DNS records, WHOIS information, performance, and redirects.

## Features

- **URL Validation**: Checks if the URL format is valid.
- **URL Availability**: Verifies if the URL is reachable and returns the HTTP status code.
- **Phishing Detection**: Analyzes the URL for common phishing indicators.
- **Resource Analysis**: Counts the number of images, links, scripts, and iframes on the page.
- **SSL Information**: Retrieves and displays SSL certificate details.
- **DNS Information**: Fetches DNS records for the URL.
- **WHOIS Information**: Retrieves WHOIS data for the domain.
- **Performance Analysis**: Measures the page load time.
- **Redirect Analysis**: Checks for and displays any redirect chains.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/URLAnalyzerApp.git
    cd URLAnalyzerApp
    ```

2. Create and activate a virtual environment (optional but recommended):
    ```bash
    python3 -m venv venv
    source venv/bin/activate   # On Windows use `venv\Scripts\activate`
    ```

3. Install the required libraries:
    ```bash
    pip install -r requirements.txt
    ```

4. Download the [ChromeDriver](https://sites.google.com/a/chromium.org/chromedriver/downloads) and ensure it's compatible with your version of Chrome. Place it in an accessible location on your system and update the path in the `urlanalyzer.py` file:
    ```python
    service = ChromeService(executable_path="/path/to/chromedriver")
    ```

## Usage

Run the application using the following command:
```bash
python urlanalyzer.py



pip install selenium requests python-whois dnspython beautifulsoup4 customtkinter
