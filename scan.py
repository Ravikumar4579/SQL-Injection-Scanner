import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin

s = requests.Session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
})

def get_forms(url):
    try:
        response = s.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"Failed to retrieve forms from {url}: {e}")
        sys.exit(1)

def form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for i in form.find_all("input"):
        input_type = i.attrs.get("type", "text")
        input_name = i.attrs.get("name")
        input_value = i.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value
        })
    
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

def is_vulnerable(response):
    errors = [
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your sql syntax"
    ]
    for error in errors:
        if error.lower() in response.content.decode().lower():
            return True
    return False

def sql_inj(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)
        for payload in ["'", '"']:
            data = {}
            for input in details["inputs"]:
                if input["type"] == "hidden" or input["value"]:
                    data[input["name"]] = f"{input['value']}{payload}"
                elif input["type"] != "submit":
                    data[input['name']] = f"test{payload}"

            form_url = urljoin(url, details['action'])

            if details["method"] == "post":
                res = s.post(form_url, data=data)
            else:
                res = s.get(form_url, params=data)

            if is_vulnerable(res):
                print(f"SQL Injection vulnerability detected on {url}")
                print(f"Form details: {details}")
                break
        else:
            continue
        break
    else:
        print(f"No SQL Injection vulnerability detected on {url}")


url_to_check = input("enter url to check for vulnerability")
sql_inj(url_to_check)
