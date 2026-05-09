import requests

def get_geo(ip):
    if ip in ['127.0.0.1', 'localhost', '0.0.0.0']:
        return {"country": "Local", "city": "-", "provider": "-"}
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "country": data.get('country_name', '-'),
                "city": data.get('city', '-'),
                "provider": data.get('org', '-')
            }
    except:
        pass
    return {"country": "-", "city": "-", "provider": "-"}