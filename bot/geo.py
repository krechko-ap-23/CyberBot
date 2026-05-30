import requests

def get_geo(ip):
    if ip in ['127.0.0.1', 'localhost', '0.0.0.0']:
        return {"country": "Local", "city": "-", "provider": "-"}
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,org,status", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                return {
                    "country": data.get('country', '-'),
                    "city": data.get('city', '-'),
                    "provider": data.get('org', '-')
                }
    except:
        pass
    return {"country": "-", "city": "-", "provider": "-"}
