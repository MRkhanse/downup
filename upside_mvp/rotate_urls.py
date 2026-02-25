# rotate_urls.py
import requests

response = requests.get('http://localhost:5000/admin/rotate-urls', 
                       cookies={'session': 'your-admin-session'})
print("URLs rotated!")