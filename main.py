import requests

# The URL you're sending the request to
url = 'http://127.0.0.1:8000/user/test_token/'

# Your JWT access token
access_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzA4NzY3ODA0LCJpYXQiOjE3MDg3Njc3ODQsImp0aSI6ImNmMmI0NzM1YzBkMzRjZDFiZmQxZGEyMDNkNTE2MGQzIiwidXNlcl9pZCI6MX0.a56XHFx0G0NEZszELF7WEv9e7payalX5BWuReJLcXyc'

# The headers with the Authorization field containing the JWT
headers = {
    'Authorization': f'Bearer {access_token}'
}

# Sending a GET request (you can change this to POST or another method if needed)
response = requests.get(url, headers=headers)

# Printing the status code and response data
print('Status Code:', response.status_code)
print('Response:', response.json())
