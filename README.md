A script to open url with http password.

Trying to keep url and http password in same domain is a hassle, most of the time
we forget the url and which http password is use. This script makes it manageable
while protecting the password with encryption and secret key.

Features:
- Add, create and delete url you access with http password.
- Auto login with selenium.
- Password and username protection encryption with secret key.
- Change secret key and update all url username and password.

Requirements:
- python 2.7
- firefox webdriver for selenium

Setup:
- install firefox webdriver
- setup you virtual environment
- pip install -r requirements.txt

Run:
- python url_password_manager.py