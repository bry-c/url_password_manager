#! ./venv/bin/python
# A script to open url with http password.
import getpass
import shelve
import base64

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from Crypto.Cipher import AES


def set_pass(label):
    # force to set raw input not visible on screen
    while True:
        value = getpass.getpass(label)

        if value:
            return value


def draw_table(data_urls):
    # draw table data url in ascii char
    print '*' * 55
    print '| Press | Label | Url'
    for counter, data_url in enumerate(data_urls, 1):
        print counter, '|', data_url['label'], '|', data_url['url']
    print '*' * 55
    print 'Other commands:'
    print 'a: add url, r: set new secret key and update url password key'
    print 'q: exit program, e: edit url, d: delete url'
    print '*' * 55


def open_to_brower(url, username, password):
    # decode username and password and open the url to webbrowser
    browser = webdriver.Firefox()
    browser.get(url)

    try:
        WebDriverWait(browser, 3).until(EC.alert_is_present(),
         'Timed out waiting for PA creation ' +
         'confirmation popup to appear.')

        alert = browser.switch_to.alert
        alert.send_keys(username + Keys.TAB + password)
        alert.accept()
    except TimeoutException:
        print("No alert")


def encrypt(value, secret_key):
    # protect username and password
    # pad some spaces value needs to be 16, 24 and 32 char long
    value = value.rjust(32)
    secret_key = secret_key.rjust(32)
    cipher = AES.new(secret_key, AES.MODE_ECB)
    encoded = base64.b64encode(cipher.encrypt(value))
    return encoded


def decrypt(value, secret_key):
    secret_key = secret_key.rjust(32)
    cipher = AES.new(secret_key, AES.MODE_ECB)
    decoded = cipher.decrypt(base64.b64decode(value))
    # remove added extra spaces
    return decoded.strip()


def set_value(label, set_pass=False):
    # force to set value visible on screen
    while True:
        value = raw_input(label)

        if value:
            return value


def cancel_command(value):
    # check if input is cancel command
    if value == 'c':
        return True
    return False


def add_url(secret_key, data_urls):
    print 'Press c to cancel'
    # add new url to list
    label = set_value('Enter label: ')
    if cancel_command(label):
        return None

    url = set_value('Enter url: ')
    if cancel_command(url):
        return None

    username = set_value('Enter username: ')
    if cancel_command(username):
        return None

    password = set_pass('Enter password: ')
    if cancel_command(password):
        return None

    data_url = {
        'label': label,
        'url': url,
        'username': encrypt(username, secret_key),
        'password': encrypt(password, secret_key)
    }

    data_urls.append(data_url)
    save_to_shelf(data_urls)
    return data_url


def save_to_shelf(data_urls):
    # save changes to shelf file
    # file to be used
    shelf = shelve.open("data_urls.shlf")
    # serializing
    shelf["data_urls"] = data_urls
    shelf.close()
    return data_urls


def get_data_urls():
    # read save data urls in shelf
    shelf = shelve.open("data_urls.shlf")
    # serializing
    data_urls = shelf.get("data_urls", [])
    shelf.close()
    return data_urls


def change_secret_key(old_secret_key, data_urls):
    # change secret key and update all your current username and password using new key
    print 'Press c to cancel'

    new_secret_key = set_pass('Enter your secret key: ')
    if cancel_command(new_secret_key):
        return None

    for data_url in data_urls:
        username = decrypt(data_url['username'], old_secret_key)
        password = decrypt(data_url['password'], old_secret_key)

        username = encrypt(username, new_secret_key)
        password = encrypt(password, new_secret_key)

        data_url['username'] = username
        data_url['password'] = password

    save_to_shelf(data_urls)
    return new_secret_key


def edit_url(secret_key, data_urls):
    # edit one url details
    print 'Press c to cancel'

    while True:
        url_index = set_value('Enter id of url to edit: ')
        if cancel_command(url_index):
            return None

        try:
            target_index = int(url_index) - 1
            data_url = data_urls[target_index]
            break
        except Exception:
            print('Item do not exists, please enter correct id.')
            continue

    label = raw_input('Enter label [%s]: ' % data_url['label']) or data_url['label']
    if cancel_command(label):
        return None
    url = raw_input('Enter url [%s]: ' % data_url['url']) or data_url['url']
    if cancel_command(url):
        return None

    decoded_username = decrypt(data_url['username'], secret_key)
    username = raw_input('Enter username [%s]: ' % decoded_username) or decoded_username
    if cancel_command(username):
        return None

    decoded_password = decrypt(data_url['password'], secret_key)
    password = getpass.getpass('Enter password: ') or decoded_password
    if cancel_command(password):
        return None

    data_url = {
        'label': label,
        'url': url,
        'username': encrypt(username, secret_key),
        'password': encrypt(password, secret_key)
    }

    # update the url
    data_urls[target_index] = data_url
    save_to_shelf(data_urls)
    return data_url


def delete_url(data_urls):
    # delete one url from list
    print 'Press c to cancel'

    while True:
        url_index = set_value('Enter id of url to delete: ')
        if cancel_command(url_index):
            return None

        try:
            target_index = int(url_index) - 1
            del data_urls[target_index]
            break
        except Exception:
            print('Item do not exists, please enter correct id.')
            continue
    save_to_shelf(data_urls)


def main():
    # run the program
    secret_key = set_pass('Enter your secret key: ')

    while True:
        data_urls = get_data_urls()
        draw_table(data_urls)

        selected = set_value('Select url to access: ')

        if selected == 'a':
            add_url(secret_key, data_urls)
        elif selected == 'r':
            new_secret_key = change_secret_key(secret_key, data_urls)
            if not new_secret_key:
                continue
            secret_key = new_secret_key
        elif selected == 'q':
            break
        elif selected.isdigit() and data_urls:
            index = int(selected) - 1

            try:
                data_url = data_urls[index]
            except IndexError:
                print 'Invalid command.'
                continue

            username = decrypt(data_url['username'], secret_key)
            password = decrypt(data_url['password'], secret_key)
            open_to_brower(data_url['url'], username, password)
        elif selected == 'e':
            edit_url(secret_key, data_urls)
        elif selected == 'd':
            delete_url(data_urls)
        else:
            print 'Invalid command.'


if __name__ == '__main__':
    main()
