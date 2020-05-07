import hashlib
import time
from password_generator import PasswordGenerator
import requests


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char  # first5_char is passed as query_char to fetch the response
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, Check the api and tr again')
    return res       # returns  tail reponse to pwned_api_check variable response


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())   # splits tail values and count
    for h, count in hashes:
        if h == hash_to_check:   # if tail matches the response return count
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()    #uses the hash library to get the SHA1 password as Hexdigest in upper case
    first5_char, tail = sha1password[:5], sha1password[5:]   #spilts the sha1password into 2 blocks first5 block that is sent as a part of URL
    response = request_api_data(first5_char)    # calls the request_api_data to pass first5_char as argument
    return get_password_leaks_count(response, tail)   #sends all the reponse and tail to the called method as argument


def pass_generator():
    pwo = PasswordGenerator()
    pwo.minlen = 6  # (Minimum Length)
    pwo.maxlen = 12  # (Maximum Length)
    pwo.minuchars = 2  # (Minimum Upper Case Characters)
    pwo.minlchars = 2  # (Minimum Lower Case Characters)
    pwo.minnumbers = 2  # (Minimum Numbers)
    pwo.minschars = 3  # (Minimum special characters)
    pass_wd = pwo.generate()
    print(f'Recommended Password : {pass_wd}')
    print("-" * 100)


print("-" * 100)
print("*" * 35 + " Password Checker Application " + "*" * 35)
print("-" * 100)
print(f'The Following Password checker allows you to check if the password was ever hacked.\n'
      f'The checker utilises pwnedpasswords api inorder to determine the number of times\n'
      f'the password was hacked on any web platform\n'
      f'This application safely gets data without sending the complete password to the server')
print("-" * 100)
time.sleep(2)
k = 0
while k != 1:
    password = input(f'Please Enter the password to be checked :\t')
    weak = 'weak'
    med = 'medium'
    strong = 'strong'

    if len(password) > 12:
        print('Caution : Password is too long It must be between 6 and 12 characters')

    elif len(password) < 6:
        print('Caution : Password is too short It must be between 6 and 12 characters')

    elif len(password) >= 6 and len(password) <= 12:
        print('Result : Password Length is OK')

        if password.lower() == password or password.upper() == password or password.isalnum() == password:
            print('Password Strength : Password is ', weak)

        elif password.lower() == password and password.upper() == password or password.isalnum() == password:
            print('Password Strength : Password is ', med)
        else:
            password.lower() == password and password.upper() == password and password.isalnum() == password
            print('Password Strength : Password is ', strong)
    print(f'Checking the Number of times the password was hacked :')
    time.sleep(2)
    count = pwned_api_check(password)
    if count:
        print(f'Result : {password} was found {count} times. Please try some other password')
        print("-" * 100)
        recommendation = input(f'Do you want recommendations for a strong password :\t')
        if recommendation in ['Yes', 'yes', 'YES']:
            pass_generator()
        else:
            pass
    else:
        print(f'The password {password} can be used and was never hacked')
    x = input(f'Do you want to check more passwords(Yes/No):\t')
    if x in ['No', 'NO', 'no']:
        k = 1
        print("-" * 100)
        print(f'Thank you for using the application. Be Secure')
        print("-" * 100)
    else:
        print("-" * 100)

