import requests
import hashlib
import time


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


print("-" * 100)
print("*" * 35 + " Password Checker Application " + "*" * 35)
print("-" * 100)
print(f'The Following Password checker allows you to check if the password was ever hacked.\n'
      f'The checker utilises pwnedpasswords api inorder to determine the number of times\n'
      f'the password was hacked on any web platform\n'
      f'This application safely gets data without sending the complete password to the server')
print("-" * 100)
time.sleep(2)
k=0
while k != 1:
    password = input(f'Please Enter the password to be checked :\t')
    count = pwned_api_check(password)
    if count:
        print(f'\nResult : {password} was found {count} times. Please try some other password')
    else:
        print(f'The password {password} can be used and is never hacked')
    x = input(f'\nDo you want to check more passwords(Yes/No):\t')
    if x in ['No', 'NO', 'no']:
        k = 1
        print("-" * 100)
        print(f'\nThank you for using the application. Be Secure')
        print("-" * 100)
    else:
        print("-" * 100)

