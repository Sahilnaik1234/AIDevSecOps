import os

# Command Injection vulnerability
user_input = input("Enter command: ")
os.system(user_input)