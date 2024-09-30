#!/usr/bin/env python3

import configparser
import argparse
import getpass

# Function to edit the .cfg file
def edit_config(value1, value2, value3):
    # Create a ConfigParser object
    config = configparser.ConfigParser()

    # Read the configuration file
    config.read("/opt/conda/etc/rucio.cfg")

    # Modify or add the three options within the section
    config.set('client', 'username', value1)
    config.set('client', 'account', value2)
    config.set('client', 'password', value3)

    # Write the changes back to the file
    with open("/opt/conda/etc/rucio.cfg", 'w') as configfile:
        config.write(configfile)

    print(f"Updated 'rucio.cfg' -> username, password, account correctly")

# Setup argument parsing
def main():
    parser = argparse.ArgumentParser(description='Edit your credentials in the rucio.cfg file.')

    # Credentials
    parser.add_argument('--user', help='Username')

    #parser.add_argument('--pwd', help='Password')

    parser.add_argument('--a', help='Account')

    # Parse the arguments
    args = parser.parse_args()

    # Securely prompt for the password (hidden from terminal history)
    value3 = getpass.getpass(prompt='Enter the password (hidden): ')

    # Call the function to edit the config file with three variables
    edit_config(args.user, args.a, value3)

if __name__ == '__main__':
    main()
