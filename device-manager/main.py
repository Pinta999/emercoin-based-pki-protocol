import deviceconf
import transfer_device_ownership
import update_device_key
import revoke_device_key

menu_options = {
    1: 'Initialize new IoT device',
    2: 'Device ownership transfer',
    3: 'Device key update',
    4: 'Device key revocation',
    5: 'Exit'
}


def print_menu():
    print('Welcome to your personal Device Manager! Choose an option:')
    for key in menu_options.keys():
        print(f' {key}. {menu_options[key]}')


def choose_option():
    end = False
    while not end:
        option = input('\n>> ')
        if option == '1':
            deviceconf.deviceconf()
        elif option == '2':
            transfer_device_ownership.ownership_transfer()
        elif option == '3':
            update_device_key.update_key()
        elif option == '4':
            revoke_device_key.revoke_key()
        elif option == '5':
            end = True
            return
        else:
            print('Invalid operation. Please select one of the possible operation.')


def main():
    print_menu()
    choose_option()

if __name__ == '__main__':
    main()
