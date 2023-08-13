import time
import requests
from web3 import Web3
from eth_account.messages import encode_defunct

web3 = Web3(Web3.HTTPProvider("https://polygon.blockpi.network/v1/rpc/7433894eead0d1c58dbc40da4635dd42fd6cd8cb"))

cyber_contract_address = web3.to_checksum_address('0xcd97405Fb58e94954E825E46dB192b916A45d412')
cyber_contract_abi = '[{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"from","type":"address"},{"indexed":false,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Deposit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"user","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Withdraw","type":"event"},{"inputs":[{"internalType":"address","name":"to","type":"address"}],"name":"depositTo","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"deposits","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"}]'
cyber_contract = web3.eth.contract(address=cyber_contract_address, abi=cyber_contract_abi)

headers = {
    'authority': 'api.cyberconnect.dev',
    'accept': '*/*',
    'authorization': '',
    'content-type': 'application/json',
    'origin': 'https://cyber.co',
    'referer': 'https://cyber.co/',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
}


def read_file(filename):
    result = []
    with open(filename, 'r') as file:
        for tmp in file.readlines():
            result.append(tmp.replace('\n', ''))

    return result


def write_to_file(filename, text):
    with open(filename, 'a') as file:
        file.write(f'{text}\n')


def get_nonce(address, proxy):
    json_data = {
        'query': '\n    mutation nonce($address: EVMAddress!) {\n  nonce(request: {address: $address}) {\n    status\n    message\n    data\n  }\n}\n    ',
        'variables': {
            'address': address,
        },
        'operationName': 'nonce',
    }

    response = requests.post('https://api.cyberconnect.dev/profile/', headers=headers, json=json_data, proxies=proxy)
    nonce = response.json()['data']['nonce']['data']
    return nonce


def sign_signature(private_key, message, type_='text'):
    message_hash = encode_defunct(text=message)
    if type_ == 'hexstr':
        message_hash = encode_defunct(hexstr=message)
    signed_message = web3.eth.account.sign_message(message_hash, private_key)

    signature = signed_message.signature.hex()
    return signature


def get_authorization(address, signature, signed_message, proxy):
    json_data = {
        'query': '\n    mutation login($request: LoginRequest!) {\n  login(request: $request) {\n    status\n    message\n    data {\n      id\n      privateInfo {\n        accessToken\n      }\n    }\n  }\n}\n    ',
        'variables': {
            'request': {
                'address': address,
                'signature': signature,
                'signedMessage': signed_message,
            },
        },
        'operationName': 'login',
    }

    response = requests.post(
        'https://api.cyberconnect.dev/profile/',
        headers=headers,
        json=json_data,
        proxies=proxy,
    ).json()['data']['login']

    if response['status'] == "SUCCESS":
        authorization = response['data']['privateInfo']['accessToken']
        return authorization
    else:
        print(f'{response}')


def get_cyber_address(authorization, proxy):
    private_headers = headers.copy()
    private_headers['authorization'] = authorization

    json_data = {
        'query': '\n    query me {\n  me {\n    status\n    message\n    data {\n      ccProfiles {\n        handle\n      }\n      lightInfo {\n        avatar\n        formattedAddress\n        displayName\n      }\n      privateInfo {\n        accessToken\n        address\n      }\n      v3Info {\n        cyberAccount\n        totalPoints\n      }\n    }\n  }\n}\n    ',
        'operationName': 'me',
    }

    response = requests.post(
        'https://api.cyberconnect.dev/profile/',
        headers=private_headers,
        json=json_data,
        proxies=proxy
    ).json()['data']['me']
    if response['status'] == 'SUCCESS':
        cyber_address = response['data']['v3Info']['cyberAccount']
        return cyber_address
    else:
        print(response)


def deposit(private, address, cyber_address):
    try:
        tx = cyber_contract.functions.depositTo(cyber_address).build_transaction(
            {
                'from': address,
                'value': web3.to_wei(2, 'ether'),
                'nonce': web3.eth.get_transaction_count(address),
                'gasPrice': web3.eth.gas_price,
            }
        )

        tx_create = web3.eth.account.sign_transaction(tx, private)
        tx_hash = web3.eth.send_raw_transaction(tx_create.rawTransaction)
        write_to_file('depositing hashes.txt', tx_hash.hex())
        print(f"{address} | Depositing hash: {tx_hash.hex()}")
        web3.eth.wait_for_transaction_receipt(tx_hash, timeout=360)
    except Exception as e:
        print(f'{address} | ERROR: {e}')


def get_data(authorization, proxy):
    private_headers = headers.copy()
    private_headers['authorization'] = authorization

    json_data = {
        'query': '\n    mutation collectV3W3st($eventId: ID!, $chainId: Int!) {\n  collectV3W3ST(eventId: $eventId, chainId: $chainId) {\n    status\n    gasLess\n    collector\n    cyberAccount\n    tokenId\n    data\n    collectId\n    chainId\n    sponsorSig\n  }\n}\n    ',
        'variables': {
            'eventId': 'TVEMmn',
            'chainId': 10,
        },
        'operationName': 'collectV3W3st',
    }

    response = requests.post(
        'https://api.cyberconnect.dev/profile/',
        headers=private_headers,
        json=json_data,
        proxies=proxy,
    ).json()
    data = response['data']['collectV3W3ST']

    if data['status'] == 'SUCCESS':
        return data['data'], True
    else:
        return data['status'], False


def cc_estimate_user_operation(address, cyber_address, data, proxy, id_):
    json_data = {
        'jsonrpc': '2.0',
        'id': id_,
        'method': 'cc_estimateUserOperation',
        'params': [
            {
                'sender': cyber_address,
                'to': '0x4bc54260ec3617b3f73fdb1fa22417ed109f372c',
                'callData': f'0x0fe1597f0000000000000000000000000d3f6ec061a5565512c2bb04897d7190c88e822c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000{cyber_address[2:]}000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000080{data[2:]}',
                'value': '0',
                "nonce": None,
                "maxFeePerGas": None,
                "maxPriorityFeePerGas": None,
                'ep': '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789',
            },
            {
                'chainId': 10,
                'owner': address,
            },
        ],
    }

    response = requests.post(
        'https://api.cyberconnect.dev/paymaster/',
        headers=headers,
        json=json_data,
        proxies=proxy
    ).json()

    return response['result']['fast']


def sponsor_user_operation(address, cyber_address, data, gas, proxy, auth):
    private_headers = headers.copy()
    private_headers['authorization'] = auth

    json_data = {
        'query': '\n    mutation sponsorUserOperation($input: SponsorUserOperationInput!) {\n  sponsorUserOperation(input: $input) {\n    userOperation {\n      sender\n      nonce\n      initCode\n      callData\n      callGasLimit\n      verificationGasLimit\n      preVerificationGas\n      maxFeePerGas\n      maxPriorityFeePerGas\n      paymasterAndData\n      signature\n    }\n    userOperationHash\n  }\n}\n    ',
        'variables': {
            'input': {
                'params': {
                    'sponsorUserOpParams': {
                        'sender': cyber_address,
                        'to': '0x4bc54260ec3617b3f73fdb1fa22417ed109f372c',
                        'callData': f'0x0fe1597f0000000000000000000000000d3f6ec061a5565512c2bb04897d7190c88e822c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000{cyber_address[2:]}000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000080{data[2:]}',
                        'value': '0',
                        'nonce': None,
                        'maxFeePerGas': gas['maxFeePerGas'],
                        'maxPriorityFeePerGas': gas['maxPriorityFeePerGas'],
                        'entryPoint': '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789',
                    },
                    'sponsorUserOpContext': {
                        'chainId': 10,
                        'owner': address,
                    },
                },
                'type': 'TRANSFER_NFT',
                'readableTransaction': '',
            },
        },
        'operationName': 'sponsorUserOperation',
    }

    response = requests.post(
        'https://api.cyberconnect.dev/profile/', 
        headers=private_headers,
        json=json_data,
        proxies=proxy,
    ).json()['data']['sponsorUserOperation']
    print(response)
    return response['userOperation'], response['userOperationHash']


def eth_send_user_operation(user_operation, address, proxy, id_):
    json_data = {
        'jsonrpc': '2.0',
        'id': id_,
        'method': 'eth_sendUserOperation',
        'params': [
            user_operation,
            '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789',
            {
                'chainId': 10,
                'owner': address,
            },
        ],
    }

    requests.post(
        'https://api.cyberconnect.dev/paymaster/',
        headers=headers,
        json=json_data,
        proxies=proxy
    ).json()


def deploy_contract(authorization, private, address, cyber_address, proxy):
    print(f'{address} | Deploying contract...')
    data = get_data(authorization, proxy)
    if data[1]:
        data = data[0]
        print((address, cyber_address, data, proxy, 0))
        cc_estimate_user_operation(address, cyber_address, data, proxy, 0)
        gas = cc_estimate_user_operation(address, cyber_address, data, proxy, 1)
        user_operation, user_operation_hash = sponsor_user_operation(address, cyber_address, data, gas, proxy, authorization)
        user_operation_signature = sign_signature(private, user_operation_hash, 'hexstr')
        user_operation['signature'] = str(user_operation_signature)
        eth_send_user_operation(user_operation, address, proxy, 3)
        print(f'{address} | CyberWallet has been deployed')
    else:
        print(f'{address} | Deploying contract status: {data[0]}')


def main():
    privates = read_file('privates.txt')
    proxies = read_file('proxies.txt')

    for private, proxy in zip(privates, proxies):
        address = web3.eth.account.from_key(private).address
        proxy = {"http": f"http://{proxy}", "https": f"http://{proxy}"}

        nonce = get_nonce(address, proxy)
        message = f'cyber.co wants you to sign in with your Ethereum account:\n{address}\n\n\nURI: https://cyber.co\nVersion: 1\nChain ID: 56\nNonce: {nonce}\nIssued At: 2023-08-04T10:57:32.803Z\nExpiration Time: 2023-08-18T10:57:32.803Z\nNot Before: 2023-08-04T10:57:32.803Z'
        signed_msg = sign_signature(private, message)
        authorization = get_authorization(address, signed_msg, message, proxy)
        cyber_address = get_cyber_address(authorization, proxy)
        deposit(private, address, cyber_address)
        time.sleep(10)
        deploy_contract(authorization, private, address, cyber_address, proxy)


if __name__ == '__main__':
    main()
