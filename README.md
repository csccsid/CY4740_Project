We have the following combination of op_code and event

| op_code | event                  | description                                                  |
|---------|------------------------|--------------------------------------------------------------|
| 1       | auth_request           | User sends auth request to server                            |
| 1       | auth_request_challenge | Server sends back a challenge in regard to that auth_request |
| 1       | challenge_response     | Client solves the challenge and sends it back to server      |
| 0       | key_not_found          | Server failed to obtain the session key of a user            |
| 4       | LIST                   | LIST command request sent from client                        |

## Run application

You should run the script to generate server_public and server_private keys first.

Command: `python src/util/generate_keys`

And it would generate keys with the names of server_public_key.pem and server_private_key.pem respectively. There are under the top-level directory. 

### Command to start server(KDC)

we have a KDC to control login and key establishment

`python src/server.py -sp 12345 -db_key_path "DB-X509-cert.pem" -db_uri "mongodb+srv://server-users.5lef1kv.mongodb.net/?authSource=%24external&authMechanism=MONGODB-X509&retryWrites=true&w=majority&appName=server-users" -priv_key "server_private_key.pem"`

### Command of client

Than to start client, here is command

`python src/new_client.py -host 127.0.0.1 -client_service_port 10001 -username interstellar_scout -password ScoutTheStars! -server_pub_key_path server_public_key.pem`

There are more user names and passwords in the file /src/util/credentials.txt

Beside of `send` and `list` commands, we also have command `exit` to logout an user.

