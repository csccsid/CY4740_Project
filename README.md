We have the following combination of op_code and event

| op_code | event                  | description                                                  |
|---------|------------------------|--------------------------------------------------------------|
| 1       | auth_request           | User sends auth request to server                            |
| 1       | auth_request_challenge | Server sends back a challenge in regard to that auth_request |
| 1       | challenge_response     | Client solves the challenge and sends it back to server      |
| 0       | key_not_found          | Server failed to obtain the session key of a user            |
| 4       | LIST                   | LIST command request sent from client                        |