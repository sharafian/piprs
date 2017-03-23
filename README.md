# PIPRS (Pull-based Interledger Payment Request Server)
> IPR-based pull payment server for five-bells-ledger

It's pronounced "Pipers."

## Usage

The default for `PIPRS_STORE` is `:memory:`. The default for `PIPRS_PORT` is
`6666`.

```sh
PIPRS_STORE=store.db PIPRS_PORT=6666 npm start
```

## API

Requests and responses are in JSON.

### POST `/users`

Creates a user in the database. The `account` and `password` are used to authenticate
a plugin-bells instance when a payment is sent. Payments will be sent if an IPR signed
with `key` is presented. Signatures are of the octet string `condition + packet`.

#### Request

- `key` - Public key of this user.
- `account` - Account URI (for five-bells-ledger account) of this user.
- `password` - Password (for five-bells-ledger account) of this user.

#### Response

- `status` - `ok` or `error`
- `message` - defined if there's an error.

### POST `/payments`

Creates an IPR payment from the user who owns the given key to the destination specified.
Uses `packet` and `condition` as the IPR.

#### Request

- `key` - Public key of user. Returns `422` if no user with this key exists.
- `packet` - base64url-encoded ILP packet.
- `condition` - base64url-encoded 32-byte ILP condition.
- `signature` - signature of the octet string `condition + packet`. Verified with `key`.

#### Response

- `status` - `ok` or `error`
- `message` - defined if there's an error.
