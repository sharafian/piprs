# PIPRS (Pull-based Interledger Payment Request Server)
> IPR-based pull payment server for five-bells-ledger

It's pronounced "Pipers." This is not safe for production use cases. It does
some bad things, like storing passwords in plaintext and doing expensive
database and crypto operations on unauthenticated requests.

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
with `key` is presented. Signatures are of an [IPR](https://github.com/interledger/rfcs/blob/master/0011-interledger-payment-request/0011-interledger-payment-request.md).

#### Request

- `key` - Public key of this user.
- `account` - Account URI (for five-bells-ledger account) of this user.
- `password` - Password (for five-bells-ledger account) of this user.

#### Response

- `status` - `ok` or `error`
- `message` - defined if there's an error.

### POST `/payments`

Creates an IPR payment from the user who owns the given key to the destination specified.
Uses the `ipr` to quote and send a payment.

#### Request

- `key` - Public key of user. Returns `422` if no user with this key exists.
- `ipr` - base64url-encoded IPR.
- `signature` - signature of IPR. Verified with `key`.

#### Response

- `status` - `ok` or `error`
- `message` - defined if there's an error.
