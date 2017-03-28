'use strict'

const uuid = require('uuid')
const nacl = require('tweetnacl')
const crypto = require('crypto')
const database = require('sqlite')
const ILP = require('ilp')
const PluginBells = require('ilp-plugin-bells')

const PORT = process.env.PIPRS_PORT || 6666
const STORE = process.env.PIPRS_STORE || ':memory:'
const CREATE_QUERY = 'CREATE TABLE IF NOT EXISTS user (key TEXT PRIMARY KEY, account TEXT, password TEXT)'
const CREATE_USER_QUERY = 'INSERT INTO user VALUES (?, ?, ?)'
const GET_USER_QUERY = 'SELECT * FROM user WHERE key = ?'

const app = require('koa')()
const router = require('koa-router')()
const parser = require('koa-bodyparser')()

const toUUID = function (buffer) {
  return buffer.slice(0, 4).toString('hex') +
    '-' + buffer.slice(4, 6).toString('hex') +
    '-' + buffer.slice(6, 8).toString('hex') +
    '-' + buffer.slice(8, 16).toString('hex')
}

router.post('/users', function * () {
  const { key, account, password } = this.request.body
  if (!key || !account || !password) {
    this.status = 422
    this.body = {
      status: 'error',
      message: 'all of key, account, and password must be specified.'
    }
    return
  }

  const plugin = new PluginBells({
    account: account,
    password: password
  })

  try {
    yield plugin.connect()
    yield database.run(CREATE_USER_QUERY, key, account, password)
  } catch (e) {
    this.status = 422
    this.body = {
      status: 'error',
      message: e.message
    }
    console.log('error authenticating:', e.message)
    return
  }

  this.status = 201
  this.body = { status: 'ok' }
})

router.post('/payments', function * () {
  const { signature, key, ipr } = this.request.body
  if (!signature || !key || !ipr) {
    this.status = 422
    this.body = {
      status: 'error',
      message: 'all of signature, key, and ipr must be specified'
    }
    return
  }

  const version = ipr.slice(0, 1) // get the version number
  if (version.toString('hex') !== '02') {
    this.status = 422
    this.body = {
      status: 'error',
      message: 'invalid IPR version'
    }
    console.log('request with invalid IPR packet', ipr.toString('hex'))
    return
  }

  const condition = ipr.slice(1, 33) // bytes between version and packet are condition
  const packet = ipr.slice(33) // get everything after the condition

  const user = yield database.get(GET_USER_QUERY, key)
  if (!user) {
    this.status = 422
    this.body = {
      status: 'error',
      message: 'no user with given key exists'
    }
    console.log('request for unknown key', key)
    return
  }

  const keyBuffer = Buffer.from(key, 'base64')
  const sigBuffer = Buffer.from(signature, 'base64')
  const message = Buffer.from(ipr, 'base64')

  let verified
  try {
    verified = nacl.sign.detached.verify(message, sigBuffer, keyBuffer)
  } catch (e) {
    this.status = 422
    this.body = {
      status: 'error',
      message: e.message
    }
    console.log('signature error:', e.message)
    return
  }

  if (!verified) {
    this.status = 422
    this.body = {
      status: 'error',
      message: 'signature does not pass verification'
    }
    console.log('request with bad signature', signature)
    return
  }
  
  const plugin = new PluginBells({
    account: user.account,
    password: user.password
  })

  // ensures that payments are idempotent.
  // could be updated to use an HMAC to prevent id squatting.
  const id = toUUID(crypto
    .createHash('sha256')
    .update(message)
    .digest())

  const quote = yield ILP.ILQP.quoteByPacket(plugin, packet)

  // sends out the payment but doesn't wait for it to be fulfilled
  plugin.sendTransfer({
    id: id,
    ilp: packet,
    executionCondition: condition,
    amount: quote.sourceAmount,
    to: quote.connectorAccount,
    expiresAt: quote.expiresAt
  })

  this.status = 200
  this.body = { status: 'ok' }
})

database
  .open(STORE, { Promise })
  .then(() => {
    return database.run(CREATE_QUERY)
  })
  .then(() => {
    app
      .use(parser)
      .use(router.routes())
      .use(router.allowedMethods())
      .listen(PORT)
    console.log('listening on', PORT)
  })
