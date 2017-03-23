'use strict'

const uuid = require('uuid')
const nacl = require('tweetnacl')
const crypto = require('crypto')
const database = require('sqlite')
const ILP = require('ilp')
const PluginBells = require('ilp-plugin-bells')

const PORT = process.env.PIPRS_PORT || 6666
const STORE = process.env.PIPRS_STORE || ':memory:'

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
    yield database.run('INSERT INTO user VALUES (?, ?, ?)',
      key, account, password)
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
  const { signature, key, packet, condition } = this.request.body
  if (!signature || !key || !packet || !condition) {
    this.status = 422
    this.body = {
      status: 'error',
      message: 'all of signature, key, packet, and condition must be specified'
    }
    return
  }

  const user = yield database.get('SELECT * FROM user WHERE key = ?', key)
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
  const message = Buffer.concat([
    Buffer.from(condition, 'base64'),
    Buffer.from(packet, 'base64'),
  ])

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
    return database.run('CREATE TABLE user (key TEXT, account TEXT, password TEXT)')
  })
  .then(() => {
    app
      .use(parser)
      .use(router.routes())
      .use(router.allowedMethods())
      .listen(PORT)
    console.log('listening on', PORT)
  })
