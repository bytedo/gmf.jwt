/**
 * json web token
 * @author yutent<yutent.io@gmail.com>
 * @date 2020/09/16 17:23:52
 */

import crypto from 'crypto.js'
import { base64encode, base64decode } from 'crypto.js'

function hmac(str, secret) {
  var buf = crypto.hmac('sha256', str, secret, 'buffer')
  return base64encode(buf, true)
}

export default class Jwt {
  constructor(expires, secret) {
    this.expires = expires
    this.secret = secret
  }

  // 签名, 返回token
  sign(data) {
    // header: base64("{"typ":"JWT","alg":"HS256"}")
    // 这里固定使用sha256,
    var header = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    var { expires, secret } = this

    // 加入过期时间, 同session.ttl
    var payload = { data, expires: Date.now() + expires * 1000 }
    var auth_str = ''

    payload = JSON.stringify(payload)
    payload = base64encode(payload, true)
    auth_str = hmac(`${header}.${payload}`, secret)

    return [header, payload, auth_str].join('.')
  }

  // 校验token
  verify(token) {
    var { secret } = this
    var jwt = token.split('.')
    var auth_str, payload

    if (jwt.length !== 3) {
      return false
    }
    auth_str = jwt.pop()
    payload = JSON.parse(base64decode(jwt[1], true))

    // 如果已经过期, 则不再校验hash
    if (payload.expires < Date.now()) {
      return 'expired'
    }

    if (hmac(jwt.join('.'), secret) === auth_str) {
      return payload.data
    }

    return false
  }
}
