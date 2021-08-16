/*
#***********************************************
#
#      Filename: gz-auth-jwt/lib/index.js
#
#        Author: wwj - 318348750@qq.com
#       Company: 甘肃国臻物联网科技有限公司
#   Description: Hapi.js  JSON Web Tokens (JWT)鉴权插件
#        Create: 2021-08-16 10:38:23
# Last Modified: 2021-08-16 14:05:25
#***********************************************
*/
'use strict'

const Boom = require('@hapi/boom')
const Hoek = require('@hapi/hoek')
const Joi = require('joi')
const Bounce = require('@hapi/bounce')
const JWT = require('jsonwebtoken')

// Declare internals

const internals = {}

module.exports = {
  pkg: require('../package.json'),
  register: (server, options) => {
    server.auth.scheme('jwt', internals.implementation)
  }
}

internals.schema = Joi.object({
  cookie: Joi.string().default('token'),
  header: Joi.string().default('authorization'),
  query: Joi.string().default('token'),
  tokenSource: Joi.array()
    .items(Joi.string().valid('cookie', 'header', 'query'))
    .single()
    .unique()
    .min(1)
    .default(['header']),
  tokenType: Joi.array()
    .items(Joi.string())
    .single()
    .unique()
    .default(['Token', 'JWT', 'Bearer', 'Inline']),
  secretKey: Joi.alternatives([
    Joi.func(),
    Joi.array()
      .items(Joi.string())
      .single()
      .min(1)
  ]).required(),
  validateFunc: Joi.func(),
  bind: Joi.any().optional(),
  verify: Joi.object()
    .keys({
      algorithms: Joi.array()
        .items(Joi.string())
        .min(1)
        .required(),
      audience: Joi.array()
        .items(Joi.string())
        .optional(),
      issuer: Joi.array()
        .items(Joi.string())
        .optional(),
      ignoreExpiration: Joi.boolean().default(false),
      ignoreNotBefore: Joi.any().optional(),
      subject: Joi.string().optional(),
      clockTolerance: Joi.number().optional(),
      maxAge: Joi.array()
        .items(Joi.string())
        .optional()
    })
    .required()
}).required()

internals.verify = async (...args) =>
  new Promise((resolve, reject) => {
    JWT.verify(...args, (err, data) => {
      if (err) {
        return reject(err)
      }
      return resolve(data)
    })
  })

internals.implementation = (server, options) => {
  const results = Joi.validate(options, internals.schema, {
    convert: true
  })
  Hoek.assert(!results.error, results.error)

  const settings = results.value
  const tryInline = settings.tokenType.includes('Inline')

  return {
    authenticate: async function (request, h) {
      let token
      let tokenTypeSelected
      if (settings.tokenSource.includes('header')) {
        switch (settings.header) {
          case 'authorization': {
            const authorization = request.headers.authorization
            if (authorization !== undefined) {
              const parts = authorization.split(/\s+/)
              if (parts.length !== 2) {
                if (!tryInline) {
                  throw Boom.badRequest('Bad HTTP authentication header format')
                }
                token = parts[0]
                tokenTypeSelected = 'Token'
                break
              }
              for (const tokenType of settings.tokenType) {
                if (tokenType === 'Inline') {
                  continue
                }
                if (tokenType.toLowerCase() === parts[0].toLowerCase()) {
                  token = parts[1]
                  tokenTypeSelected = tokenType
                  break
                }
              }
              if (!token) {
                return h.unauthenticated(Boom.unauthorized(null, parts[0]))
              }
            }
            break
          }
          default: {
            token = request.headers[settings.header]
            break
          }
        }
      }
      if (!token && settings.tokenSource.includes('cookie')) {
        throw Boom.notImplemented('Not implemented yet!')
      }
      if (!token && settings.tokenSource.includes('query')) {
        token = request.query[settings.query]
        settings.tokenTypeSelected = 'Token'
      }

      if (!token) {
        return h.unauthenticated(Boom.unauthorized(null, 'jwt'))
      }
      if (token.split('.').length !== 3) {
        return h.unauthenticated(
          Boom.unauthorized('Invalid token format', 'jwt', {
            token
          })
        )
      }
      // verification is done later, but we want to avoid decoding if malformed
      request.auth.token = token // keep encoded JWT available in the request
      // otherwise use the same key (String) to validate all JWTs
      let decoded
      try {
        decoded = JWT.decode(token, { complete: options.complete || false })
      } catch (e) {
        return h.unauthenticated(
          Boom.unauthorized('Invalid token format', 'jwt', {
            token,
            tokenTypeSelected
          })
        )
      }

      const { secretKey } = internals.isFunction(settings.secretKey)
        ? await settings.secretKey(decoded)
        : { secretKey: settings.secretKey }

      const validateFunc = options.validateFunc
        ? options.validateFunc.bind(options.bind || h.context)
        : internals.validateFunc.bind(options.bind || h.context)
      const keys = Array.isArray(secretKey) ? secretKey : [secretKey]
      let k
      for (let i = 0; i < keys.length; ++i) {
        k = keys[i]
        let verified
        try {
          verified = await internals.verify(token, k, settings.verify)
        } catch (err) {
          if (i >= keys.length - 1) {
            // we have exhausted all keys and still fail
            const message = err.message === 'jwt expired' ? 'Expired token' : 'Invalid token'
            return h.unauthenticated(
              Boom.unauthorized(message, 'jwt', { token, tokenTypeSelected })
            )
          }
          // verification failed but there are still keys to try
          continue
        }
        try {
          const { isValid, credentials, artifacts, response } = await validateFunc(
            {
              token,
              tokenType: settings.tokenTypeSelected,
              credentials: verified
            },
            request,
            h
          )

          if (response !== undefined) {
            return h.response(response).takeover()
          }
          if (!isValid) {
            // invalid credentials
            return h.unauthenticated(
              Boom.unauthorized('Invalid credentials', 'jwt', {
                credentials:
                  credentials && typeof credentials === 'object' ? credentials : verified,
                token,
                tokenTypeSelected
              })
            )
          }

          // valid key and credentials
          return h.authenticated({
            credentials: credentials && typeof credentials === 'object' ? credentials : verified,
            artifacts:
              artifacts && typeof artifacts === 'object' ? { ...artifacts, token } : { token }
          })
        } catch (err) {
          Bounce.rethrow(err, 'system')
          return h.unauthenticated(Boom.boomify(err, { credentials: verified }))
        }
      }
      return h.unauthenticated(
        Boom.unauthorized('Invalid credentials', 'jwt', {
          credentials: decoded,
          token,
          tokenTypeSelected
        })
      )
    }
  }
}

internals.validateFunc = async function ({ credentials }, request, h) {
  return {
    isValid: !!credentials.sub
  }
}

/**
 * isFunction checks if a given value is a function.
 * @param {Object} functionToCheck - the object we want to confirm is a function
 * @returns {Boolean} - true if the functionToCheck is a function. :-)
 */
internals.isFunction = function (functionToCheck) {
  const getType = {}

  return (
    functionToCheck &&
    (getType.toString.call(functionToCheck) === '[object Function]' ||
      getType.toString.call(functionToCheck) === '[object AsyncFunction]')
  )
}
