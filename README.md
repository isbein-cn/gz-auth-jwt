# Hapi Auth using JSON Web Tokens (JWT)

***The*** authentication scheme/plugin for
[**Hapi.js**](http://hapijs.com/) apps using **JSON Web Tokens**

This node.js module (Hapi plugin) lets you use JSON Web Tokens (JWTs)
for authentication in your [Hapi.js](http://hapijs.com/)
web application.

If you are totally new to JWTs, we wrote an introductory post explaining
the concepts & benefits: https://github.com/dwyl/learn-json-web-tokens

api-auth-jwt/issues

### Install from NPM

```sh
npm install @clickdishes/hapi-auth-jwt --save
```

### Example

This basic usage example should help you get started:


```javascript
const Hapi = require('hapi');

const people = { // our "users database"
    1: {
      id: 1,
      name: 'Jen Jones'
    }
};

// bring your own validation function
const validate = async function (decoded, request) {

    // do your checks to see if the person is valid
    if (!people[decoded.id]) {
      return { isValid: false };
    }
    else {
      return { isValid: true, credentials: decoded };
    }
};

const init = async () => {
  const server = new Hapi.Server({ port: 8000 });
  // include our module here ↓↓
  await server.register(require('@clickdishes/hapi-auth-jwt'));

  server.auth.strategy('jwt', 'jwt',
  { secretKey: 'NeverShareYourSecret',          // Never Share your secret key
    validateFunc: validate,            // validate function defined above
    verify: { algorithms: [ 'HS256' ] } // pick a strong algorithm
  });

  server.auth.default('jwt');

  server.route([
    {
      method: "GET", path: "/", config: { auth: false },
      handler: function(request, reply) {
        return {text: 'Token not required'};
      }
    },
    {
      method: 'GET', path: '/restricted', config: { auth: 'jwt' },
      handler: async function(request, h) {
        return h.response({text: 'You used a Token!'})
        .header("Authorization", request.headers.authorization);
      }
    }
  ]);
  await server.start();
  return server;
};


init().then(server => {
  console.log('Server running at:', server.info.uri);
})
.catch(error => {
  console.log(error);
});
```

## Documentation

- `secretKey` - (***required*** - *unless you have a `customVerify` function*) the secret key (or array of potential keys)
used to check the signature of the token ***or*** a **key lookup function** with
signature `async function(decoded)` where:
    - `decoded` - the ***decoded*** but ***unverified*** JWT received from client
    - Returns an object `{ isValid, secretKey }` where:
        - `isValid` - result of validation
        - `secretKey` - the secret key (or array of keys to try)
 
- `validateFunc` - (***required***) the function which is run once the Token has been decoded with
 signature `async function(decoded, request, h)` where:
    - `decoded` - (***required***) is the decoded and verified JWT received in the request
    - `request` - (***required***) is the original ***request*** received from the client
    - `h` - (***required***) the response toolkit.
    - Returns an object `{ isValid, credentials, response }` where:
        - `isValid` - `true` if the JWT was valid, otherwise `false`.
        - `credentials` - (***optional***) alternative credentials to be set instead of `decoded`.
        - `response` - (***optional***) If provided will be used immediately as a takeover response.
