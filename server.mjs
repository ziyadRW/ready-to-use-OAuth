import express from "express";
import bodyParser from "body-parser";
import { hash, compare } from "bcrypt";
import { join, dirname } from "path";
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import base64url from 'base64url';
import { fileURLToPath } from "url";
import { createRequire } from "module";
import { signin, signup } from "./db/db.mjs";
const app = express();

const require = createRequire(import.meta.url);
const secret = require('./client_secret.json');
const querystring = require('querystring');

const authenticators = {};
const rpID = 'localhost';  
const expectedOrigin = 'http://localhost:3000';
const CLIENT_ID = secret.client_id
const CLIENT_SECRET = secret.client_secret
const REDIRECT_URI = 'http://localhost:3000/auth/google/callback';


const { urlencoded } = bodyParser;

const __dirname = dirname(fileURLToPath(import.meta.url));

 
app.use(bodyParser.json());
app.use(urlencoded({ extended: true }));
app.use(express.static(join(__dirname, "public")));

// Registration endpoint
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await hash(password, 10);
    const user = { username, password: hashedPassword };

    signup(username, user);

    res.send("User registered successfully");
  } catch (error) {
    res.status(500).send("Error registering new user");
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  let user = signin(username);
  if (!user) {
    return res.status(400).send("Invalid credentials");
  }
  const match = await compare(password, user.password);
  if (match) {
    res.send("Login successful");
  } else {
    res.status(400).send("Invalid credentials");
  }
});

app.get('/auth/google', (req, res) => {
  const authorizationUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
  const params = {
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',  // Updated scope
      access_type: 'online'
  };
  res.redirect(`${authorizationUrl}?${querystring.stringify(params)}`);
});






app.get('/auth/google/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) {
      return res.status(400).send('Authorization code is missing');
  }
  try {
      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: querystring.stringify({
              code,
              client_id: CLIENT_ID,
              client_secret: CLIENT_SECRET,
              redirect_uri: REDIRECT_URI,
              grant_type: 'authorization_code'
          })
      });

      if (!tokenResponse.ok) {
          throw new Error('Failed to exchange authorization code for access token');
      }

      const tokenData = await tokenResponse.json();
      const accessToken = tokenData.access_token;

      if (!accessToken) {
          throw new Error('Access token is missing in the response');
      }

      const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v1/userinfo', {
          headers: { Authorization: `Bearer ${accessToken}` }
      });

      if (!userInfoResponse.ok) {
          throw new Error('Failed to fetch user info');
      }

      const userData = await userInfoResponse.json();
      // send Login successful
      res.send(`
          <h1>Login successful</h1>
          <p>Welcome ${userData.email}</p>
      `);
      
  } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
  }
});




app.post('/register/start', async (req, res) => {
  // Extract username from request body
  const { username } = req.body;
  if (!username) {
    return res.status(400).send({ error: 'Username is required' });
  }

  // Check if user already exists
  const user = await signin(username);
  if (user) {
    return res.status(400).send({ error: 'User already exists' });
  }

  // Generate registration options
  const registrationOptions = await generateRegistrationOptions({
    rpName: 'Future Of Authentication',
    rpID,
    userID: base64url(Buffer.from(username)),
    userName: username,
    timeout: 60000, // Timeout for the request in milliseconds
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'discouraged',
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  // Store the challenge temporarily for verification in the next step
  authenticators[username] = {
    challenge: registrationOptions.challenge,
  };

  // Send registration options to the client
  return res.send(registrationOptions);
});

// Endpoint to finish the registration process
app.post('/register/finish', async (req, res) => {
  const { username, attestationResponse } = req.body;

  // Retrieve the stored challenge from the 'authenticators' object
  const expectedChallenge = authenticators[username].challenge;

  let verification;
  try {
    // Verify the registration response
    verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  // Check if verification was successful
  const { verified } = verification;
  if (verified) {
    // Prepare user data for storage
    const user = {
      devices:[{
        credentialPublicKey: base64url.encode(verification.registrationInfo.credentialPublicKey),
        credentialID: base64url.encode(verification.registrationInfo.credentialID),
        transports: attestationResponse.response.transports,
      }],
      userID: base64url(Buffer.from(username)),
      userName: username,
    };

    // Remove the temporary authenticator
    authenticators[username] = undefined;

    try {
      // Store the user in the database
      await signup(username, user);
    }
    catch (error) {
      return res.status(400).send({ error: error.message });
    }

    // Send verification result to the client
    return res.send({ verified });
  } else {
    return res.status(400).send({ error: 'Unable to verify registration' });
  }
});

// Endpoint to start the login process
app.post('/login/start', async (req, res) => {
  const { username } = req.body;
  // Verify if the user exists
  const user = await signin(username);
  if (!user) {
    return res.status(400).send({ error: 'User does not exist' });
  }

  // Generate authentication options
  const options = {
    rpID,
    timeout: 60000, // Timeout for the request in milliseconds
    userVerification: 'required',
    allowCredentials: user.devices.map((device) => ({
      id: new Uint8Array(base64url.toBuffer(device.credentialID)),
      type: 'public-key',
      transports: device.transports,
    })),
  };

  const authenticationOptions = await generateAuthenticationOptions(options);

  // Store the challenge for later use during verification
  authenticators[username] = {
    currentChallenge: authenticationOptions.challenge,
  };

  // Send authentication options to the client
  return res.send(authenticationOptions);
});

// Endpoint to finish the login process
app.post('/login/finish', async (req, res) => {
  const { username, assertionResponse } = req.body;
  const expectedChallenge = authenticators[username].currentChallenge;

  const user = await signin(username);
  const device = user.devices[0];

  let verification;
  try {
    // Verify the authentication response
    verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: new Uint8Array(base64url.toBuffer(device.credentialID)),
        credentialPublicKey: new Uint8Array(base64url.toBuffer(device.credentialPublicKey)),
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  // Send the verification result to the client
  const { verified } = verification;
  if (verified) {
    return res.send({ verified });
  } else {
    return res.status(400).send({ error: 'Unable to verify login' });
  }
});












 


app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});
