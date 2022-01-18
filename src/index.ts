import { generators, Issuer } from 'openid-client';
import express from 'express';
import cookieSession from 'cookie-session';
import auth from 'auth.json';
import { port, domain } from 'config.json';

const slackIdClient = (() => {
    const issuer = await Issuer.discover('https://slack.com/.well-known/openid-configuration');
    return new issuer.Client({
        client_id: '2210535565.2883178111171',
        response_types: ['code'],
        redirect_uri: `https://${domain}/rotkov/slackauthed`,
    });
})();

const app = express();
app.use(helmet());
app.use(cookieSession({
    ...auth.cookie,
    cookie: {
        secure: true,
        httpOnly: true,
        domain,
        path: 'rotkov',
        maxAge: 60 * 60 * 1000,
        sameSite: true,
    }
});

app.route('/slack')
   .get('/login', (req, res) => {
        const cv = req.session.codeVerifier = generators.codeVerifier();

        res.redirect(slackIdClient.authorizationUrl({
            scope: 'openid email profile'
            code_challenge: generators.codeChallenge(cv),
            code_challenge_method: 'S256',
        }));
    })
   .get('/authed', (req, res) => {
        const tokenSet = await client.callback(
            'https://slack.com/api/openid.connect.token',
            client.callbackParams(req),
            { code_verifier: req.session.codeVerifier }
        );
        console.log('received and validated tokens %j', tokenSet);
        console.log('validated ID Token claims %j', tokenSet.claims());
    });

app.listen(port, () => console.log(`rotkov up n runnin on port ${port}`));
