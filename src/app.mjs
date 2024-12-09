import express from 'express';
import { mflix_route } from './routes/mflix.mjs';
import { validateBody, valid, validateParams } from './middleware/validation.mjs'
import { accounts_route } from './routes/accounts.mjs';
import { errorHandler } from './errors/error.mjs';
import schemas from './validation-schemas/schemas.mjs';
import AccountsService from './service/AccountsService.mjs';
import { authSetRole } from './middleware/authenticationSetRole.mjs';
import { authenticate, auth } from './middleware/authentication.mjs';
import { ADD_UPDATE_ACCOUNT } from './config/pathes.mjs';
import rateLimit from 'express-rate-limit';

const app = express();
const port = process.env.PORT || 3500;
export const accountsService = new AccountsService(process.env.MONGO_URI, "sample_mflix");
const server = app.listen(port);

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: async (req, res) => req.limit,
    message: "You've exceeded the limit of requests per minute"
});

export function roleBasedRateLimiter(req, res, next) {
    if (req.role === 'USER') {
        limiter(req, res, next);
    } else {
        next();
    }
}

server.on("listening", () => console.log(`Server listening on port ${server.address().port}`));

app.use(express.json());
app.use('/accounts/account/role', authSetRole(process.env.SET_ROLE_USERNAME || 'roleAdmin', process.env.SET_ROLE_PASSWORD || 'rolePass'));
app.use(authenticate(accountsService));
app.use(auth(JSON.stringify({ path: ADD_UPDATE_ACCOUNT, method: "POST" }), 
    JSON.stringify({ path: "/accounts/account/role", method: "PUT" })));
app.use(roleBasedRateLimiter);
app.use(validateBody(schemas));
app.use(valid);
app.use('/mflix', mflix_route);
app.use('/accounts', accounts_route);
app.use(errorHandler);
