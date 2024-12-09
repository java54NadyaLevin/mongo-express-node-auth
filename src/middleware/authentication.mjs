import bcrypt from 'bcrypt'
import { getError } from '../errors/error.mjs';
const BASIC = "Basic ";
export function authenticate(accountingService) {
    return async (req, res, next) => {
        const authHeader = req.header("Authorization")
        if (authHeader) {
            if (authHeader.startsWith(BASIC)) {
                await basicAuth(authHeader, req, accountingService)
            }
        }
        next();
    }
}
export function auth(...skipRoutes) {

    return (req, res, next) => {
        if (!skipRoutes.includes(JSON.stringify({ path: req.path, method: req.method }))) {
            if (!req.user) {
                throw getError(401, "Authorization needed");
            }
            const path = req.path;
            const allowedRoutes = ROLE_ACCESS[req.role] || {};
            const allowedMethods = Object.entries(allowedRoutes).find(([key, methods]) => path.startsWith(key));
            const [keys, methods] = allowedMethods;
            if (!allowedMethods || !methods.includes(req.method)) {
                res.status(403).json({ message: 'You do not have permission to access this route' });
            }
        }
        next();
    }
}
async function basicAuth(authHeader, req, accountingService) {
    const userPasswordBase64 = authHeader.substring(BASIC.length);
    const userPasswordAscii = Buffer.from(userPasswordBase64, 'base64').toString("ascii");
    const userPasswordTokens = userPasswordAscii.split(":");
    try {
        const account = await accountingService.getAccount(userPasswordTokens[0]);
        if (account) {
            if (await bcrypt.compare(userPasswordTokens[1], account.hashPassword)) {
                req.user = account._id;
                req.role = account.role || 'USER';
                req.limit = account.limit || 30;
            }
        }
    } catch (error) {

    }


}
const ROLE_ACCESS = {
    ADMIN: {
        '/accounts/account': ['DELETE', 'GET'],
    },
    USER: {
        '/mflix/comments': ['POST', 'GET', 'DELETE', 'PUT'],
        '/movies/rates': ['POST'],
        '/accounts/account': ['PUT', 'DELETE', 'GET']
    },
    PREMIUM_USER: {
        '/mflix/comments': ['POST', 'GET', 'DELETE', 'PUT'],
        '/movies/rates': ['POST'],
        '/accounts/account': ['PUT', 'DELETE', 'GET']
    },
};