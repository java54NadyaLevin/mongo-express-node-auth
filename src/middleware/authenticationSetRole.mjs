import bcrypt from 'bcrypt'
import { getError } from '../errors/error.mjs';
const BASIC = "Basic ";
export function authSetRole(username, password) {
    return async (req, res, next) => {
        const authHeader = req.header("Authorization")
        if (!authHeader) { res.status(401).json({ message: 'This request needs authorization' }); }
        if (authHeader && authHeader.startsWith(BASIC)) {
            const userPasswordBase64 = authHeader.substring(BASIC.length);
            const userPasswordAscii = Buffer.from(userPasswordBase64, 'base64').toString("ascii");
            const userPasswordTokens = userPasswordAscii.split(":");
            const storesPass = bcrypt.hashSync(password, 10);
            if (userPasswordTokens[0] == username && await bcrypt.compare(userPasswordTokens[1], storesPass)) {
                req.user = userPasswordTokens[0];
                next()
            } else {
                res.status(401).json({ message: 'Invalid credentials' });
            }

        }
    }


}