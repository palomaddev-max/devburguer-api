import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import * as Yup from 'yup';
import authConfig from '../../config/auth.js';
import User from '../models/User.js';

class SessionController {
  async store(request, response) {
    const schema = Yup.object({
      email: Yup.string().email().required(),
      password: Yup.string().required().min(6),
    });

    const isValid = await schema.isValid(request.body, { strict: true });

    const emailOrPasswordIsIncorrect = () => {
      response.status(400).json({ error: 'Email or password incorrect.' });
    };

    if (!isValid) {
      return emailOrPasswordIsIncorrect();
    }

    const { email, password } = request.body;

    const existingUser = await User.findOne({ where: { email } });

    if (!existingUser) {
      return emailOrPasswordIsIncorrect();
    }

    const isPasswordCorrect = await bcrypt.compare(
      password,
      existingUser.password_hash,
    );

    if (!isPasswordCorrect) {
      return emailOrPasswordIsIncorrect();
    }

    const token = jwt.sign(
      {
        id: existingUser.id,
        name: existingUser.name,
        admin: existingUser.admin,
      },
      authConfig.secret,
      {
        expiresIn: authConfig.expiresIn,
      },
    );

    return response.status(200).json({
      id: existingUser.id,
      name: existingUser.name,
      email: existingUser.email,
      admin: existingUser.admin,
      token,
    });
  }
}

export default new SessionController();
