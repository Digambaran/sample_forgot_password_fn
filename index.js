import { shared, env } from "@appblocks/node-sdk";
import { nanoid } from "nanoid";
import { createTransport } from "nodemailer";
import bcrypt from "bcrypt";

const BLOCK_NAME = "sample_forgot_password_fn";

const getFromBlockEnv = (name) => process.env[BLOCK_NAME.toLocaleUpperCase() + "_" + name];

async function sendMail({ to, subject, text, html }) {
  const from = getFromBlockEnv("SHIELD_MAILER_EMAIL");
  const password = getFromBlockEnv("SHIELD_MAILER_PASSWORD");
  const host = getFromBlockEnv("SHIELD_MAILER_HOST");
  const port = getFromBlockEnv("SHIELD_MAILER_PORT");

  const transporter = createTransport({
    host,
    port,
    secure: port === 465, // true for 465, false for other ports
    auth: { user: from, pass: password },
  });

  console.log(`to:${to}`);
  console.log(`from:${from}`);
  console.log(`html:${html}`);
  console.log(`text:${text}`);
  console.log(`subject:${subject}`);

  const info = await transporter.sendMail({
    from,
    to,
    subject,
    text,
    html,
  });

  console.log("info");
  console.log(info);
  if (!info) throw new Error("Email not sent");
  return info;
}

const sample_forgot_password_fn = async (req, res) => {
  env.init();

  // const saltRounds = getFromBlockEnv("SALT_ROUNDS") || 10;
  const saltRounds = 10;

  const resetPasswordTokenExpiry = getFromBlockEnv("PASSWORD_RECOVERY_TOKEN_EXPIRY") || 60 * 5;
  const changePasswordPageUrl = `http://localhost:4012`;
  const { prisma, getBody, sendResponse, redis } = await shared.getShared();

  console.log(`saltRounds:${saltRounds}`);
  console.log(`changePasswordPageUrl:${changePasswordPageUrl}`);

  // health check
  if (req.params["health"] === "health") {
    sendResponse(res, 200, { success: true, msg: "Health check success" });
    return;
  }
  try {
    const { email } = await getBody(req);

    const userData = await prisma.users.findFirst({ where: { email } });

    if (!userData) {
      console.log(`record for user with email:${email} not found`);
      sendResponse(res, 200, {
        err: false,
        msg: "email sent",
        data: {},
      });
      return;
    }
    console.log(`record for user with email:${email} found`);

    const token = nanoid(64);
    const salt = await bcrypt.genSalt(parseInt(saltRounds, 10));
    const tokenHashed = await bcrypt.hash(token, salt);

    console.log(`tokens generated`);
    console.log(`salt:${salt}`);
    console.log(`token:${token}`);
    console.log(`hashedToken:${tokenHashed}`);

    const set = await redis.set(tokenHashed, email, {
      EX: resetPasswordTokenExpiry,
    });

    if (!set) {
      console.log(`token not set in redis:${set}`);
      sendResponse(res, 500, {
        err: true,
        msg: "server error",
        data: {},
      });
      return;
    }
    console.log(`token set in redis:${set}`);

    try {
      await sendMail({
        to: email,
        subject: "password reset link",
        text: "sample shield reset password",
        html: `${changePasswordPageUrl}/?token=${token}$${salt.split("$")[3]}/end=true`,
      });

      console.log(`reset link sent to email:${email}`);
    } catch (err) {
      console.log(`sending reset link failed`);
      await redis.del(tokenHashed);
      sendResponse(res, 500, {
        err: true,
        msg: "server error",
        data: { token, tokenHashed },
      });
      return;
    }

    sendResponse(res, 200, {
      err: false,
      msg: "reset link sent",
      data: { token, tokenHashed },
    });
    return;
  } catch (err) {
    console.log(err);
    sendResponse(res, 500, {
      err: true,
      msg: "server error",
      data: {},
    });
    return;
  }
};

export default sample_forgot_password_fn;
