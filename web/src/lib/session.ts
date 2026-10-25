import { SignJWT, jwtVerify } from "jose";

export const sessionCookieName = "secclaw_session";

export type Session = {
  userId: number;
  email: string;
  name: string;
  role: string;
};

function getSecret() {
  const value = process.env.SESSION_SECRET;

  if (!value || value.length < 32) {
    throw new Error("SESSION_SECRET must contain at least 32 characters");
  }

  return new TextEncoder().encode(value);
}

export async function createSessionToken(session: Session) {
  return new SignJWT(session)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("8h")
    .sign(getSecret());
}

export async function verifySessionToken(token: string): Promise<Session> {
  const { payload } = await jwtVerify(token, getSecret());

  return {
    userId: Number(payload.userId),
    email: String(payload.email),
    name: String(payload.name),
    role: String(payload.role),
  };
}
