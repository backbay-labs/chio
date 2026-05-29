export interface StaticBearerAuth {
  authToken: string;
}

export function staticBearerAuth(authToken: string): StaticBearerAuth {
  return { authToken };
}
